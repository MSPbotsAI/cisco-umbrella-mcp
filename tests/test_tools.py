"""tools/list snapshot + error-envelope mapping tests.

No network calls: tool enumeration goes through FastMCP's in-process
list_tools(), and the error-code mapping is tested directly against
UmbrellaError, independent of any real HTTP request.
"""

import pytest

from cisco_umbrella_mcp.api_client import UmbrellaError
from cisco_umbrella_mcp.config import Settings
from cisco_umbrella_mcp.server import create_mcp_server

# Every customer-scoped tool requires organization_id — it becomes the
# X-Umbrella-OrgId header. The three provider-level tools below do not take
# it: they are how a caller discovers an organization_id in the first place.
EXPECTED_TOOLS = {
    "cisco_umbrella_test_connection": set(),
    "cisco_umbrella_get_activity_dns": {"organization_id", "from_", "to"},
    "cisco_umbrella_get_activity_proxy": {"organization_id", "from_", "to"},
    "cisco_umbrella_get_activity_firewall": {"organization_id", "from_", "to"},
    "cisco_umbrella_get_activity_amp_retrospective": {"organization_id", "from_", "to"},
    "cisco_umbrella_get_summaries_by_category": {"organization_id", "from_", "to"},
    "cisco_umbrella_get_categories": {"organization_id"},
    "cisco_umbrella_list_roaming_computers": {"organization_id"},
    "cisco_umbrella_list_networks": {"organization_id"},
    "cisco_umbrella_list_virtual_appliances": {"organization_id"},
    "cisco_umbrella_list_applications": {"organization_id"},
    "cisco_umbrella_list_protocols": {"organization_id"},
    "cisco_umbrella_list_application_categories": {"organization_id"},
    # provider-level: no customer scope
    "cisco_umbrella_list_customers": set(),
    "cisco_umbrella_get_providers_console": set(),
}

# Tools that must NOT gain organization_id — a provider credential is the
# whole point of them.
PROVIDER_LEVEL_TOOLS = {
    "cisco_umbrella_test_connection",
    "cisco_umbrella_list_customers",
    "cisco_umbrella_get_providers_console",
}


@pytest.mark.asyncio
async def test_tools_list_snapshot():
    mcp = create_mcp_server(Settings())
    tools = await mcp.list_tools()
    names = {t.name for t in tools}
    assert names == set(EXPECTED_TOOLS), f"unexpected tool set: {names}"

    by_name = {t.name: t for t in tools}
    for name, expected_required in EXPECTED_TOOLS.items():
        tool = by_name[name]
        required = set(tool.inputSchema.get("required", []))
        assert required == expected_required, f"{name}: required={required}"
        assert tool.annotations is not None and tool.annotations.readOnlyHint is True
        assert len(tool.description or "") <= 500, f"{name}: description too long"
        first_line = (tool.description or "").strip().splitlines()[0]
        assert len(first_line) <= 100, f"{name}: first line too long: {first_line!r}"

        # Scope must be explicit, never inferred from the token's own org.
        properties = tool.inputSchema.get("properties", {})
        if name in PROVIDER_LEVEL_TOOLS:
            assert "organization_id" not in properties, f"{name}: should not be customer-scoped"
        else:
            assert "organization_id" in required, f"{name}: organization_id must be required"


@pytest.mark.asyncio
async def test_service_instructions_present_and_bounded():
    mcp = create_mcp_server(Settings())
    assert mcp.instructions
    assert len(mcp.instructions) <= 1500


@pytest.mark.parametrize(
    "status_code,expected_code,expected_retryable",
    [
        (0, "upstream_error", True),
        (400, "invalid_argument", False),
        (401, "unauthorized", False),
        (403, "unauthorized", False),
        (404, "not_found", False),
        (422, "invalid_argument", False),
        (429, "rate_limited", True),
        (500, "upstream_error", True),
        (503, "upstream_error", True),
    ],
)
def test_error_envelope_mapping(status_code, expected_code, expected_retryable):
    import json

    err = UmbrellaError(status_code, "boom")
    envelope = json.loads(err.to_envelope())
    assert envelope["error"]["code"] == expected_code
    assert envelope["error"]["retryable"] is expected_retryable
    assert envelope["error"]["message"] == "boom"


@pytest.mark.asyncio
async def test_customer_scope_travels_as_a_header_not_a_query_param():
    """organization_id becomes X-Umbrella-OrgId, never a query parameter.

    Omitting the header would silently run the call at the parent org's
    scope and return a well-formed 200 holding nothing — indistinguishable
    downstream from "this customer had no activity this month".
    """
    from mcp.server.fastmcp import FastMCP

    from cisco_umbrella_mcp.tools import reports

    captured = {}

    class _StubClient:
        async def get(self, path, params=None, extra_headers=None):
            captured["path"] = path
            captured["params"] = params
            captured["extra_headers"] = extra_headers
            return {"data": []}

    mcp = FastMCP(name="test")
    reports.register(mcp, lambda: _StubClient())
    await mcp.call_tool(
        "cisco_umbrella_get_summaries_by_category",
        {"organization_id": "1234567", "from_": "-30days", "to": "now"},
    )
    assert captured["path"] == "/reports/v2/summaries-by-category"
    assert captured["extra_headers"] == {"X-Umbrella-OrgId": "1234567"}
    assert "organization_id" not in captured["params"]


@pytest.mark.asyncio
async def test_authorization_header_cannot_be_overridden_by_extra_headers():
    """extra_headers is merged beneath Authorization, which stays
    authoritative — a caller must not be able to substitute its own
    credential for the one minted from this tenant's key/secret.
    """
    import httpx

    from cisco_umbrella_mcp import api_client

    captured = {}

    async def fake_request_with_retry(method, url, *, headers, params=None, data=None):
        captured.setdefault("calls", []).append((url, dict(headers)))
        if url == api_client.TOKEN_URL:
            return httpx.Response(200, json={"access_token": "minted-token"})
        return httpx.Response(200, json={"data": []})

    original = api_client._request_with_retry
    api_client._request_with_retry = fake_request_with_retry
    try:
        client = api_client.UmbrellaClient("key", "secret")
        await client.get(
            "/reports/v2/categories",
            extra_headers={"X-Umbrella-OrgId": "1234567", "Authorization": "Bearer attacker"},
        )
    finally:
        api_client._request_with_retry = original

    _, business_headers = captured["calls"][-1]
    assert business_headers["Authorization"] == "Bearer minted-token"
    assert business_headers["X-Umbrella-OrgId"] == "1234567"
