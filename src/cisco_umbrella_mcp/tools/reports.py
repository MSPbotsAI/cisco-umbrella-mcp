"""Cisco Umbrella reporting, deployment, app-discovery, and managed-provider tools.

Tool naming convention: cisco_umbrella_<action>_<resource>
"""

import json
from collections.abc import Callable

from mcp.server.fastmcp import FastMCP

from ..api_client import UmbrellaClient, UmbrellaError

_NO_CREDS = (
    "Error: No Cisco Umbrella credentials configured. Set UMBRELLA_API_KEY/UMBRELLA_KEY_SECRET "
    "or use AUTH_MODE=gateway."
)

def register(mcp: FastMCP, client_factory: Callable[[], UmbrellaClient | None]) -> None:
    @mcp.tool()
    async def cisco_umbrella_get_activity_dns(
        from_: str,
        to: str,
        limit: int = 100,
        offset: int | None = None,
        domains: str | None = None,
        categories: str | None = None,
        identityids: str | None = None,
        verdict: str | None = None,
        threats: str | None = None,
        timezone: str | None = None,
    ) -> str:
        """List DNS activity events.

        API: GET /reports/v2/activity/dns

        Args:
            from_: Required. Start of the time range. Accepts epoch
                milliseconds, ISO-8601 (e.g. "2024-01-01T00:00:00Z"), or a
                relative offset (e.g. "-1days", "-7days", "now").
            to: Required. End of the time range. Same accepted formats as from_.
            limit: Max results per page (default 100).
            offset: Pagination offset.
            domains: Comma-separated domain filter.
            categories: Comma-separated content category ID filter.
            identityids: Comma-separated identity (e.g. roaming computer) ID filter.
            verdict: Filter by verdict, e.g. "allowed" or "blocked".
            threats: Comma-separated threat name filter.
            timezone: IANA timezone name for the response's time fields.
        """
        client = client_factory()
        if client is None:
            return _NO_CREDS
        params = {
            "from": from_,
            "to": to,
            "limit": limit,
            "offset": offset,
            "domains": domains,
            "categories": categories,
            "identityids": identityids,
            "verdict": verdict,
            "threats": threats,
            "timezone": timezone,
        }
        try:
            result = await client.get("/reports/v2/activity/dns", params=params)
            return json.dumps(result, indent=2)
        except UmbrellaError as e:
            return f"Error: {e}"

    @mcp.tool()
    async def cisco_umbrella_get_activity_proxy(
        from_: str,
        to: str,
        limit: int = 100,
        offset: int | None = None,
        domains: str | None = None,
        urls: str | None = None,
        categories: str | None = None,
        identityids: str | None = None,
        verdict: str | None = None,
        threats: str | None = None,
        filename: str | None = None,
        timezone: str | None = None,
    ) -> str:
        """List proxy (Secure Web Gateway) activity events.

        API: GET /reports/v2/activity/proxy

        Args:
            from_: Required. Start of the time range. Accepts epoch
                milliseconds, ISO-8601 (e.g. "2024-01-01T00:00:00Z"), or a
                relative offset (e.g. "-1days", "-7days", "now").
            to: Required. End of the time range. Same accepted formats as from_.
            limit: Max results per page (default 100).
            offset: Pagination offset.
            domains: Comma-separated domain filter.
            urls: Comma-separated URL filter.
            categories: Comma-separated content category ID filter.
            identityids: Comma-separated identity ID filter.
            verdict: Filter by verdict, e.g. "allowed" or "blocked".
            threats: Comma-separated threat name filter.
            filename: Filter by downloaded file name.
            timezone: IANA timezone name for the response's time fields.
        """
        client = client_factory()
        if client is None:
            return _NO_CREDS
        params = {
            "from": from_,
            "to": to,
            "limit": limit,
            "offset": offset,
            "domains": domains,
            "urls": urls,
            "categories": categories,
            "identityids": identityids,
            "verdict": verdict,
            "threats": threats,
            "filename": filename,
            "timezone": timezone,
        }
        try:
            result = await client.get("/reports/v2/activity/proxy", params=params)
            return json.dumps(result, indent=2)
        except UmbrellaError as e:
            return f"Error: {e}"

    @mcp.tool()
    async def cisco_umbrella_get_activity_firewall(
        from_: str,
        to: str,
        limit: int = 100,
        offset: int | None = None,
        identityids: str | None = None,
        ruleid: str | None = None,
        verdict: str | None = None,
        categories: str | None = None,
        timezone: str | None = None,
    ) -> str:
        """List network firewall activity events.

        API: GET /reports/v2/activity/firewall

        Args:
            from_: Required. Start of the time range. Accepts epoch
                milliseconds, ISO-8601 (e.g. "2024-01-01T00:00:00Z"), or a
                relative offset (e.g. "-1days", "-7days", "now").
            to: Required. End of the time range. Same accepted formats as from_.
            limit: Max results per page (default 100).
            offset: Pagination offset.
            identityids: Comma-separated identity (e.g. network tunnel) ID filter.
            ruleid: Filter by firewall rule ID.
            verdict: Filter by verdict, e.g. "allowed" or "blocked".
            categories: Comma-separated category filter.
            timezone: IANA timezone name for the response's time fields.
        """
        client = client_factory()
        if client is None:
            return _NO_CREDS
        params = {
            "from": from_,
            "to": to,
            "limit": limit,
            "offset": offset,
            "identityids": identityids,
            "ruleid": ruleid,
            "verdict": verdict,
            "categories": categories,
            "timezone": timezone,
        }
        try:
            result = await client.get("/reports/v2/activity/firewall", params=params)
            return json.dumps(result, indent=2)
        except UmbrellaError as e:
            return f"Error: {e}"

    @mcp.tool()
    async def cisco_umbrella_get_activity_amp_retrospective(
        from_: str,
        to: str,
        limit: int = 100,
        offset: int | None = None,
        ampdisposition: str | None = None,
        sha256: str | None = None,
        timezone: str | None = None,
    ) -> str:
        """List AMP (Advanced Malware Protection) retrospective activity events —
        files that were re-classified as malicious after they were first seen.

        API: GET /reports/v2/activity/amp-retrospective

        Args:
            from_: Required. Start of the time range. Accepts epoch
                milliseconds, ISO-8601 (e.g. "2024-01-01T00:00:00Z"), or a
                relative offset (e.g. "-1days", "-7days", "now").
            to: Required. End of the time range. Same accepted formats as from_.
            limit: Max results per page (default 100).
            offset: Pagination offset.
            ampdisposition: Filter by AMP disposition, e.g. "malicious".
            sha256: Filter by a specific file's SHA-256 hash.
            timezone: IANA timezone name for the response's time fields.
        """
        client = client_factory()
        if client is None:
            return _NO_CREDS
        params = {
            "from": from_,
            "to": to,
            "limit": limit,
            "offset": offset,
            "ampdisposition": ampdisposition,
            "sha256": sha256,
            "timezone": timezone,
        }
        try:
            result = await client.get("/reports/v2/activity/amp-retrospective", params=params)
            return json.dumps(result, indent=2)
        except UmbrellaError as e:
            return f"Error: {e}"

    @mcp.tool()
    async def cisco_umbrella_list_roaming_computers(
        page: int = 1,
        limit: int = 100,
        name: str | None = None,
        status: str | None = None,
        swg_status: str | None = None,
        last_sync_before: str | None = None,
        last_sync_after: str | None = None,
    ) -> str:
        """List roaming computers (endpoints running the Umbrella roaming client).

        API: GET /deployments/v2/roamingcomputers

        Args:
            page: Page number (default 1).
            limit: Max results per page (default 100, max 100).
            name: Filter by computer name (partial match).
            status: Filter by status.
            swg_status: Filter by Secure Web Gateway module status.
            last_sync_before: Only computers that last synced before this time.
            last_sync_after: Only computers that last synced after this time.
        """
        client = client_factory()
        if client is None:
            return _NO_CREDS
        params = {
            "page": page,
            "limit": limit,
            "name": name,
            "status": status,
            "swgStatus": swg_status,
            "lastSyncBefore": last_sync_before,
            "lastSyncAfter": last_sync_after,
        }
        try:
            result = await client.get("/deployments/v2/roamingcomputers", params=params)
            return json.dumps(result, indent=2)
        except UmbrellaError as e:
            return f"Error: {e}"

    @mcp.tool()
    async def cisco_umbrella_list_applications(
        sources: str | None = None,
        identity: str | None = None,
        labels: str | None = None,
        controllable: bool | None = None,
        categories: str | None = None,
        subcategory: str | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> str:
        """List discovered cloud applications (App Discovery).

        API: GET /reports/v2/appDiscovery/applications

        Args:
            sources: Comma-separated data source filter, e.g. "dns,swg,cdfw".
            identity: Filter by identity (e.g. roaming computer or network) ID.
            labels: Comma-separated label filter.
            controllable: Filter to only applications with a controllable policy.
            categories: Comma-separated application category ID filter.
            subcategory: Filter by application subcategory.
            limit: Max results per page.
            offset: Pagination offset.
        """
        client = client_factory()
        if client is None:
            return _NO_CREDS
        params = {
            "sources": sources,
            "identity": identity,
            "labels": labels,
            "controllable": controllable,
            "categories": categories,
            "subcategory": subcategory,
            "limit": limit,
            "offset": offset,
        }
        try:
            result = await client.get("/reports/v2/appDiscovery/applications", params=params)
            return json.dumps(result, indent=2)
        except UmbrellaError as e:
            return f"Error: {e}"

    @mcp.tool()
    async def cisco_umbrella_list_protocols(
        identity: str | None = None,
        limit: int | None = None,
        offset: int | None = None,
        sort: str | None = None,
        order: str | None = None,
    ) -> str:
        """List discovered network protocols (App Discovery).

        API: GET /reports/v2/appDiscovery/protocols

        Args:
            identity: Filter by identity (e.g. roaming computer or network) ID.
            limit: Max results per page.
            offset: Pagination offset.
            sort: Sort field — "firstDetected" or "lastDetected".
            order: Sort order — "asc" or "desc".
        """
        client = client_factory()
        if client is None:
            return _NO_CREDS
        params = {
            "identity": identity,
            "limit": limit,
            "offset": offset,
            "sort": sort,
            "order": order,
        }
        try:
            result = await client.get("/reports/v2/appDiscovery/protocols", params=params)
            return json.dumps(result, indent=2)
        except UmbrellaError as e:
            return f"Error: {e}"

    @mcp.tool()
    async def cisco_umbrella_list_application_categories(
        limit: int | None = None,
        offset: int | None = None,
    ) -> str:
        """List application categories (App Discovery).

        API: GET /reports/v2/appDiscovery/applicationCategories

        Args:
            limit: Max results per page (1-100).
            offset: Pagination offset.
        """
        client = client_factory()
        if client is None:
            return _NO_CREDS
        params = {"limit": limit, "offset": offset}
        try:
            result = await client.get(
                "/reports/v2/appDiscovery/applicationCategories", params=params
            )
            return json.dumps(result, indent=2)
        except UmbrellaError as e:
            return f"Error: {e}"

    @mcp.tool()
    async def cisco_umbrella_list_customers(
        page: int = 1,
        limit: int = 100,
    ) -> str:
        """List customer organizations under this Umbrella Managed Provider (MSP) account.

        API: GET /admin/v2/managed/customers

        Args:
            page: Page number (default 1).
            limit: Max results per page (default 100, max 100).
        """
        client = client_factory()
        if client is None:
            return _NO_CREDS
        params = {"page": page, "limit": limit}
        try:
            result = await client.get("/admin/v2/managed/customers", params=params)
            return json.dumps(result, indent=2)
        except UmbrellaError as e:
            return f"Error: {e}"

    @mcp.tool()
    async def cisco_umbrella_get_providers_console() -> str:
        """Get this Umbrella Managed Provider console's subscription/usage summary
        (package name, total/used seats, customer count, status, renewal/expiry
        dates). Not a list — returns a single object.

        API: GET /reports/v2/providers/consoles
        """
        client = client_factory()
        if client is None:
            return _NO_CREDS
        try:
            result = await client.get("/reports/v2/providers/consoles")
            return json.dumps(result, indent=2)
        except UmbrellaError as e:
            return f"Error: {e}"
