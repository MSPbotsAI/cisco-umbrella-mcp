"""Cisco Umbrella reporting, deployment, app-discovery, and managed-provider tools.

Tool naming convention: cisco_umbrella_<action>_<resource>
"""

from collections.abc import Callable
from typing import Annotated

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from .._json import dump_json_capped
from ..api_client import UmbrellaClient, UmbrellaError
from ._common import NO_TOKEN

_MAX_LIMIT = 200


def register(mcp: FastMCP, client_factory: Callable[[], UmbrellaClient | None]) -> None:
    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def cisco_umbrella_get_activity_dns(
        from_: Annotated[
            str,
            Field(
                description=(
                    "Required. Start of the time range. Accepts epoch "
                    'milliseconds, ISO-8601 (e.g. "2024-01-01T00:00:00Z"), or a '
                    'relative offset (e.g. "-1days", "-7days", "now").'
                )
            ),
        ],
        to: Annotated[str, Field(description="Required. End of the time range. Same accepted formats as from_.")],
        limit: Annotated[int, Field(description="Max results per page (default 100, hard cap 200).")] = 100,
        offset: Annotated[int | None, Field(description="Pagination offset.")] = None,
        domains: Annotated[str | None, Field(description="Comma-separated domain filter.")] = None,
        categories: Annotated[str | None, Field(description="Comma-separated content category ID filter.")] = None,
        identityids: Annotated[
            str | None, Field(description="Comma-separated identity (e.g. roaming computer) ID filter.")
        ] = None,
        verdict: Annotated[str | None, Field(description='Filter by verdict, e.g. "allowed" or "blocked".')] = None,
        threats: Annotated[str | None, Field(description="Comma-separated threat name filter.")] = None,
        timezone: Annotated[
            str | None, Field(description="IANA timezone name for the response's time fields.")
        ] = None,
    ) -> str:
        """List DNS activity events.

        Note: with a Managed Provider (MSSP) root credential (rather than a
        per-customer one), this may return empty results — there's no
        parameter here to scope to one managed customer. See README Known
        Gaps before assuming empty means no activity.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        limit = min(limit, _MAX_LIMIT)
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
            return dump_json_capped(result)
        except UmbrellaError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def cisco_umbrella_get_activity_proxy(
        from_: Annotated[
            str,
            Field(
                description=(
                    "Required. Start of the time range. Accepts epoch "
                    'milliseconds, ISO-8601 (e.g. "2024-01-01T00:00:00Z"), or a '
                    'relative offset (e.g. "-1days", "-7days", "now").'
                )
            ),
        ],
        to: Annotated[str, Field(description="Required. End of the time range. Same accepted formats as from_.")],
        limit: Annotated[int, Field(description="Max results per page (default 100, hard cap 200).")] = 100,
        offset: Annotated[int | None, Field(description="Pagination offset.")] = None,
        domains: Annotated[str | None, Field(description="Comma-separated domain filter.")] = None,
        urls: Annotated[str | None, Field(description="Comma-separated URL filter.")] = None,
        categories: Annotated[str | None, Field(description="Comma-separated content category ID filter.")] = None,
        identityids: Annotated[str | None, Field(description="Comma-separated identity ID filter.")] = None,
        verdict: Annotated[str | None, Field(description='Filter by verdict, e.g. "allowed" or "blocked".')] = None,
        threats: Annotated[str | None, Field(description="Comma-separated threat name filter.")] = None,
        filename: Annotated[str | None, Field(description="Filter by downloaded file name.")] = None,
        timezone: Annotated[
            str | None, Field(description="IANA timezone name for the response's time fields.")
        ] = None,
    ) -> str:
        """List proxy (Secure Web Gateway) activity events.

        Note: with a Managed Provider (MSSP) root credential (rather than a
        per-customer one), this may return empty results — there's no
        parameter here to scope to one managed customer. See README Known
        Gaps before assuming empty means no activity.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        limit = min(limit, _MAX_LIMIT)
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
            return dump_json_capped(result)
        except UmbrellaError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def cisco_umbrella_get_activity_firewall(
        from_: Annotated[
            str,
            Field(
                description=(
                    "Required. Start of the time range. Accepts epoch "
                    'milliseconds, ISO-8601 (e.g. "2024-01-01T00:00:00Z"), or a '
                    'relative offset (e.g. "-1days", "-7days", "now").'
                )
            ),
        ],
        to: Annotated[str, Field(description="Required. End of the time range. Same accepted formats as from_.")],
        limit: Annotated[int, Field(description="Max results per page (default 100, hard cap 200).")] = 100,
        offset: Annotated[int | None, Field(description="Pagination offset.")] = None,
        identityids: Annotated[
            str | None, Field(description="Comma-separated identity (e.g. network tunnel) ID filter.")
        ] = None,
        ruleid: Annotated[str | None, Field(description="Filter by firewall rule ID.")] = None,
        verdict: Annotated[str | None, Field(description='Filter by verdict, e.g. "allowed" or "blocked".')] = None,
        categories: Annotated[str | None, Field(description="Comma-separated category filter.")] = None,
        timezone: Annotated[
            str | None, Field(description="IANA timezone name for the response's time fields.")
        ] = None,
    ) -> str:
        """List network firewall activity events.

        Note: with a Managed Provider (MSSP) root credential (rather than a
        per-customer one), this may return empty results — there's no
        parameter here to scope to one managed customer. See README Known
        Gaps before assuming empty means no activity.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        limit = min(limit, _MAX_LIMIT)
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
            return dump_json_capped(result)
        except UmbrellaError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def cisco_umbrella_get_activity_amp_retrospective(
        from_: Annotated[
            str,
            Field(
                description=(
                    "Required. Start of the time range. Accepts epoch "
                    'milliseconds, ISO-8601 (e.g. "2024-01-01T00:00:00Z"), or a '
                    'relative offset (e.g. "-1days", "-7days", "now").'
                )
            ),
        ],
        to: Annotated[str, Field(description="Required. End of the time range. Same accepted formats as from_.")],
        limit: Annotated[int, Field(description="Max results per page (default 100, hard cap 200).")] = 100,
        offset: Annotated[int | None, Field(description="Pagination offset.")] = None,
        ampdisposition: Annotated[
            str | None, Field(description='Filter by AMP disposition, e.g. "malicious".')
        ] = None,
        sha256: Annotated[str | None, Field(description="Filter by a specific file's SHA-256 hash.")] = None,
        timezone: Annotated[
            str | None, Field(description="IANA timezone name for the response's time fields.")
        ] = None,
    ) -> str:
        """List AMP retrospective events (files reclassified malicious after first seen).

        Note: with a Managed Provider (MSSP) root credential (rather than a
        per-customer one), this may return empty results — there's no
        parameter here to scope to one managed customer. See README Known
        Gaps before assuming empty means no activity.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        limit = min(limit, _MAX_LIMIT)
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
            return dump_json_capped(result)
        except UmbrellaError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def cisco_umbrella_list_roaming_computers(
        page: Annotated[int, Field(description="Page number (default 1).")] = 1,
        limit: Annotated[int, Field(description="Max results per page (default 100, hard cap 200).")] = 100,
        name: Annotated[str | None, Field(description="Filter by computer name (partial match).")] = None,
        status: Annotated[str | None, Field(description="Filter by status.")] = None,
        swg_status: Annotated[
            str | None, Field(description="Filter by Secure Web Gateway module status.")
        ] = None,
        last_sync_before: Annotated[
            str | None,
            Field(
                description=(
                    "Only computers that last synced before this time. Same "
                    'formats as from_/to elsewhere: epoch ms, ISO-8601, or a '
                    'relative offset (e.g. "-7days", "now").'
                )
            ),
        ] = None,
        last_sync_after: Annotated[
            str | None,
            Field(description="Only computers that last synced after this time. Same formats as last_sync_before."),
        ] = None,
    ) -> str:
        """List roaming computers (endpoints running the Umbrella roaming client).

        Note: with a Managed Provider (MSSP) root credential (rather than a
        per-customer one), this may return empty results — no parameter here
        scopes to one managed customer; see README Known Gaps. No server-side
        recency sort — page through and sort client-side if needed.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        limit = min(limit, _MAX_LIMIT)
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
            return dump_json_capped(result)
        except UmbrellaError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def cisco_umbrella_list_applications(
        sources: Annotated[
            str | None, Field(description='Comma-separated data source filter, e.g. "dns,swg,cdfw".')
        ] = None,
        identity: Annotated[
            str | None, Field(description="Filter by identity (e.g. roaming computer or network) ID.")
        ] = None,
        labels: Annotated[str | None, Field(description="Comma-separated label filter.")] = None,
        controllable: Annotated[
            bool | None, Field(description="Filter to only applications with a controllable policy.")
        ] = None,
        categories: Annotated[
            str | None, Field(description="Comma-separated application category ID filter.")
        ] = None,
        subcategory: Annotated[str | None, Field(description="Filter by application subcategory.")] = None,
        limit: Annotated[int | None, Field(description="Max results per page (hard cap 200).")] = None,
        offset: Annotated[int | None, Field(description="Pagination offset.")] = None,
    ) -> str:
        """List discovered cloud applications (App Discovery).

        Named, app-layer identifications (e.g. Dropbox, Salesforce) — use
        `cisco_umbrella_list_protocols` for raw protocols, or
        `cisco_umbrella_list_application_categories` for the taxonomy.

        Note: returned 403 Access Forbidden in MSSP root-credential testing —
        likely an unlicensed add-on, not a code/parameter issue. See README
        Known Gaps.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        if limit is not None:
            limit = min(limit, _MAX_LIMIT)
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
            return dump_json_capped(result)
        except UmbrellaError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def cisco_umbrella_list_protocols(
        identity: Annotated[
            str | None, Field(description="Filter by identity (e.g. roaming computer or network) ID.")
        ] = None,
        limit: Annotated[int | None, Field(description="Max results per page (hard cap 200).")] = None,
        offset: Annotated[int | None, Field(description="Pagination offset.")] = None,
        sort: Annotated[
            str | None, Field(description='Sort field — "firstDetected" or "lastDetected".')
        ] = None,
        order: Annotated[str | None, Field(description='Sort order — "asc" or "desc".')] = None,
    ) -> str:
        """List discovered network protocols (App Discovery).

        Raw network protocol-level traffic (e.g. SSH, BitTorrent), not named
        cloud applications — use `cisco_umbrella_list_applications` for those.

        Note: returned 403 Access Forbidden in testing with a Managed
        Provider (MSSP) root credential — likely an unlicensed add-on for
        that account, not a code/parameter issue. See README Known Gaps.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        if limit is not None:
            limit = min(limit, _MAX_LIMIT)
        params = {
            "identity": identity,
            "limit": limit,
            "offset": offset,
            "sort": sort,
            "order": order,
        }
        try:
            result = await client.get("/reports/v2/appDiscovery/protocols", params=params)
            return dump_json_capped(result)
        except UmbrellaError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def cisco_umbrella_list_application_categories(
        limit: Annotated[int | None, Field(description="Max results per page (hard cap 200).")] = None,
        offset: Annotated[int | None, Field(description="Pagination offset.")] = None,
    ) -> str:
        """List application categories (App Discovery).

        The content-category taxonomy (IDs/names) used to group and filter
        applications — not application or protocol instances themselves.

        Note: returned 403 Access Forbidden in testing with a Managed
        Provider (MSSP) root credential — likely an unlicensed add-on for
        that account, not a code/parameter issue. See README Known Gaps.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        if limit is not None:
            limit = min(limit, _MAX_LIMIT)
        params = {"limit": limit, "offset": offset}
        try:
            result = await client.get(
                "/reports/v2/appDiscovery/applicationCategories", params=params
            )
            return dump_json_capped(result)
        except UmbrellaError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def cisco_umbrella_list_customers(
        page: Annotated[int, Field(description="Page number (default 1).")] = 1,
        limit: Annotated[int, Field(description="Max results per page (default 100, hard cap 200).")] = 100,
    ) -> str:
        """List customer organizations under this Umbrella Managed Provider (MSP) account."""
        client = client_factory()
        if client is None:
            return NO_TOKEN
        limit = min(limit, _MAX_LIMIT)
        params = {"page": page, "limit": limit}
        try:
            result = await client.get("/admin/v2/managed/customers", params=params)
            return dump_json_capped(result)
        except UmbrellaError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def cisco_umbrella_get_providers_console() -> str:
        """Get this Umbrella Managed Provider console's subscription/usage summary.

        Package name, total/used seats, customer count, status, renewal/
        expiry dates. Not a list — returns a single object.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.get("/reports/v2/providers/consoles")
            return dump_json_capped(result)
        except UmbrellaError as e:
            return e.to_envelope()
