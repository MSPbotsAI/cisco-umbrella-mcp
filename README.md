# cisco-umbrella-mcp

Cisco Umbrella MCP Service — a stateless HTTP MCP server wrapping the [Cisco Umbrella REST API v2](https://developer.cisco.com/docs/cloud-security/) (classic Umbrella, not the newer Secure Access/SASE product), scoped to the 10 endpoints MSPbots currently uses: DNS/proxy/firewall/AMP-retrospective activity reports, roaming computers, app-discovery (applications/protocols/application categories), managed-provider customer list, and the provider console summary.

**Tech stack:** Python 3.12 + uv + FastMCP (Starlette/Uvicorn)

## When would an agent use this

Cisco Umbrella protects a customer's network at the DNS/web layer — it blocks malicious domains, filters web content by category, and logs network activity. An agent should reach for this MCP for requests like:

- "Has this domain been queried or blocked on this customer's network recently?" → `cisco_umbrella_get_activity_dns`
- "What web categories/URLs are being filtered or proxied for this customer?" → `cisco_umbrella_get_activity_proxy`
- "Any firewall allows/blocks for this customer's network in the last day?" → `cisco_umbrella_get_activity_firewall`
- "Did a file that looked clean later get flagged as malware?" → `cisco_umbrella_get_activity_amp_retrospective`
- "List this customer's roaming laptops and their last sync/status" → `cisco_umbrella_list_roaming_computers`
- "List the customer orgs we manage under Cisco Umbrella" / "What's our Umbrella package usage across customers?" → `cisco_umbrella_list_customers`, `cisco_umbrella_get_providers_console`

**Caveat:** this credential set is a Managed Provider (MSSP) root-org key, not a per-customer credential, so the per-customer activity/device tools above may come back empty in practice — see [Known Gaps](#known-gaps) below for the verified details.

## Authentication method note

Cisco Umbrella's classic REST API supports the **OAuth2 client_credentials grant** — a pure server-to-server exchange, no user browser redirect. An admin creates an API Key + Key Secret pair in the Umbrella dashboard (Admin > API Keys), and this service exchanges that pair for a short-lived (1 hour) bearer token on every call (no refresh token, so no cross-request caching — same "re-login every call" pattern as `covedataprotection-mcp`/`webroot-mcp`/`logmein-mcp`).

```
POST https://api.umbrella.com/auth/v2/token
Authorization: Basic base64(apiKey:keySecret)
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
```

**Region note:** MSPbots' own integration config for Cisco Umbrella has a `dataCenter` field (`us`/`eu`). Verified directly against the raw OpenAPI spec embedded in Cisco's own developer docs for all 10 endpoints plus the auth/token endpoint: **every one of them lists exactly one host, `https://api.umbrella.com`** — there is no separate EU host for classic Umbrella. (Cisco's newer "Secure Access" product does have its own region concept, but that's a different product from what this service targets.) This service therefore ignores the `dataCenter` value entirely; it's not needed for any of these 10 endpoints.

## Quick Start

```powershell
# Install dependencies
cd D:\claude\project\cisco-umbrella-mcp
uv sync

# Run in stdio mode (for Claude Desktop)
$env:UMBRELLA_API_KEY="your_api_key"
$env:UMBRELLA_KEY_SECRET="your_key_secret"
uv run cisco-umbrella-mcp
```

## Configuration

Copy `.env.example` to `.env` and fill in your values:

| Variable | Default | Description |
|----------|---------|--------------|
| `UMBRELLA_API_KEY` | — | Cisco Umbrella API Key (Admin > API Keys) |
| `UMBRELLA_KEY_SECRET` | — | Cisco Umbrella Key Secret (shown once at creation time) |
| `AUTH_MODE` | `gateway` | `gateway` = credentials per-request via headers (SOP-compliant); `env` = shared credentials from env vars (local dev only) |
| `MCP_TRANSPORT` | `stdio` | `stdio` (Claude Desktop) or `http` (gateway) |
| `MCP_HTTP_PORT` | `8080` | HTTP server port |

## HEADER 授权参数说明

Gateway 模式下，每个请求必须携带以下两个 HTTP Header：

| Header | 类型 | 是否必填 | 默认值 | 枚举值 | 字段描述 | Example |
|---|---|---|---|---|---|---|
| `X-Umbrella-Api-Key` | string | 是 | 无 | 无 | Cisco Umbrella API Key（Umbrella 后台 Admin > API Keys 页面生成） | `AbCdEf1234567890` |
| `X-Umbrella-Key-Secret` | string | 是 | 无 | 无 | Cisco Umbrella Key Secret（创建时仅显示一次，用于配合 API Key 走 client_credentials 换 token） | `xyz9876543210abcdef` |

## Claude Desktop Setup

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "cisco-umbrella": {
      "command": "uv",
      "args": ["run", "--directory", "D:/claude/project/cisco-umbrella-mcp", "cisco-umbrella-mcp"],
      "env": {
        "UMBRELLA_API_KEY": "your_api_key",
        "UMBRELLA_KEY_SECRET": "your_key_secret"
      }
    }
  }
}
```

## Transport Modes

### stdio (Claude Desktop / CLI)
```powershell
$env:UMBRELLA_API_KEY="your_api_key"
$env:UMBRELLA_KEY_SECRET="your_key_secret"
uv run cisco-umbrella-mcp
```

### HTTP — single-tenant
```powershell
$env:UMBRELLA_API_KEY="your_api_key"
$env:UMBRELLA_KEY_SECRET="your_key_secret"
$env:MCP_TRANSPORT="http"
$env:AUTH_MODE="env"
uv run cisco-umbrella-mcp
```

### HTTP — gateway / multi-tenant
```powershell
$env:MCP_TRANSPORT="http"
$env:AUTH_MODE="gateway"
uv run cisco-umbrella-mcp
# Each request must include: X-Umbrella-Api-Key and X-Umbrella-Key-Secret headers
```

## Available Tools (14)

| Tool | Description | API | Parameters |
|---|---|---|---|
| `cisco_umbrella_get_activity_dns` | DNS activity events | `GET /reports/v2/activity/dns` | `organization_id` (required), `from_`, `to` (required), `limit`, `offset`, `domains`, `categories`, `identityids`, `verdict`, `threats`, `timezone` |
| `cisco_umbrella_get_activity_proxy` | Proxy (SWG) activity events | `GET /reports/v2/activity/proxy` | `organization_id` (required), `from_`, `to` (required), `limit`, `offset`, `domains`, `urls`, `categories`, `identityids`, `verdict`, `threats`, `filename`, `timezone` |
| `cisco_umbrella_get_activity_firewall` | Firewall activity events | `GET /reports/v2/activity/firewall` | `organization_id` (required), `from_`, `to` (required), `limit`, `offset`, `identityids`, `ruleid`, `verdict`, `categories`, `timezone` |
| `cisco_umbrella_get_activity_amp_retrospective` | AMP retrospective activity events | `GET /reports/v2/activity/amp-retrospective` | `organization_id` (required), `from_`, `to` (required), `limit`, `offset`, `ampdisposition`, `sha256`, `timezone` |
| `cisco_umbrella_list_roaming_computers` | List roaming client endpoints | `GET /deployments/v2/roamingcomputers` | `organization_id` (required), `page`, `limit`, `name`, `status`, `swg_status`, `last_sync_before`, `last_sync_after` |
| `cisco_umbrella_list_applications` | List discovered cloud applications | `GET /reports/v2/appDiscovery/applications` | `organization_id` (required), `sources`, `identity`, `labels`, `controllable`, `categories`, `subcategory`, `limit`, `offset` |
| `cisco_umbrella_list_protocols` | List discovered network protocols | `GET /reports/v2/appDiscovery/protocols` | `organization_id` (required), `identity`, `limit`, `offset`, `sort`, `order` |
| `cisco_umbrella_list_application_categories` | List application categories | `GET /reports/v2/appDiscovery/applicationCategories` | `organization_id` (required), `limit`, `offset` |
| `cisco_umbrella_get_categories` | Category catalogue; `type` marks security vs content categories | `GET /reports/v2/categories` | `organization_id` (required) |
| `cisco_umbrella_get_summaries_by_category` | Per-category request counts for a time range | `GET /reports/v2/summaries-by-category` | `organization_id`, `from_`, `to` (required), `limit`, `offset`, `categories`, `domains`, `identityids`, `verdict`, `threats`, `threattypes`, `filternoisydomains` |
| `cisco_umbrella_list_networks` | List registered networks and their deployment state | `GET /deployments/v2/networks` | `organization_id` (required), `page`, `limit` |
| `cisco_umbrella_list_virtual_appliances` | List virtual appliances, their health and state | `GET /deployments/v2/virtualappliances` | `organization_id` (required), `page`, `limit` |
| `cisco_umbrella_list_customers` | List customer orgs under this Managed Provider account | `GET /admin/v2/managed/customers` | `page`, `limit` |
| `cisco_umbrella_get_providers_console` | Get provider console subscription/usage summary (single object, not a list) | `GET /reports/v2/providers/consoles` | none |

`from_`/`to` accept epoch milliseconds, ISO-8601, or a relative offset (e.g. `"-1days"`, `"-7days"`, `"now"`), per Umbrella's reporting API conventions. (`from_` has a trailing underscore because `from` is a Python reserved word — it's mapped to the literal `from` query parameter internally.)

`organization_id` is the managed customer's Umbrella organization ID, sent as the `X-Umbrella-OrgId` request header. It is **required** on every customer-scoped tool rather than optional. Omitting it would run the call at the provider (parent) organization's own scope, which answers `200` with either nothing or the parent's own traffic — indistinguishable downstream from "this customer had no activity in this period". Consumers of these tools state security findings to end clients, so a loud failure is safer than a quiet empty. Resolve an ID with `cisco_umbrella_list_customers`; the three provider-level tools (`list_customers`, `get_providers_console`, `test_connection`) deliberately do not take one.

## Known Gaps

Tested against two real Managed Provider (MSSP) accounts *before* per-customer scoping existed. Of the 10 tools that build had, only **2 were confirmed working with verified real data**; the other 8 were blocked or unverified (empty results don't prove correctness — they just mean no error was raised). The 4 tools added since have not been exercised live at all.

**Per-customer scoping, added 2026-09-18 — premise documented, not yet live-verified.** The empty results below were the expected consequence of running every call at the provider (parent) org's own scope, which carries no client traffic. Cisco documents `X-Umbrella-OrgId` as the way to point a parent organization's access token at one child organization, which is what `organization_id` now sends. **Two placements exist in Cisco's own documentation and they disagree**: the KB article puts the header on the business request (what this build implements), while the getting-started guide puts it on `POST /auth/v2/token` to mint a child-scoped token. If the business-request placement turns out not to work, the change is confined to `UmbrellaClient._login()` — the token leg and the business leg build their headers independently. Confirm with one real call against a managed customer known to have traffic before trusting any of these figures.

> **Breaking change, 2026-09-18.** `organization_id` became a required parameter on all 8 customer-scoped tools plus the 4 new ones. Calls that omit it now fail schema validation instead of silently returning parent-scope data. Agent sessions built against the previous signatures will break.

**✅ Confirmed working (real, non-empty, cross-validated data):**
- `cisco_umbrella_get_providers_console` — real subscription summary on both test accounts (`customerCount: 77` and `customerCount: 47` respectively).
- `cisco_umbrella_list_customers` — returned 77 real customer organizations (real company names) on account 1. Failed with `403 Access Forbidden` on account 2 — confirmed by decoding that account's token that it genuinely lacks the `admin.customers:read` scope (20 total scopes vs. 76 on account 1). Not a code bug; a real per-key permission difference.

**⚠️ Unverified — returned well-formed but empty results on both accounts, not proven correct:** `cisco_umbrella_get_activity_dns`, `_proxy`, `_firewall`, `_amp_retrospective`, `cisco_umbrella_list_roaming_computers`. Cross-checked the live OpenAPI parameter definitions for Activity DNS directly against Cisco's own docs (pulled the raw spec, not summarized) — `from`/`to`/`limit` are exactly as implemented, no missing/misnamed parameter. The likely explanation is that both test accounts are **Managed Provider root orgs**, which have no direct DNS/proxy/firewall/AMP traffic or roaming computers of their own — that data lives under each *managed customer* org individually. **This is what `organization_id` / `X-Umbrella-OrgId` now addresses** — the earlier conclusion here ("searched Cisco's docs for a scoping parameter/header, found none") was wrong: the header is documented, see the note at the top of this section. These 5 should be re-run against a managed customer with known traffic. If the header turns out not to scope a parent token, the fallback is the provider-side reporting family (`/reports/v2/providers/category-requests-by-org`, `/providers/deployments`, `/providers/categories`), which returns every managed org broken out by org and works with a parent token as-is.
- **`cisco_umbrella_list_applications`, `_protocols`, `_application_categories` (App Discovery) — confirmed blocked, not a code bug.** Reproduced identically on both test accounts and via direct curl with the same tokens (ruling out request-construction issues): `403 Access Forbidden` on account 1, `500`/`403` on account 2. Both tokens' scope lists included `reports.appdiscovery:read`, so this is most likely a package/entitlement restriction (App Discovery as a paid add-on not included in either account's "Umbrella for MSSPs" tier), not a permissions or parameter problem.
- `cisco_umbrella_get_providers_console` returns a single subscription-summary object, not a list — confirmed via both live tests. Despite the plural name in MSPbots' own configured API list ("Providers Consoles"), double-check this against whatever MSPbots' existing collector expects (array vs single object).
- The `Applications` app-discovery endpoint's optional parameter list may not be fully exhaustive (a couple of parameters near the end of that endpoint's schema were not fully captured during research) — the ones documented here (`sources`, `identity`, `labels`, `controllable`, `categories`, `subcategory`, `limit`, `offset`) are confirmed real; there may be one or two more not yet added.
- Scope is limited to the 14 operations MSPbots currently uses, not Umbrella's full API surface (which also includes Internal Domains, Sites, Network Tunnels, Policies, Tagging, the separate "Providers" API for per-customer actions, and the Key Admin API for managing API keys themselves). Whether Umbrella's `networks` and `sites` are the same objects under two names is an open question — the provider-side deployment response uses an identity type of `site`.

## API Reference

- [Cisco Umbrella API Authentication](https://developer.cisco.com/docs/cloud-security/umbrella-api-authentication/)
- [Cisco Cloud Security API Documentation (DevNet)](https://developer.cisco.com/docs/cloud-security/)
