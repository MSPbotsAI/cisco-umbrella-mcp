# cisco-umbrella-mcp

Cisco Umbrella MCP Service — a stateless HTTP MCP server wrapping the [Cisco Umbrella REST API v2](https://developer.cisco.com/docs/cloud-security/) (classic Umbrella, not the newer Secure Access/SASE product), scoped to the 10 endpoints MSPbots currently uses: DNS/proxy/firewall/AMP-retrospective activity reports, roaming computers, app-discovery (applications/protocols/application categories), managed-provider customer list, and the provider console summary.

**Tech stack:** Python 3.12 + uv + FastMCP (Starlette/Uvicorn)

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

## Available Tools (10)

| Tool | Description | API | Parameters |
|---|---|---|---|
| `cisco_umbrella_get_activity_dns` | DNS activity events | `GET /reports/v2/activity/dns` | `from_`, `to` (required), `limit`, `offset`, `domains`, `categories`, `identityids`, `verdict`, `threats`, `timezone` |
| `cisco_umbrella_get_activity_proxy` | Proxy (SWG) activity events | `GET /reports/v2/activity/proxy` | `from_`, `to` (required), `limit`, `offset`, `domains`, `urls`, `categories`, `identityids`, `verdict`, `threats`, `filename`, `timezone` |
| `cisco_umbrella_get_activity_firewall` | Firewall activity events | `GET /reports/v2/activity/firewall` | `from_`, `to` (required), `limit`, `offset`, `identityids`, `ruleid`, `verdict`, `categories`, `timezone` |
| `cisco_umbrella_get_activity_amp_retrospective` | AMP retrospective activity events | `GET /reports/v2/activity/amp-retrospective` | `from_`, `to` (required), `limit`, `offset`, `ampdisposition`, `sha256`, `timezone` |
| `cisco_umbrella_list_roaming_computers` | List roaming client endpoints | `GET /deployments/v2/roamingcomputers` | `page`, `limit`, `name`, `status`, `swg_status`, `last_sync_before`, `last_sync_after` |
| `cisco_umbrella_list_applications` | List discovered cloud applications | `GET /reports/v2/appDiscovery/applications` | `sources`, `identity`, `labels`, `controllable`, `categories`, `subcategory`, `limit`, `offset` |
| `cisco_umbrella_list_protocols` | List discovered network protocols | `GET /reports/v2/appDiscovery/protocols` | `identity`, `limit`, `offset`, `sort`, `order` |
| `cisco_umbrella_list_application_categories` | List application categories | `GET /reports/v2/appDiscovery/applicationCategories` | `limit`, `offset` |
| `cisco_umbrella_list_customers` | List customer orgs under this Managed Provider account | `GET /admin/v2/managed/customers` | `page`, `limit` |
| `cisco_umbrella_get_providers_console` | Get provider console subscription/usage summary (single object, not a list) | `GET /reports/v2/providers/consoles` | none |

`from_`/`to` accept epoch milliseconds, ISO-8601, or a relative offset (e.g. `"-1days"`, `"-7days"`, `"now"`), per Umbrella's reporting API conventions. (`from_` has a trailing underscore because `from` is a Python reserved word — it's mapped to the literal `from` query parameter internally.)

## Known Gaps

Tested against two real Managed Provider (MSSP) accounts. Of the 10 tools, only **2 are confirmed working with verified real data**; the other 8 are either blocked or unverified (empty results don't prove correctness — they just mean no error was raised).

**✅ Confirmed working (real, non-empty, cross-validated data):**
- `cisco_umbrella_get_providers_console` — real subscription summary on both test accounts (`customerCount: 77` and `customerCount: 47` respectively).
- `cisco_umbrella_list_customers` — returned 77 real customer organizations (real company names) on account 1. Failed with `403 Access Forbidden` on account 2 — confirmed by decoding that account's token that it genuinely lacks the `admin.customers:read` scope (20 total scopes vs. 76 on account 1). Not a code bug; a real per-key permission difference.

**⚠️ Unverified — returned well-formed but empty results on both accounts, not proven correct:** `cisco_umbrella_get_activity_dns`, `_proxy`, `_firewall`, `_amp_retrospective`, `cisco_umbrella_list_roaming_computers`. Cross-checked the live OpenAPI parameter definitions for Activity DNS directly against Cisco's own docs (pulled the raw spec, not summarized) — `from`/`to`/`limit` are exactly as implemented, no missing/misnamed parameter. The likely explanation is that both test accounts are **Managed Provider root orgs**, which have no direct DNS/proxy/firewall/AMP traffic or roaming computers of their own — that data lives under each *managed customer* org individually. Searched Cisco's docs for a "query as this customer org" scoping parameter/header for classic Umbrella — found none (a "Multi-Org" token-scoping concept exists, but only for the separate Secure Access/SASE product, not classic Umbrella). There's a distinct "Providers" API family (`/providers/customers/{customerId}/...`) that looks like it might be the intended path to per-customer data, but it's outside the 10-endpoint scope confirmed for this build. Needs a real single-customer-org credential (not provider-level) to actually confirm these 5.
- **`cisco_umbrella_list_applications`, `_protocols`, `_application_categories` (App Discovery) — confirmed blocked, not a code bug.** Reproduced identically on both test accounts and via direct curl with the same tokens (ruling out request-construction issues): `403 Access Forbidden` on account 1, `500`/`403` on account 2. Both tokens' scope lists included `reports.appdiscovery:read`, so this is most likely a package/entitlement restriction (App Discovery as a paid add-on not included in either account's "Umbrella for MSSPs" tier), not a permissions or parameter problem.
- `cisco_umbrella_get_providers_console` returns a single subscription-summary object, not a list — confirmed via both live tests. Despite the plural name in MSPbots' own configured API list ("Providers Consoles"), double-check this against whatever MSPbots' existing collector expects (array vs single object).
- The `Applications` app-discovery endpoint's optional parameter list may not be fully exhaustive (a couple of parameters near the end of that endpoint's schema were not fully captured during research) — the ones documented here (`sources`, `identity`, `labels`, `controllable`, `categories`, `subcategory`, `limit`, `offset`) are confirmed real; there may be one or two more not yet added.
- Scope is limited to the 10 operations MSPbots currently uses (user-confirmed), not Umbrella's full API surface (which also includes Networks, Internal Domains, Sites, Network Tunnels, Policies, Tagging, the separate "Providers" API for per-customer actions, and the Key Admin API for managing API keys themselves).

## API Reference

- [Cisco Umbrella API Authentication](https://developer.cisco.com/docs/cloud-security/umbrella-api-authentication/)
- [Cisco Cloud Security API Documentation (DevNet)](https://developer.cisco.com/docs/cloud-security/)
