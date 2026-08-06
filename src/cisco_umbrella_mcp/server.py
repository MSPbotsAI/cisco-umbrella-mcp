import contextvars
import sys
from collections.abc import Callable

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from .api_client import UmbrellaClient
from .config import Settings

# ─────────────────────────────────────────────────────────────────────────────
# Per-request credential contextvar for gateway mode.
# GatewayTokenMiddleware sets this before the MCP handler runs.
# Python asyncio copies context per task, so concurrent requests are isolated.
# ─────────────────────────────────────────────────────────────────────────────
_gateway_creds_var: contextvars.ContextVar[tuple[str, str] | None] = contextvars.ContextVar(
    "umbrella_gateway_creds", default=None
)


def get_client_from_context(settings: Settings) -> UmbrellaClient | None:
    """Resolve the active UmbrellaClient for the current request context."""
    if settings.auth_mode == "gateway":
        creds = _gateway_creds_var.get()
        if creds is None:
            return None
        api_key, key_secret = creds
    else:
        api_key = settings.umbrella_api_key
        key_secret = settings.umbrella_key_secret

    if not api_key or not key_secret:
        return None
    return UmbrellaClient(api_key, key_secret)


class GatewayTokenMiddleware:
    """ASGI middleware for gateway mode.

    Reads the configured API key + key secret headers from each request and
    stores them in the contextvar for the duration of that request. Returns
    401 if either header is missing on /mcp requests.
    """

    def __init__(self, app: ASGIApp, settings: Settings):
        self.app = app
        self.settings = settings

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if not path.startswith("/mcp"):
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        # Header lookup is case-insensitive in Starlette
        api_key = request.headers.get(self.settings.umbrella_api_key_header.lower())
        key_secret = request.headers.get(self.settings.umbrella_key_secret_header.lower())
        if not api_key or not key_secret:
            response = JSONResponse(
                {
                    "error": "Missing credentials",
                    "message": (
                        f"Gateway mode requires the {self.settings.umbrella_api_key_header} and "
                        f"{self.settings.umbrella_key_secret_header} headers"
                    ),
                    "required_headers": [
                        self.settings.umbrella_api_key_header,
                        self.settings.umbrella_key_secret_header,
                    ],
                },
                status_code=401,
            )
            await response(scope, receive, send)
            return

        ctx_token = _gateway_creds_var.set((api_key, key_secret))
        try:
            await self.app(scope, receive, send)
        finally:
            _gateway_creds_var.reset(ctx_token)


def create_mcp_server(settings: Settings) -> FastMCP:
    """Build the FastMCP server instance and register all tools."""
    # DNS-rebinding protection is disabled because the container runs behind
    # mcp-gateway on an internal Docker network and is never publicly exposed.
    mcp = FastMCP(
        name="cisco-umbrella-mcp",
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )

    client_factory: Callable[[], UmbrellaClient | None] = lambda: get_client_from_context(settings)

    if not settings.has_credentials:
        # Graceful degradation: register only a diagnostic tool when no credentials are available.
        @mcp.tool()
        async def cisco_umbrella_test_connection() -> str:
            """Test Cisco Umbrella API connection. Shows configuration requirements when credentials are missing."""
            return (
                "Error: Missing Cisco Umbrella credentials.\n\n"
                "Set the required environment variables:\n"
                "  UMBRELLA_API_KEY=your_api_key\n"
                "  UMBRELLA_KEY_SECRET=your_key_secret\n\n"
                "Or use gateway mode (per-request credentials):\n"
                "  AUTH_MODE=gateway\n"
                f"  Send headers: {settings.umbrella_api_key_header}: your_api_key, "
                f"{settings.umbrella_key_secret_header}: your_key_secret"
            )

        print(
            "Warning: No Cisco Umbrella credentials found. Only the diagnostic tool is available.",
            file=sys.stderr,
        )
        return mcp

    # Register all tool modules here.
    from .tools import reports

    reports.register(mcp, client_factory)

    return mcp
