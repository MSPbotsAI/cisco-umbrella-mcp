import asyncio
import base64
from typing import Any

import httpx

from ._json import error_envelope

BASE_URL = "https://api.umbrella.com"
TOKEN_URL = f"{BASE_URL}/auth/v2/token"

_TIMEOUT = httpx.Timeout(connect=5.0, read=30.0, write=10.0, pool=5.0)
_RETRYABLE_STATUS = {429, 500, 502, 503, 504}
_MAX_RETRIES = 3
_MAX_BACKOFF_SECONDS = 20.0

# One shared connection pool for the process lifetime. No credentials are
# ever stored on it — api_key/key_secret are passed per-call, so this is
# safe to share across tenants/requests (see server.py's contextvar-based
# credential isolation, which is what actually keeps tenants apart).
_http_client: httpx.AsyncClient | None = None


def _get_http_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None:
        _http_client = httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True)
    return _http_client


# status_code -> (error code, retryable). status_code 0 means a network/
# connection-level failure (no response at all).
_STATUS_TO_CODE: dict[int, tuple[str, bool]] = {
    0: ("upstream_error", True),
    400: ("invalid_argument", False),
    401: ("unauthorized", False),
    403: ("unauthorized", False),
    404: ("not_found", False),
    422: ("invalid_argument", False),
    429: ("rate_limited", True),
}


def _classify(status_code: int) -> tuple[str, bool]:
    if status_code in _STATUS_TO_CODE:
        return _STATUS_TO_CODE[status_code]
    if status_code >= 500:
        return "upstream_error", True
    return "invalid_argument", False


class UmbrellaError(Exception):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message
        super().__init__(f"Cisco Umbrella API error {status_code}: {message}")

    def to_envelope(self) -> str:
        code, retryable = _classify(self.status_code)
        return error_envelope(code, self.message, retryable)


def _retry_delay(resp: httpx.Response, attempt: int) -> float:
    retry_after = resp.headers.get("Retry-After")
    if retry_after:
        try:
            return min(float(retry_after), _MAX_BACKOFF_SECONDS)
        except ValueError:
            pass
    return min(2**attempt, _MAX_BACKOFF_SECONDS)


def _raise_for_status(resp: httpx.Response) -> None:
    if resp.status_code >= 400:
        try:
            detail = resp.json()
            if isinstance(detail, dict):
                msg = detail.get("message") or detail.get("error") or str(detail)
            else:
                msg = str(detail)
        except ValueError:
            msg = resp.text
        raise UmbrellaError(resp.status_code, msg)


async def _request_with_retry(
    method: str,
    url: str,
    *,
    headers: dict[str, str],
    params: dict | None = None,
    data: dict | None = None,
) -> httpx.Response:
    """Issue one HTTP request against the shared connection pool, with
    limited retry + exponential backoff on 429/5xx and network-level
    errors (honoring Retry-After when the upstream sends one). Used for
    both the OAuth token exchange and the actual report/report-adjacent
    API calls, so a transient blip on either leg gets the same treatment.
    """
    client = _get_http_client()
    last_exc: Exception | None = None
    for attempt in range(_MAX_RETRIES + 1):
        try:
            resp = await client.request(method, url, headers=headers, params=params, data=data)
        except httpx.RequestError as e:
            last_exc = e
            if attempt < _MAX_RETRIES:
                await asyncio.sleep(min(2**attempt, _MAX_BACKOFF_SECONDS))
                continue
            raise UmbrellaError(0, f"{e or type(e).__name__} (url={url})") from e

        if resp.status_code in _RETRYABLE_STATUS and attempt < _MAX_RETRIES:
            await asyncio.sleep(_retry_delay(resp, attempt))
            continue
        return resp

    # Unreachable in practice (loop always returns or raises above), but
    # keeps type checkers happy and guards against future edits.
    if last_exc:
        raise UmbrellaError(0, f"{last_exc}") from last_exc
    raise UmbrellaError(0, "request failed with no response")


class UmbrellaClient:
    """Async httpx client wrapping the Cisco Umbrella REST API v2.

    Auth: OAuth2 client_credentials grant. The API Key + Key Secret pair
    (created in Umbrella under Admin > API Keys) is exchanged for a bearer
    access token (1 hour expiry, no refresh token) via HTTP Basic Auth on
    POST /auth/v2/token. Since the token can't be cached across requests in
    a stateless multi-tenant service, this client deliberately re-
    authenticates on every call — do not add token caching here.

    Both the token exchange and the actual API call reuse the shared
    module-level connection pool (see _get_http_client) and get limited
    retry + backoff on 429/5xx via _request_with_retry.
    """

    def __init__(self, api_key: str, key_secret: str):
        self._api_key = api_key
        self._key_secret = key_secret

    async def _login(self) -> str:
        basic = base64.b64encode(f"{self._api_key}:{self._key_secret}".encode()).decode()
        resp = await _request_with_retry(
            "POST",
            TOKEN_URL,
            headers={
                "Authorization": f"Basic {basic}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data={"grant_type": "client_credentials"},
        )
        _raise_for_status(resp)
        return resp.json()["access_token"]

    def _clean_params(self, params: dict | None) -> dict:
        if not params:
            return {}
        return {k: v for k, v in params.items() if v is not None}

    async def get(self, path: str, params: dict | None = None) -> Any:
        token = await self._login()
        resp = await _request_with_retry(
            "GET",
            f"{BASE_URL}{path}",
            headers={"Authorization": f"Bearer {token}"},
            params=self._clean_params(params),
        )
        _raise_for_status(resp)
        if resp.status_code == 204 or not resp.content:
            return None
        try:
            return resp.json()
        except ValueError:
            return {"raw_response": resp.text}
