import base64
from typing import Any

import httpx

BASE_URL = "https://api.umbrella.com"
TOKEN_URL = f"{BASE_URL}/auth/v2/token"


class UmbrellaError(Exception):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        super().__init__(f"Cisco Umbrella API error {status_code}: {message}")


class UmbrellaClient:
    """Async httpx client wrapping the Cisco Umbrella REST API v2.

    Auth: OAuth2 client_credentials grant. The API Key + Key Secret pair
    (created in Umbrella under Admin > API Keys) is exchanged for a bearer
    access token (1 hour expiry, no refresh token) via HTTP Basic Auth on
    POST /auth/v2/token. Since the token can't be cached across requests in
    a stateless service, this client re-authenticates on every call.
    """

    def __init__(self, api_key: str, key_secret: str):
        self._api_key = api_key
        self._key_secret = key_secret

    async def _login(self, client: httpx.AsyncClient) -> str:
        basic = base64.b64encode(f"{self._api_key}:{self._key_secret}".encode()).decode()
        resp = await client.post(
            TOKEN_URL,
            headers={
                "Authorization": f"Basic {basic}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data={"grant_type": "client_credentials"},
        )
        self._raise_for_status(resp)
        return resp.json()["access_token"]

    def _clean_params(self, params: dict | None) -> dict:
        if not params:
            return {}
        return {k: v for k, v in params.items() if v is not None}

    async def get(self, path: str, params: dict | None = None) -> Any:
        async with httpx.AsyncClient() as client:
            token = await self._login(client)
            resp = await client.get(
                f"{BASE_URL}{path}",
                headers={"Authorization": f"Bearer {token}"},
                params=self._clean_params(params),
            )
            self._raise_for_status(resp)
            return resp.json() if resp.status_code != 204 else None

    def _raise_for_status(self, resp: httpx.Response) -> None:
        if resp.status_code >= 400:
            try:
                detail = resp.json()
            except Exception:
                detail = resp.text
            raise UmbrellaError(resp.status_code, str(detail))
