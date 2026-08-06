from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Transport
    mcp_transport: Literal["stdio", "http"] = "stdio"
    mcp_http_port: int = 8080
    mcp_http_host: str = "0.0.0.0"

    # Auth mode:
    # "gateway" — production/SOP-compliant: API key + key secret from HTTP headers per request (no global state)
    # "env"     — local dev only: shared API key + key secret from env vars (not SOP-compliant)
    auth_mode: Literal["env", "gateway"] = "gateway"

    # Cisco Umbrella credentials (only required in env mode)
    umbrella_api_key: str | None = None
    umbrella_key_secret: str | None = None

    # HTTP header names used to pass the API key + key secret in gateway mode.
    # The client must include both headers on every /mcp request.
    umbrella_api_key_header: str = "X-Umbrella-Api-Key"
    umbrella_key_secret_header: str = "X-Umbrella-Key-Secret"

    @property
    def has_credentials(self) -> bool:
        """Returns True if the server can serve API calls.

        Gateway mode always returns True — each request carries its own credentials.
        Env mode requires both UMBRELLA_API_KEY and UMBRELLA_KEY_SECRET to be set.
        """
        if self.auth_mode == "gateway":
            return True
        return self.umbrella_api_key is not None and self.umbrella_key_secret is not None


def get_settings() -> Settings:
    return Settings()
