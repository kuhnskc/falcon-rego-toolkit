from typing import Optional

from backend.common.crowdstrike_client import CrowdStrikeClient
from backend.config import CROWDSTRIKE_CLOUDS


class AuthService:
    """Manages CrowdStrike API authentication session."""

    def __init__(self):
        self._client: Optional[CrowdStrikeClient] = None
        self._base_url: str = ""

    @property
    def is_authenticated(self) -> bool:
        return self._client is not None and self._client.token is not None

    @property
    def cloud_environment(self) -> str | None:
        for name, url in CROWDSTRIKE_CLOUDS.items():
            if url == self._base_url:
                return name
        return None

    @property
    def base_url(self) -> str:
        return self._base_url

    def login(self, client_id: str, client_secret: str, base_url: str) -> bool:
        client = CrowdStrikeClient(base_url, client_id, client_secret)
        client.authenticate()
        self._client = client
        self._base_url = base_url
        return True

    def logout(self):
        self._client = None
        self._base_url = ""

    def get_client(self) -> CrowdStrikeClient:
        if not self._client:
            raise RuntimeError("Not authenticated")
        return self._client


# Singleton auth service instance
auth_service = AuthService()
