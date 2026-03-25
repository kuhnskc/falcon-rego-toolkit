import time
from typing import Optional

import requests

from backend.config import API_TIMEOUT
from backend.common.exceptions import CrowdStrikeAPIError, AuthenticationError


class CrowdStrikeClient:
    """Shared HTTP client for CrowdStrike API with token management."""

    def __init__(self, base_url: str, client_id: str, client_secret: str):
        self.base_url = base_url.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.token: Optional[str] = None
        self.token_expiry: float = 0

    def authenticate(self) -> bool:
        url = f"{self.base_url}/oauth2/token"
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }
        resp = requests.post(url, headers=headers, data=data, timeout=API_TIMEOUT)
        if resp.status_code not in (200, 201):
            raise AuthenticationError(f"Authentication failed: {resp.status_code} {resp.text}")
        body = resp.json()
        self.token = body["access_token"]
        self.token_expiry = time.time() + body.get("expires_in", 1799) - 60  # refresh 60s early
        return True

    def _ensure_token(self):
        if self.token is None or time.time() >= self.token_expiry:
            self.authenticate()

    def _headers(self, extra: dict | None = None) -> dict:
        self._ensure_token()
        h = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if extra:
            h.update(extra)
        return h

    def get(self, path: str, params: dict | None = None, extra_headers: dict | None = None) -> requests.Response:
        resp = requests.get(
            f"{self.base_url}{path}",
            headers=self._headers(extra_headers),
            params=params,
            timeout=API_TIMEOUT,
        )
        return resp

    def post(self, path: str, json: dict | None = None, params: dict | None = None, extra_headers: dict | None = None) -> requests.Response:
        resp = requests.post(
            f"{self.base_url}{path}",
            headers=self._headers(extra_headers),
            json=json,
            params=params,
            timeout=API_TIMEOUT,
        )
        return resp

    def patch(self, path: str, json: dict | None = None, params: dict | None = None, extra_headers: dict | None = None) -> requests.Response:
        resp = requests.patch(
            f"{self.base_url}{path}",
            headers=self._headers(extra_headers),
            json=json,
            params=params,
            timeout=API_TIMEOUT,
        )
        return resp

    def delete(self, path: str, params: dict | None = None, json: dict | None = None, extra_headers: dict | None = None) -> requests.Response:
        resp = requests.delete(
            f"{self.base_url}{path}",
            headers=self._headers(extra_headers),
            params=params,
            json=json,
            timeout=API_TIMEOUT,
        )
        return resp

    def put(self, path: str, json: dict | None = None, params: dict | None = None, extra_headers: dict | None = None) -> requests.Response:
        resp = requests.put(
            f"{self.base_url}{path}",
            headers=self._headers(extra_headers),
            json=json,
            params=params,
            timeout=API_TIMEOUT,
        )
        return resp
