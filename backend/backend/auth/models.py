from pydantic import BaseModel


class LoginRequest(BaseModel):
    client_id: str
    client_secret: str
    base_url: str = "https://api.crowdstrike.com"


class LoginResponse(BaseModel):
    authenticated: bool
    cloud_environment: str | None = None
    base_url: str


class AuthStatus(BaseModel):
    authenticated: bool
    cloud_environment: str | None = None
    base_url: str = ""
