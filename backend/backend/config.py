from pydantic_settings import BaseSettings

DEFAULT_BASE_URL = "https://api.crowdstrike.com"
API_TIMEOUT = 30

CROWDSTRIKE_CLOUDS = {
    "US-1": "https://api.crowdstrike.com",
    "US-2": "https://api.us-2.crowdstrike.com",
    "EU-1": "https://api.eu-1.crowdstrike.com",
    "US-GOV-1": "https://api.laggar.gcw.crowdstrike.com",
    "US-GOV-2": "https://api.govcloud-us-east-1.crowdstrike.com",
}


class Settings(BaseSettings):
    falcon_client_id: str = ""
    falcon_client_secret: str = ""
    falcon_base_url: str = DEFAULT_BASE_URL

    class Config:
        env_file = ".env"
