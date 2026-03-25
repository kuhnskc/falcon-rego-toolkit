from pydantic import BaseModel


class PolicyCreateRequest(BaseModel):
    name: str
    description: str
    logic: str
    resource_type: str
    severity: int
    alert_info: str
    remediation_info: str = ""


class PolicyUpdateRequest(BaseModel):
    description: str | None = None
    severity: int | None = None
    logic: str | None = None
    platform: str | None = None
    alert_info: str | None = None
    remediation_info: str | None = None


class PolicyTestRequest(BaseModel):
    logic: str
    resource_type: str
    num_assets: int = 3


class SampleAssetRequest(BaseModel):
    resource_type: str
