from pydantic import BaseModel


class KacPolicyCreateRequest(BaseModel):
    name: str
    description: str = ""


class KacPolicyUpdateRequest(BaseModel):
    name: str | None = None
    description: str | None = None
    is_enabled: bool | None = None


class KacPrecedenceUpdate(BaseModel):
    precedence: int


class HostGroupsRequest(BaseModel):
    host_group_ids: list[str]


class RuleGroupCreateRequest(BaseModel):
    name: str
    description: str = ""


class RuleGroupUpdateRequest(BaseModel):
    name: str | None = None
    description: str | None = None
    deny_on_error: bool | None = None


class CustomRuleAddRequest(BaseModel):
    rule_id: str
    action: str = "Prevent"  # Valid: Prevent, Alert, Disabled


class CustomRulesDeleteRequest(BaseModel):
    rule_ids: list[str]


class LabelSelector(BaseModel):
    key: str
    operator: str
    value: str = ""


class NamespaceSelector(BaseModel):
    value: str


class SelectorsUpdateRequest(BaseModel):
    labels: list[LabelSelector] = []
    namespaces: list[NamespaceSelector] = []


class RuleGroupPrecedenceRequest(BaseModel):
    rule_group_ids: list[str]


class CustomRegoRuleCreateRequest(BaseModel):
    name: str
    description: str = ""
    logic: str
    severity: int = 3
    alert_info: str = ""
    remediation_info: str = ""


class CustomRegoRuleUpdateRequest(BaseModel):
    name: str | None = None
    description: str | None = None
    severity: int | None = None
    logic: str | None = None


class KacEvaluateRequest(BaseModel):
    logic: str
    manifest_yaml: str
