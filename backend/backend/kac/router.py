from fastapi import APIRouter, HTTPException, Query

from backend.auth.service import auth_service
from backend.kac.models import (
    KacPolicyCreateRequest,
    KacPolicyUpdateRequest,
    KacPrecedenceUpdate,
    HostGroupsRequest,
    RuleGroupCreateRequest,
    RuleGroupUpdateRequest,
    CustomRuleAddRequest,
    CustomRulesDeleteRequest,
    SelectorsUpdateRequest,
    RuleGroupPrecedenceRequest,
    CustomRegoRuleCreateRequest,
    CustomRegoRuleUpdateRequest,
    KacEvaluateRequest,
)
from backend.kac.service import KacService

router = APIRouter()


def _get_service() -> KacService:
    try:
        client = auth_service.get_client()
    except RuntimeError:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return KacService(client)


# ── Policies ────────────────────────────────────────────────────────

@router.get("/policies")
def list_policies(
    filter: str | None = Query(None),
    limit: int = Query(100, le=500),
    offset: int = Query(0),
):
    svc = _get_service()
    return svc.list_policies(filter_str=filter, limit=limit, offset=offset)


@router.get("/policies/{policy_id}")
def get_policy(policy_id: str):
    svc = _get_service()
    policy = svc.get_policy(policy_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    return policy


@router.post("/policies")
def create_policy(req: KacPolicyCreateRequest):
    svc = _get_service()
    result = svc.create_policy(name=req.name, description=req.description)
    if result.get("error"):
        raise HTTPException(status_code=result["status_code"], detail=result["detail"])
    return result


@router.patch("/policies/{policy_id}")
def update_policy(policy_id: str, req: KacPolicyUpdateRequest):
    svc = _get_service()
    updates = req.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")
    result = svc.update_policy(policy_id, updates)
    if result.get("error"):
        raise HTTPException(status_code=result["status_code"], detail=result["detail"])
    return result


@router.delete("/policies/{policy_id}")
def delete_policy(policy_id: str):
    svc = _get_service()
    result = svc.delete_policy(policy_id)
    if result.get("error"):
        raise HTTPException(status_code=result["status_code"], detail=result["detail"])
    return result


@router.patch("/policies/{policy_id}/precedence")
def update_precedence(policy_id: str, req: KacPrecedenceUpdate):
    svc = _get_service()
    result = svc.update_precedence(policy_id, req.precedence)
    if result.get("error"):
        raise HTTPException(status_code=result["status_code"], detail=result["detail"])
    return result


# ── Host groups ─────────────────────────────────────────────────────

@router.post("/policies/{policy_id}/host-groups")
def add_host_groups(policy_id: str, req: HostGroupsRequest):
    svc = _get_service()
    result = svc.add_host_groups(policy_id, req.host_group_ids)
    if result.get("error"):
        raise HTTPException(status_code=result["status_code"], detail=result["detail"])
    return result


@router.delete("/policies/{policy_id}/host-groups")
def remove_host_groups(policy_id: str, host_group_ids: list[str] = Query(...)):
    svc = _get_service()
    result = svc.remove_host_groups(policy_id, host_group_ids)
    if result.get("error"):
        raise HTTPException(status_code=result["status_code"], detail=result["detail"])
    return result


# ── Rule groups ─────────────────────────────────────────────────────

@router.post("/policies/{policy_id}/rule-groups")
def create_rule_groups(policy_id: str, groups: list[RuleGroupCreateRequest]):
    svc = _get_service()
    groups_dicts = [g.model_dump() for g in groups]
    result = svc.create_rule_groups(policy_id, groups_dicts)
    if result.get("error"):
        raise HTTPException(status_code=result["status_code"], detail=result["detail"])
    return result


@router.patch("/policies/{policy_id}/rule-groups/{group_id}")
def update_rule_group(policy_id: str, group_id: str, req: RuleGroupUpdateRequest):
    svc = _get_service()
    update_data = req.model_dump(exclude_none=True)
    update_data["id"] = group_id
    result = svc.update_rule_group(policy_id, update_data)
    if result.get("error"):
        raise HTTPException(status_code=result["status_code"], detail=result["detail"])
    return result


@router.delete("/policies/{policy_id}/rule-groups")
def delete_rule_groups(policy_id: str, rule_group_ids: list[str] = Query(...)):
    svc = _get_service()
    result = svc.delete_rule_groups(policy_id, rule_group_ids)
    if result.get("error"):
        raise HTTPException(status_code=result["status_code"], detail=result["detail"])
    return result


# ── Custom rules ────────────────────────────────────────────────────

@router.post("/policies/{policy_id}/rule-groups/{group_id}/custom-rules")
def add_custom_rules(policy_id: str, group_id: str, rules: list[CustomRuleAddRequest]):
    svc = _get_service()
    rules_dicts = [{"id": r.rule_id, "action": r.action} for r in rules]
    result = svc.add_custom_rules(policy_id, group_id, rules_dicts)
    if result.get("error"):
        raise HTTPException(status_code=result["status_code"], detail=result["detail"])
    return result


@router.delete("/policies/{policy_id}/custom-rules")
def delete_custom_rules(policy_id: str, req: CustomRulesDeleteRequest):
    svc = _get_service()
    result = svc.delete_custom_rules(policy_id, req.rule_ids)
    if result.get("error"):
        raise HTTPException(status_code=result["status_code"], detail=result["detail"])
    return result


# ── Selectors ───────────────────────────────────────────────────────

@router.put("/policies/{policy_id}/rule-groups/{group_id}/selectors")
def update_selectors(policy_id: str, group_id: str, req: SelectorsUpdateRequest):
    svc = _get_service()
    selectors = {
        "labels": [l.model_dump() for l in req.labels],
        "namespaces": [n.model_dump() for n in req.namespaces],
    }
    result = svc.update_selectors(policy_id, group_id, selectors)
    if result.get("error"):
        raise HTTPException(status_code=result["status_code"], detail=result["detail"])
    return result


# ── Rule group precedence ───────────────────────────────────────────

@router.put("/policies/{policy_id}/rule-groups/precedence")
def set_rule_group_precedence(policy_id: str, req: RuleGroupPrecedenceRequest):
    svc = _get_service()
    result = svc.set_rule_group_precedence(policy_id, req.rule_group_ids)
    if result.get("error"):
        raise HTTPException(status_code=result["status_code"], detail=result["detail"])
    return result


# ── Custom Rego rule creation (upload logic) ───────────────────────

@router.post("/custom-rego-rules")
def create_custom_rego_rule(req: CustomRegoRuleCreateRequest):
    svc = _get_service()
    result = svc.create_custom_rego_rule(
        name=req.name,
        description=req.description,
        logic=req.logic,
        severity=req.severity,
        alert_info=req.alert_info,
        remediation_info=req.remediation_info,
    )
    if result.get("error"):
        raise HTTPException(status_code=result["status_code"], detail=result["detail"])
    return result


@router.delete("/custom-rego-rules/{rule_uuid}")
def delete_custom_rego_rule(rule_uuid: str):
    svc = _get_service()
    result = svc.delete_custom_rego_rule(rule_uuid)
    if result.get("error"):
        raise HTTPException(status_code=result["status_code"], detail=result["detail"])
    return result


@router.get("/custom-rego-rules/{rule_uuid}")
def get_custom_rego_rule(rule_uuid: str):
    svc = _get_service()
    rule = svc.get_custom_rego_rule(rule_uuid)
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule


@router.patch("/custom-rego-rules/{rule_uuid}")
def update_custom_rego_rule(rule_uuid: str, req: CustomRegoRuleUpdateRequest):
    svc = _get_service()
    updates = req.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")
    result = svc.update_custom_rego_rule(rule_uuid, updates)
    if result.get("error"):
        raise HTTPException(status_code=result["status_code"], detail=result["detail"])
    return result


# ── Local OPA evaluation (no CrowdStrike auth required) ──────────

@router.post("/evaluate-rule")
def evaluate_rule(req: KacEvaluateRequest):
    """Evaluate a KAC Rego rule locally against a K8s manifest using OPA."""
    return KacService.evaluate_rule(req.logic, req.manifest_yaml)
