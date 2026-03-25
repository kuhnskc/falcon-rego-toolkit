from fastapi import APIRouter, HTTPException, Query

from backend.auth.service import auth_service
from backend.cspm.models import PolicyCreateRequest, PolicyUpdateRequest, PolicyTestRequest
from backend.cspm.service import CspmService

router = APIRouter()


def _get_service() -> CspmService:
    try:
        client = auth_service.get_client()
    except RuntimeError:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return CspmService(client)


@router.get("/policies")
def list_policies():
    svc = _get_service()
    return svc.list_policies()


@router.post("/policies")
def create_policy(req: PolicyCreateRequest):
    svc = _get_service()
    result = svc.create_policy(
        name=req.name,
        description=req.description,
        logic=req.logic,
        resource_type=req.resource_type,
        severity=req.severity,
        alert_info=req.alert_info,
        remediation_info=req.remediation_info,
    )
    if result.get("error"):
        raise HTTPException(status_code=result["status_code"], detail=result["detail"])
    return result


@router.patch("/policies/{uuid}")
def update_policy(uuid: str, req: PolicyUpdateRequest):
    svc = _get_service()
    updates = req.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")
    result = svc.update_policy(uuid, updates)
    if result.get("error"):
        raise HTTPException(status_code=result["status_code"], detail=result["detail"])
    return result


@router.delete("/policies/{uuid}")
def delete_policy(uuid: str):
    svc = _get_service()
    result = svc.delete_policy(uuid)
    if result.get("error"):
        raise HTTPException(status_code=result["status_code"], detail=result["detail"])
    return result


@router.post("/policies/test")
def test_policy(req: PolicyTestRequest):
    svc = _get_service()
    return svc.test_policy(req.logic, req.resource_type, req.num_assets)


@router.get("/assets/sample")
def get_sample_asset(resource_type: str = Query(...)):
    svc = _get_service()
    data = svc.get_sample_asset(resource_type)
    if data is None:
        raise HTTPException(status_code=404, detail=f"No sample asset found for {resource_type}")
    return data


@router.get("/resource-types")
def get_resource_types():
    svc = _get_service()
    return svc.discover_resource_types()


@router.get("/input-schema")
def get_input_schema(resource_type: str = Query(...)):
    svc = _get_service()
    data = svc.get_input_schema(resource_type)
    if data is None:
        raise HTTPException(status_code=404, detail=f"No schema found for {resource_type}")
    return data
