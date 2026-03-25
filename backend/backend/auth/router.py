from fastapi import APIRouter, HTTPException

from backend.auth.models import LoginRequest, LoginResponse, AuthStatus
from backend.auth.service import auth_service
from backend.common.exceptions import AuthenticationError

router = APIRouter()


@router.post("/login", response_model=LoginResponse)
def login(req: LoginRequest):
    try:
        auth_service.login(req.client_id, req.client_secret, req.base_url)
        return LoginResponse(
            authenticated=True,
            cloud_environment=auth_service.cloud_environment,
            base_url=req.base_url,
        )
    except AuthenticationError as e:
        raise HTTPException(status_code=401, detail=str(e))


@router.post("/logout")
def logout():
    auth_service.logout()
    return {"status": "logged_out"}


@router.get("/status", response_model=AuthStatus)
def status():
    return AuthStatus(
        authenticated=auth_service.is_authenticated,
        cloud_environment=auth_service.cloud_environment,
        base_url=auth_service.base_url,
    )
