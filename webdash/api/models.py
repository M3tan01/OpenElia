"""
webdash/api/models.py — brain-model configuration.

GET /models (token) — mode + model names + per-agent overrides + agent registry. No secrets.
POST setters (token + confirm) — local / cloud / hybrid / auth. /models/auth is write-only:
it stores the provider key in the keychain and never echoes it back.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from webdash.data import AGENT_REGISTRY, DashboardData, get_data
from webdash.guards import require_confirm
from webdash.security import require_token

router = APIRouter(prefix="/api", dependencies=[Depends(require_token)])

_VALID_AGENTS = {a for group in AGENT_REGISTRY.values() for a in group}


def _valid_providers() -> set[str]:
    from model_manager import SUPPORTED_PROVIDERS

    return set(SUPPORTED_PROVIDERS)


class LocalModel(BaseModel):
    model: str
    confirm: bool = False


class CloudModel(BaseModel):
    provider: str
    model: str
    confirm: bool = False


class HybridOverride(BaseModel):
    agent: str
    provider: str
    model: str
    confirm: bool = False


class ProviderAuth(BaseModel):
    provider: str
    api_key: str
    confirm: bool = False


@router.get("/models")
def get_models(data: DashboardData = Depends(get_data)) -> dict:
    """Active brain config (mode, models, overrides) + agent registry. No secrets."""
    return data.models()


@router.post("/models/local")
def set_local(req: LocalModel) -> dict:
    require_confirm(req.confirm)
    from model_manager import ModelManager

    ModelManager.set_local_model(req.model)
    return ModelManager.get_config()


@router.post("/models/cloud")
def set_cloud(req: CloudModel) -> dict:
    require_confirm(req.confirm)
    if req.provider.lower() not in _valid_providers():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=f"unknown provider '{req.provider}'")
    from model_manager import ModelManager

    ModelManager.set_cloud_model(req.provider, req.model)
    return ModelManager.get_config()


@router.post("/models/hybrid")
def set_hybrid(req: HybridOverride) -> dict:
    require_confirm(req.confirm)
    if req.agent not in _VALID_AGENTS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=f"unknown agent '{req.agent}'")
    if req.provider.lower() not in _valid_providers() | {"local", "ollama"}:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=f"unknown provider '{req.provider}'")
    from model_manager import ModelManager

    ModelManager.set_agent_override(req.agent, req.provider, req.model)
    return ModelManager.get_config()


@router.post("/models/auth")
def set_auth(req: ProviderAuth) -> dict:
    """Store a provider API key in the keychain. Write-only — never returns the key."""
    require_confirm(req.confirm)
    if req.provider.lower() not in _valid_providers():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=f"unknown provider '{req.provider}'")
    from model_manager import ModelManager

    ModelManager.store_provider_key(req.provider, req.api_key)
    return {"stored": True, "provider": req.provider.lower()}
