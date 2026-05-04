"""Settings API routes for Agent configurations."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import set_key
from fastapi import APIRouter, HTTPException
from loguru import logger
from pydantic import BaseModel

import codebase_rag.constants as cs
from codebase_rag.config import settings

router = APIRouter(prefix="/settings", tags=["Settings"])


class AgentConfigRequest(BaseModel):
    role: str
    provider: str
    model: str
    api_key: str | None = None
    endpoint: str | None = None


class AgentConfigResponse(BaseModel):
    role: str
    provider: str
    model: str
    has_api_key: bool


class GlobalSettingsResponse(BaseModel):
    agents: dict[str, AgentConfigResponse]
    has_github_token: bool


@router.get("/models", response_model=GlobalSettingsResponse)
async def get_model_settings() -> GlobalSettingsResponse:
    """Retrieve the current specialized agent configurations. API keys are masked."""
    response = {}
    
    # Iterate over all defined model roles
    for role in cs.ModelRole:
        config = settings.get_agent_config(role)
        response[role.value] = AgentConfigResponse(
            role=role.value,
            provider=config.provider,
            model=config.model_id,
            has_api_key=bool(config.api_key and config.api_key != cs.DEFAULT_API_KEY)
        )
        
    return GlobalSettingsResponse(
        agents=response,
        has_github_token=bool(settings.GITHUB_TOKEN and settings.GITHUB_TOKEN != "")
    )


@router.post("/models")
async def update_model_settings(request: AgentConfigRequest):
    """Write an updated Model Configuration and API Key directly to .env."""
    
    if request.role not in [r.value for r in cs.ModelRole]:
        raise HTTPException(status_code=400, detail="Invalid Agent Role.")
        
    role_prefix = request.role.upper()
    env_path = Path(".env")
    
    if not env_path.exists():
        env_path.touch()
        
    try:
        set_key(str(env_path), f"{role_prefix}_PROVIDER", request.provider)
        set_key(str(env_path), f"{role_prefix}_MODEL", request.model)
        
        # We only overwrite API Key if one was explicitly passed, to avoid erasing 
        # existing ones when just switching models.
        if request.api_key is not None:
            set_key(str(env_path), f"{role_prefix}_API_KEY", request.api_key)
            
        if request.endpoint is not None:
            set_key(str(env_path), f"{role_prefix}_ENDPOINT", request.endpoint)
            
        logger.success(f"Updated configuration for {request.role} agent in .env")
        
        return {"status": "success", "message": f"{request.role} agent updated."}
        
    except Exception as e:
        logger.error(f"Failed to update .env configurations: {e}")
        raise HTTPException(status_code=500, detail="Failed to write configuration to .env")
