"""GitHub App Webhooks and Integration."""

from __future__ import annotations

import asyncio
import hmac
import os
import shutil
import subprocess
import uuid
from pathlib import Path

from fastapi import APIRouter, Header, HTTPException, Request
from loguru import logger

from codebase_rag.api.state import project_store

router = APIRouter(prefix="/github", tags=["GitHub"])

GITHUB_WEBHOOK_SECRET = os.environ.get("GITHUB_WEBHOOK_SECRET", "")
CLONE_BASE = Path(os.environ.get("ZEROGATE_UPLOAD_DIR", "storage/projects"))

@router.post("/import")
async def manual_import(request: Request):
    """Manually trigger a GitHub repository import and autonomous scan."""
    data = await request.json()
    repo_url = data.get("url")
    if not repo_url:
        raise HTTPException(status_code=400, detail="URL is required.")
        
    # Standardize URL for git clone
    clone_url = repo_url
    if not clone_url.endswith(".git") and "github.com" in clone_url:
        clone_url += ".git"
        
    project_id = uuid.uuid4().hex[:16]
    
    # Run in background to avoid process timeout
    asyncio.create_task(_clone_and_ingest(repo_url, "main", clone_url, project_id))
    
    return {"project_id": project_id, "status": "queued"}


def verify_signature(payload_body: bytes, signature_header: str) -> bool:
    """Verify that the webhook signature matches our secret."""
    if not GITHUB_WEBHOOK_SECRET:
        logger.warning("GITHUB_WEBHOOK_SECRET not set, blindly trusting webhook.")
        return True
        
    if not signature_header:
        return False
        
    hash_object = hmac.new(
        GITHUB_WEBHOOK_SECRET.encode("utf-8"),
        msg=payload_body,
        digestmod="sha256"
    )
    expected_signature = "sha256=" + hash_object.hexdigest()
    return hmac.compare_digest(expected_signature, signature_header)


async def _clone_and_ingest(repo_url: str, default_branch: str, clone_url: str, project_id: str | None = None) -> None:
    """Clone a GitHub repository and orchestrate a full Agentic Graph scan."""
    if not project_id:
        project_id = uuid.uuid4().hex[:16]
    project_dir = CLONE_BASE / project_id
    source_dir = project_dir / "source"
    
    try:
        logger.info(f"Cloning GitHub repo: {repo_url} into {source_dir}")
        source_dir.mkdir(parents=True, exist_ok=True)
        
        # In a real GitHub App, you would use an Installation Access Token to clone
        # For this prototype, we're assuming public repos or SSH keys configured on the host
        cmd = ["git", "clone", "--depth", "1", clone_url, str(source_dir)]
        result = await asyncio.to_thread(
            subprocess.run, cmd, capture_output=True, text=True, check=False
        )
        
        if result.returncode != 0:
            logger.error(f"Git clone failed: {result.stderr}")
            return
            
        logger.success(f"Successfully cloned {repo_url}. Triggering Autonomous Scan.")
        
        # Initialize project state
        state = project_store.create(project_id, source_dir)
        
        # Call the ingestion logic directly from the projects router
        from codebase_rag.api.routes.projects import _run_ingestion
        
        task = asyncio.create_task(_run_ingestion(project_id, source_dir))
        state._task = task
        
    except Exception as e:
        logger.error(f"Failed to handle GitHub webhook execution: {e}")
        shutil.rmtree(project_dir, ignore_errors=True)


@router.post("/webhook")
async def github_webhook(
    request: Request,
    x_github_event: str = Header(None),
    x_hub_signature_256: str = Header(None),
):
    """Handle incoming webhooks from GitHub API."""
    payload_body = await request.body()
    
    if not verify_signature(payload_body, x_hub_signature_256):
        raise HTTPException(status_code=401, detail="Invalid GitHub signature.")
        
    payload = await request.json()
    
    # Handle Ping event on installation
    if x_github_event == "ping":
        logger.info("Received GitHub ping event.")
        return {"status": "pong"}
        
    # Handle Push Event
    if x_github_event == "push":
        repository = payload.get("repository", {})
        repo_url = repository.get("html_url")
        clone_url = repository.get("clone_url")
        default_branch = repository.get("default_branch", "main")
        
        # Ensure we're only scanning pushes to the default branch to reduce noise
        ref = payload.get("ref", "")
        if ref == f"refs/heads/{default_branch}":
            if repo_url and clone_url:
                asyncio.create_task(_clone_and_ingest(repo_url, default_branch, clone_url))
                return {"status": "accepted", "message": "Autonomous scan queued for main branch."}
        else:
            return {"status": "ignored", "message": "Push not on default branch."}
            
    logger.info(f"Ignored unhandled GitHub event: {x_github_event}")
    return {"status": "ignored"}
