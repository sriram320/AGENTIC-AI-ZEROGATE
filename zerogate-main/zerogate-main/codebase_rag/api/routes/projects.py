"""Project management API routes: upload, status, scan, report, download."""

from __future__ import annotations

import asyncio
import os
import shutil
import uuid
import zipfile
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from loguru import logger

from codebase_rag.api.models import (
    ProjectStatus,
    ProjectStatusResponse,
    ProjectUploadResponse,
    VulnerabilityReport,
)
from codebase_rag.api.state import project_store
from codebase_rag.api.ws_manager import ws_manager

router = APIRouter(prefix="/projects", tags=["Projects"])

import tempfile
UPLOAD_BASE = Path(os.environ.get("ZEROGATE_UPLOAD_DIR", Path(tempfile.gettempdir()) / "zerogate" / "projects"))


async def _run_ingestion(project_id: str, project_path: Path) -> None:
    """Background task: ingest a project into Memgraph."""
    from codebase_rag.config import settings
    from codebase_rag.graph_updater import GraphUpdater

    state = project_store.get(project_id)
    if not state:
        return

    try:
        project_store.update_status(
            project_id, status=ProjectStatus.PARSING, progress=0.1
        )
        await ws_manager.broadcast(
            project_id,
            {
                "type": "status",
                "project_id": project_id,
                "data": {"status": "parsing", "progress": 0.1},
            },
        )

        # Count files for progress tracking
        all_files = list(project_path.rglob("*"))
        source_files = [f for f in all_files if f.is_file()]
        total = len(source_files)
        project_store.update_status(project_id, total_files=total)

        project_store.update_status(
            project_id, status=ProjectStatus.INDEXING, progress=0.3
        )
        await ws_manager.broadcast(
            project_id,
            {
                "type": "status",
                "project_id": project_id,
                "data": {"status": "indexing", "progress": 0.3},
            },
        )

        # Use existing GraphUpdater to parse and ingest into Memgraph
        from codebase_rag.parser_loader import load_parsers
        from codebase_rag.services.graph_service import MemgraphIngestor

        parsers, queries = load_parsers()

        ingestor = MemgraphIngestor(
            host=settings.MEMGRAPH_HOST,
            port=settings.MEMGRAPH_PORT,
            batch_size=settings.MEMGRAPH_BATCH_SIZE,
            username=settings.MEMGRAPH_USERNAME or None,
            password=settings.MEMGRAPH_PASSWORD or None,
        )
        with ingestor:
            ingestor.ensure_constraints()
            updater = GraphUpdater(
                repo_path=project_path,
                ingestor=ingestor,
                parsers=parsers,
                queries=queries,
            )
            updater.run()

        project_store.update_status(
            project_id,
            status=ProjectStatus.SCANNING,
            progress=0.7,
            files_processed=total,
        )
        await ws_manager.broadcast(
            project_id,
            {
                "type": "status",
                "project_id": project_id,
                "data": {"status": "scanning", "progress": 0.7},
            },
        )

        from codebase_rag.auto_scanner import AutoScanner
    
        scanner = AutoScanner(
            host=settings.MEMGRAPH_HOST,
            port=settings.MEMGRAPH_PORT,
            username=settings.MEMGRAPH_USERNAME,
            password=settings.MEMGRAPH_PASSWORD,
            project_path=str(project_path),
            orchestrator_config=settings.active_orchestrator_config,
        )
        report = await scanner.run_full_scan(project_id)
        
        project_store.update_status(
            project_id,
            status=ProjectStatus.SCANNING,
            progress=0.85,
        )
        await ws_manager.broadcast(
            project_id,
            {
                "type": "status",
                "project_id": project_id,
                "data": {"status": "analyzing_fixes", "progress": 0.85},
            },
        )

        # Run the Multi-Agent LangGraph Pipeline to triage and generate patches
        from codebase_rag.agents.graph import build_orchestrator_graph
        from codebase_rag.agents.state import AgentState
        
        if report.findings:
            logger.info("Starting Multi-Agent LangGraph Orchestration...")
            graph = build_orchestrator_graph()
            
            # Initial state
            initial_state: AgentState = {
                "project_id": project_id,
                "project_path": str(project_path),
                "vulnerabilities": report.findings,
                "current_index": 0,
                "is_exploitable": False,
                "analysis_reasoning": "",
                "current_patch": None,
                "verification_success": False,
                "verification_logs": "",
                "all_fixes": [],
            }
            
            # Run graph
            final_state = await graph.ainvoke(initial_state)
            
            # Update findings with patches and triage status
            fixes = final_state.get("all_fixes", [])
            for finding in report.findings:
                # Find matching fix
                matching_fix = next((f for f in fixes if f.finding_id == finding.finding_id), None)
                if matching_fix:
                    finding.fix_available = True
                    finding.fix_diff = matching_fix.unified_diff

        project_store.set_report(project_id, report)
        project_store.update_status(project_id, status=ProjectStatus.DONE, progress=1.0)

        await ws_manager.broadcast(
            project_id,
            {
                "type": "status",
                "project_id": project_id,
                "data": {
                    "status": "done",
                    "progress": 1.0,
                    "findings_count": len(report.findings),
                },
            },
        )
        logger.success(
            f"Project {project_id} ingestion and scan complete. "
            f"{len(report.findings)} findings."
        )

    except Exception as e:
        logger.error(f"Ingestion/scan failed for {project_id}: {e}")
        project_store.update_status(
            project_id,
            status=ProjectStatus.ERROR,
            error_message=str(e),
        )
        await ws_manager.broadcast(
            project_id,
            {
                "type": "error",
                "project_id": project_id,
                "data": {"message": str(e)},
            },
        )


@router.post("/upload", response_model=ProjectUploadResponse)
async def upload_project(file: UploadFile = File(...)):
    """Upload a ZIP file containing a project to analyze."""
    if not file.filename or not file.filename.endswith(".zip"):
        raise HTTPException(
            status_code=400,
            detail="Only .zip files are supported. Please compress your project first.",
        )

    project_id = uuid.uuid4().hex[:16]
    project_dir = UPLOAD_BASE / project_id
    project_dir.mkdir(parents=True, exist_ok=True)

    zip_path = project_dir / "upload.zip"
    try:
        content = await file.read()
        zip_path.write_bytes(content)

        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(project_dir / "source")

        zip_path.unlink()
    except zipfile.BadZipFile:
        shutil.rmtree(project_dir, ignore_errors=True)
        raise HTTPException(status_code=400, detail="Invalid ZIP file.")
    except Exception as e:
        shutil.rmtree(project_dir, ignore_errors=True)
        raise HTTPException(status_code=500, detail=f"Upload failed: {e}")

    source_dir = project_dir / "source"

    # If the ZIP contained a single top-level folder, use that as root
    entries = list(source_dir.iterdir())
    if len(entries) == 1 and entries[0].is_dir():
        source_dir = entries[0]

    state = project_store.create(project_id, source_dir)

    # Launch background ingestion + scan
    task = asyncio.create_task(_run_ingestion(project_id, source_dir))
    state._task = task

    return ProjectUploadResponse(project_id=project_id)


@router.get("/{project_id}/status", response_model=ProjectStatusResponse)
async def get_project_status(project_id: str):
    """Get the current ingestion/scan status of a project."""
    state = project_store.get(project_id)
    if not state:
        raise HTTPException(status_code=404, detail="Project not found.")
    return state.to_status_response()


@router.post("/{project_id}/scan")
async def trigger_scan(project_id: str):
    """Manually trigger a security scan for an already-ingested project."""
    state = project_store.get(project_id)
    if not state:
        raise HTTPException(status_code=404, detail="Project not found.")
    if state.status not in (ProjectStatus.DONE, ProjectStatus.ERROR):
        raise HTTPException(
            status_code=409,
            detail=f"Project is currently '{state.status.value}'. Wait for completion.",
        )

    from ...auto_scanner import AutoScanner
    from ...config import settings

    project_store.update_status(project_id, status=ProjectStatus.SCANNING, progress=0.5)

    try:
        scanner = AutoScanner(
            host=settings.MEMGRAPH_HOST,
            port=settings.MEMGRAPH_PORT,
            username=settings.MEMGRAPH_USERNAME,
            password=settings.MEMGRAPH_PASSWORD,
            project_path=str(state.upload_dir),
            orchestrator_config=settings.active_orchestrator_config,
        )
        report = await scanner.run_full_scan(project_id)
        project_store.set_report(project_id, report)
        project_store.update_status(project_id, status=ProjectStatus.DONE, progress=1.0)
        return {"status": "done", "findings_count": len(report.findings)}
    except Exception as e:
        project_store.update_status(
            project_id, status=ProjectStatus.ERROR, error_message=str(e)
        )
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{project_id}/report", response_model=VulnerabilityReport)
async def get_report(project_id: str):
    """Get the vulnerability scan report for a project."""
    state = project_store.get(project_id)
    if not state:
        raise HTTPException(status_code=404, detail="Project not found.")
    if not state.report:
        raise HTTPException(
            status_code=404,
            detail="No scan report available yet. Trigger a scan first.",
        )
    return state.report


@router.get("/{project_id}/download")
async def download_patched_project(project_id: str):
    """Download the (potentially patched) project as a ZIP file."""
    state = project_store.get(project_id)
    if not state:
        raise HTTPException(status_code=404, detail="Project not found.")

    import io

    buffer = io.BytesIO()
    source_dir = state.upload_dir

    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for file_path in source_dir.rglob("*"):
            if file_path.is_file():
                arcname = file_path.relative_to(source_dir)
                zf.write(file_path, arcname)

    buffer.seek(0)

    return StreamingResponse(
        buffer,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="zerogate-{project_id}.zip"'
        },
    )
