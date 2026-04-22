"""WebSocket endpoint for real-time project updates."""

from __future__ import annotations

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from loguru import logger

from codebase_rag.api.ws_manager import ws_manager

router = APIRouter(tags=["WebSocket"])


@router.websocket("/ws/{project_id}")
async def websocket_endpoint(websocket: WebSocket, project_id: str):
    """
    WebSocket connection for receiving real-time updates about a project.

    Messages are JSON objects with the shape:
        { "type": "status"|"progress"|"finding"|"error",
          "project_id": "...",
          "data": { ... } }
    """
    await ws_manager.connect(project_id, websocket)
    try:
        while True:
            # Keep connection alive; client can send pings
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        await ws_manager.disconnect(project_id, websocket)
        logger.debug(f"WebSocket client disconnected from project {project_id}")
    except Exception as e:
        await ws_manager.disconnect(project_id, websocket)
        logger.warning(f"WebSocket error for project {project_id}: {e}")
