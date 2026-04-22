"""WebSocket manager for broadcasting real-time updates to connected clients."""

from __future__ import annotations

import asyncio
import json
from collections import defaultdict

from fastapi import WebSocket
from loguru import logger


class ConnectionManager:
    """Manages WebSocket connections grouped by project_id."""

    def __init__(self) -> None:
        self._connections: dict[str, list[WebSocket]] = defaultdict(list)
        self._lock = asyncio.Lock()

    async def connect(self, project_id: str, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self._connections[project_id].append(websocket)
        logger.debug(f"WebSocket connected for project {project_id}")

    async def disconnect(self, project_id: str, websocket: WebSocket) -> None:
        async with self._lock:
            conns = self._connections.get(project_id, [])
            if websocket in conns:
                conns.remove(websocket)
            if not conns:
                self._connections.pop(project_id, None)
        logger.debug(f"WebSocket disconnected for project {project_id}")

    async def broadcast(self, project_id: str, message: dict) -> None:
        async with self._lock:
            conns = list(self._connections.get(project_id, []))

        dead: list[WebSocket] = []
        payload = json.dumps(message)

        for ws in conns:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)

        if dead:
            async with self._lock:
                for ws in dead:
                    conns_list = self._connections.get(project_id, [])
                    if ws in conns_list:
                        conns_list.remove(ws)


# Global singleton
ws_manager = ConnectionManager()
