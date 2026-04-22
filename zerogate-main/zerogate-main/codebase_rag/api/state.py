"""In-memory project state manager for tracking upload/scan lifecycle."""

from __future__ import annotations

import asyncio
import threading
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .models import (
    FixProposal,
    ProjectStatus,
    ProjectStatusResponse,
    VulnerabilityReport,
)


@dataclass
class ProjectState:
    project_id: str
    upload_dir: Path
    status: ProjectStatus = ProjectStatus.QUEUED
    progress: float = 0.0
    files_processed: int = 0
    total_files: int = 0
    error_message: str | None = None
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    report: VulnerabilityReport | None = None
    fix_proposals: dict[str, FixProposal] = field(default_factory=dict)
    _task: asyncio.Task | None = field(default=None, repr=False)

    def to_status_response(self) -> ProjectStatusResponse:
        return ProjectStatusResponse(
            project_id=self.project_id,
            status=self.status,
            progress=self.progress,
            files_processed=self.files_processed,
            total_files=self.total_files,
            error_message=self.error_message,
            created_at=self.created_at,
        )


class ProjectStore:
    """Thread-safe in-memory store for active projects."""

    def __init__(self) -> None:
        self._projects: dict[str, ProjectState] = {}
        self._lock = threading.Lock()

    def create(self, project_id: str, upload_dir: Path) -> ProjectState:
        state = ProjectState(project_id=project_id, upload_dir=upload_dir)
        with self._lock:
            self._projects[project_id] = state
        return state

    def get(self, project_id: str) -> ProjectState | None:
        with self._lock:
            return self._projects.get(project_id)

    def update_status(
        self,
        project_id: str,
        *,
        status: ProjectStatus | None = None,
        progress: float | None = None,
        files_processed: int | None = None,
        total_files: int | None = None,
        error_message: str | None = None,
    ) -> ProjectState | None:
        with self._lock:
            state = self._projects.get(project_id)
            if state is None:
                return None
            if status is not None:
                state.status = status
            if progress is not None:
                state.progress = progress
            if files_processed is not None:
                state.files_processed = files_processed
            if total_files is not None:
                state.total_files = total_files
            if error_message is not None:
                state.error_message = error_message
            return state

    def set_report(self, project_id: str, report: VulnerabilityReport) -> None:
        with self._lock:
            state = self._projects.get(project_id)
            if state:
                state.report = report

    def list_all(self) -> list[ProjectState]:
        with self._lock:
            return list(self._projects.values())


# Global singleton
project_store = ProjectStore()
