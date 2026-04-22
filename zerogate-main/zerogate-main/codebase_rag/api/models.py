"""Pydantic models for ZeroGate Web API request/response schemas."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field

# ── Enums ─────────────────────────────────────────────────────────────────


class ProjectStatus(str, Enum):
    QUEUED = "queued"
    PARSING = "parsing"
    INDEXING = "indexing"
    SCANNING = "scanning"
    DONE = "done"
    ERROR = "error"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FindingStatus(str, Enum):
    OPEN = "open"
    FIX_GENERATED = "fix_generated"
    APPLIED = "applied"
    DISMISSED = "dismissed"


# ── Project Models ────────────────────────────────────────────────────────


class ProjectUploadResponse(BaseModel):
    project_id: str
    status: ProjectStatus = ProjectStatus.QUEUED
    message: str = "Project uploaded successfully. Ingestion started."


class ProjectStatusResponse(BaseModel):
    project_id: str
    status: ProjectStatus
    progress: float = Field(0.0, ge=0.0, le=1.0)
    files_processed: int = 0
    total_files: int = 0
    error_message: str | None = None
    created_at: str | None = None


# ── Vulnerability Models ──────────────────────────────────────────────────


class AffectedNode(BaseModel):
    file_path: str
    function_name: str
    qualified_name: str | None = None
    start_line: int | None = None
    end_line: int | None = None


class VulnerabilityFinding(BaseModel):
    finding_id: str
    title: str
    severity: Severity
    category: str
    description: str
    blast_radius: list[AffectedNode] = []
    status: FindingStatus = FindingStatus.OPEN
    fix_available: bool = False
    fix_diff: str | None = None


class ReportSummary(BaseModel):
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class VulnerabilityReport(BaseModel):
    project_id: str
    scan_timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())
    findings: list[VulnerabilityFinding] = []
    summary: ReportSummary = Field(default_factory=ReportSummary)


# ── Fix/Patch Models ─────────────────────────────────────────────────────


class FixProposal(BaseModel):
    finding_id: str
    original_code: str
    patched_code: str
    unified_diff: str
    explanation: str
    file_path: str
    function_name: str | None = None


class ApplyFixRequest(BaseModel):
    finding_id: str


class ApplyFixResponse(BaseModel):
    finding_id: str
    status: Literal["applied", "failed"]
    message: str


# ── WebSocket Models ──────────────────────────────────────────────────────


class WSMessage(BaseModel):
    type: Literal["progress", "status", "finding", "error"]
    project_id: str
    data: dict
