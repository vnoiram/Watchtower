from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from api.app import models


class ProblemDetails(BaseModel):
    type: str = "about:blank"
    title: str
    status: int
    detail: str | None = None
    instance: str | None = None


class CursorPage(BaseModel):
    items: list[Any]
    next_cursor: str | None = None


class RepositoryCreate(BaseModel):
    provider: models.RepositoryProvider
    owner: str
    name: str
    provider_repository_id: str | None = None
    url: str | None = None
    local_path: str | None = None
    visibility: str | None = None
    default_branch: str | None = "main"
    source_classification: models.SourceClassification = models.SourceClassification.private


class RepositoryOut(RepositoryCreate):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    archived: bool
    fork: bool
    topics: list[str]
    primary_language: str | None
    last_synced_at: datetime | None
    pushed_at: datetime | None
    created_at: datetime
    updated_at: datetime


class ApplicationCreate(BaseModel):
    repository_id: UUID
    name: str
    path: str = "."
    application_type: models.ApplicationType = models.ApplicationType.unknown
    lifecycle: models.Lifecycle = models.Lifecycle.experimental
    criticality: str = "medium"
    internet_exposed: bool = False
    production: bool = False
    auto_fix_enabled: bool = False
    auto_merge_enabled: bool = False
    owner: str | None = None


class ApplicationOut(ApplicationCreate):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    support_status: str
    latest_scan_at: datetime | None = None
    latest_scan_status: models.ScanStatus | None = None
    created_at: datetime
    updated_at: datetime


class JobCreate(BaseModel):
    job_type: models.JobType
    repository_id: UUID | None = None
    application_id: UUID | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    max_attempts: int = 3


class JobOut(JobCreate):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    status: models.JobStatus
    attempts: int
    locked_by: str | None
    locked_at: datetime | None
    run_after: datetime
    started_at: datetime | None
    completed_at: datetime | None
    last_error: str | None
    created_at: datetime
    updated_at: datetime


class ScanCreate(BaseModel):
    application_id: UUID
    scan_type: str = "source"
    trigger_type: models.TriggerType = models.TriggerType.manual
    commit_sha: str | None = None
    branch: str | None = None
    tool: str | None = None
    tool_version: str | None = None


class ScanOut(ScanCreate):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    status: models.ScanStatus
    result_summary: dict[str, Any]
    error_message: str | None
    retry_count: int
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    application_id: UUID
    component_id: UUID
    vulnerability_id: UUID
    status: models.FindingStatus
    severity: models.Severity
    fixed_version: str | None
    risk_score: float
    resolved_at: datetime | None
    created_at: datetime
    updated_at: datetime


class VexCreate(BaseModel):
    finding_id: UUID
    status: models.VexStatus
    justification: str
    impact_statement: str | None = None
    approved_by: str
    review_date: datetime

    @model_validator(mode="after")
    def require_future_review_date(self) -> "VexCreate":
        if self.review_date is None:
            raise ValueError("review_date is required")
        return self


class VexOut(VexCreate):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    created_at: datetime
    updated_at: datetime


class DashboardSummary(BaseModel):
    repositories: int
    applications: int
    open_critical: int
    open_high: int
    stale_scans: int
    failed_jobs: int
    expired_vex: int
