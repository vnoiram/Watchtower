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


class TechnologyInventoryOut(BaseModel):
    id: UUID
    application_id: UUID
    application_name: str
    application_path: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    category: str
    name: str
    version: str | None
    detection_source: str
    confidence: float
    detected_at: datetime


class SbomInventoryOut(BaseModel):
    id: UUID
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    scan_id: UUID
    sbom_kind: str
    format: str
    specification_version: str | None
    commit_sha: str | None
    generated_at: datetime
    active: bool
    component_count: int


class ComponentApplicationOut(BaseModel):
    application_id: UUID
    application_name: str
    application_path: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    active_sbom_id: UUID
    generated_at: datetime


class ComponentInventoryOut(BaseModel):
    id: UUID
    purl: str
    ecosystem: str | None
    namespace: str | None
    name: str
    version: str | None
    supplier: str | None
    license: str | None
    active_sbom_count: int
    application_count: int
    applications: list[ComponentApplicationOut] = Field(default_factory=list)


class VulnerabilityInventoryOut(BaseModel):
    id: UUID
    source: str
    external_id: str
    title: str | None
    severity: models.Severity
    cvss_score: float | None
    open_finding_count: int
    affected_application_count: int


class RemediationActionOut(BaseModel):
    id: UUID
    finding_id: UUID
    action_type: str
    status: str
    provider: str | None
    provider_id: str | None
    url: str | None
    branch: str | None
    fixed_version: str | None
    metadata_json: dict[str, Any]
    created_at: datetime
    updated_at: datetime
    finding_severity: models.Severity | None = None
    finding_status: models.FindingStatus | None = None
    application_id: UUID | None = None
    application_name: str | None = None
    vulnerability_external_id: str | None = None
    component_name: str | None = None


class RemediationCandidateOut(BaseModel):
    finding_id: UUID
    finding_status: models.FindingStatus
    severity: models.Severity
    risk_score: float
    fixed_version: str
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    component_id: UUID
    component_name: str
    component_version: str | None
    vulnerability_id: UUID
    vulnerability_external_id: str
    vulnerability_title: str | None
    created_at: datetime


class GitHubIssueActionOut(RemediationActionOut):
    error: str | None = None
    close_error: str | None = None
    github_issue_url: str | None = None


class RemediationValidationOut(RemediationActionOut):
    validation_status: str
    validation_scan_id: UUID | None = None
    validation_scan_status: models.ScanStatus | None = None
    validation_error: str | None = None


class IssueClosureOut(BaseModel):
    finding_id: UUID
    finding_status: models.FindingStatus
    severity: models.Severity
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    vulnerability_external_id: str
    component_name: str
    action_id: UUID | None = None
    provider_id: str | None = None
    url: str | None = None
    close_state: str
    close_error: str | None = None
    github_issue_closed_at: str | None = None


class ArtifactInventoryOut(BaseModel):
    scan_id: UUID
    scan_status: models.ScanStatus
    scan_created_at: datetime
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    artifact_type: str
    storage_key: str
    digest: str | None = None
    sbom_id: UUID | None = None
    sbom_kind: str | None = None


class AiFixActionOut(RemediationActionOut):
    requested_fixed_version: str | None = None


class AiFixCandidateOut(RemediationCandidateOut):
    pass


class AutoMergeEligibilityOut(BaseModel):
    action_id: UUID
    action_type: str
    action_status: str
    finding_id: UUID
    finding_severity: models.Severity
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    allowed: bool
    reason: str
    dry_run: bool
    update_kind: str
    ci_passed: bool
    validation_scan_resolved: bool
    tier_allows: bool
    touches_forbidden_path: bool


class IsolatedLaneOut(BaseModel):
    repository_id: UUID
    repository_owner: str
    repository_name: str
    repository_provider: models.RepositoryProvider
    source_classification: models.SourceClassification
    application_id: UUID
    application_name: str
    application_path: str
    latest_scan_id: UUID | None
    latest_scan_status: models.ScanStatus | None
    latest_scan_created_at: datetime | None
    active_source_sbom_count: int


class SlaFindingOut(BaseModel):
    finding_id: UUID
    severity: models.Severity
    status: models.FindingStatus
    risk_score: float
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    vulnerability_external_id: str
    component_name: str
    created_at: datetime
    age_days: int
    sla_days: int
    due_at: datetime
    breached: bool


class AuditLogOut(BaseModel):
    id: UUID
    actor: str
    role: str
    action: str
    resource_type: str
    resource_id: str | None
    metadata_json: dict[str, Any]
    created_at: datetime


class OperationsReadinessOut(BaseModel):
    check: str
    status: str
    configured: bool
    detail: str


class DailyOperationCheckOut(BaseModel):
    check: str
    status: str
    count: int
    detail: str


class KpiMetricOut(BaseModel):
    metric: str
    value: float
    unit: str
    detail: str


class RepositoryRolloutOut(BaseModel):
    repository_id: UUID
    repository_owner: str
    repository_name: str
    provider: models.RepositoryProvider
    source_classification: models.SourceClassification
    archived: bool
    application_count: int
    owner_completeness_percent: float
    active_sbom_coverage_percent: float
    latest_scan_status: models.ScanStatus | None
    latest_scan_created_at: datetime | None
    stale_scan_count: int
    open_critical_high_count: int


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


class VexInventoryOut(VexOut):
    finding_status: models.FindingStatus
    finding_severity: models.Severity
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    component_name: str
    component_version: str | None
    vulnerability_external_id: str
    vulnerability_title: str | None
    expired: bool


class ScanHealthOut(BaseModel):
    application_id: UUID
    application_name: str
    application_path: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    latest_scan_id: UUID | None
    latest_scan_status: models.ScanStatus | None
    latest_scan_error_message: str | None
    scanner_failures: list[Any] = Field(default_factory=list)
    latest_scan_created_at: datetime | None
    latest_scan_completed_at: datetime | None
    stale: bool


class SbomCoverageOut(BaseModel):
    application_id: UUID
    application_name: str
    application_path: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    has_active_source_sbom: bool
    latest_sbom_id: UUID | None
    latest_sbom_generated_at: datetime | None
    component_count: int


class NotificationInventoryOut(BaseModel):
    id: UUID
    channel: str
    severity: models.Severity
    subject: str
    status: str
    sent_at: datetime | None
    created_at: datetime
    finding_id: UUID | None = None
    finding_status: models.FindingStatus | None = None
    application_id: UUID | None = None
    application_name: str | None = None
    component_name: str | None = None
    vulnerability_external_id: str | None = None


class ApplicationMaintenanceOut(BaseModel):
    application_id: UUID
    application_name: str
    application_path: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    owner: str | None
    support_status: str
    lifecycle: models.Lifecycle
    latest_scan_id: UUID | None
    latest_scan_status: models.ScanStatus | None
    latest_scan_created_at: datetime | None
    reasons: list[str] = Field(default_factory=list)


class JobHealthOut(BaseModel):
    id: UUID
    job_type: models.JobType
    status: models.JobStatus
    repository_id: UUID | None
    repository_owner: str | None = None
    repository_name: str | None = None
    application_id: UUID | None
    application_name: str | None = None
    attempts: int
    max_attempts: int
    run_after: datetime
    started_at: datetime | None
    completed_at: datetime | None
    last_error: str | None
    created_at: datetime
    health_reason: str


class DashboardSummary(BaseModel):
    repositories: int
    applications: int
    open_critical: int
    open_high: int
    stale_scans: int
    failed_jobs: int
    expired_vex: int
    sbom_coverage_percent: float
    missing_active_sbom: int
    unhealthy_jobs: int
    sla_breached_findings: int
    isolated_applications: int
    scan_failure_rate_percent: float
    notification_failure_count: int
