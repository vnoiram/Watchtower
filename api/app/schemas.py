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


class ComponentUsageOut(BaseModel):
    component_id: UUID
    purl: str
    ecosystem: str | None
    component_name: str
    component_version: str | None
    application_id: UUID
    application_name: str
    application_path: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    active_sbom_id: UUID
    generated_at: datetime


class VulnerabilityInventoryOut(BaseModel):
    id: UUID
    source: str
    external_id: str
    title: str | None
    severity: models.Severity
    cvss_score: float | None
    open_finding_count: int
    affected_application_count: int


class VulnerabilityImpactOut(BaseModel):
    finding_id: UUID
    finding_status: models.FindingStatus
    severity: models.Severity
    risk_score: float
    fixed_version: str | None = None
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    component_id: UUID
    component_name: str
    component_version: str | None = None
    vulnerability_id: UUID
    vulnerability_external_id: str
    vulnerability_title: str | None = None
    last_seen_scan_id: UUID | None = None
    updated_at: datetime


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


class JobRetryCandidateOut(BaseModel):
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
    last_error: str | None
    created_at: datetime


class ScannerInventoryOut(BaseModel):
    scan_id: UUID
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    status: models.ScanStatus
    tool: str | None
    tool_version: str | None
    scanner_failure: bool
    scanner_failures: list[Any] = Field(default_factory=list)
    created_at: datetime
    completed_at: datetime | None


class ExceptionReviewOut(BaseModel):
    exception_type: str
    finding_id: UUID
    severity: models.Severity
    status: models.FindingStatus | models.VexStatus
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    component_name: str
    vulnerability_external_id: str
    review_date: datetime | None = None
    expired: bool | None = None
    justification: str | None = None


class StorageCleanupCandidateOut(BaseModel):
    reason: str
    storage_key: str | None
    digest: str | None = None
    scan_id: UUID | None = None
    sbom_id: UUID | None = None
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    created_at: datetime


class OperationalWorkloadOut(BaseModel):
    item: str
    count: int
    status: str
    detail: str


class RepositorySyncOut(BaseModel):
    repository_id: UUID
    repository_owner: str
    repository_name: str
    provider: models.RepositoryProvider
    source_classification: models.SourceClassification
    archived: bool
    fork: bool
    last_synced_at: datetime | None
    latest_sync_job_id: UUID | None = None
    latest_sync_job_status: models.JobStatus | None = None
    latest_sync_job_error: str | None = None
    stale: bool
    reasons: list[str] = Field(default_factory=list)


class ApplicationDetectionOut(BaseModel):
    issue_type: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    application_id: UUID | None = None
    application_name: str | None = None
    application_path: str | None = None
    application_type: models.ApplicationType | None = None
    technology_count: int = 0
    detail: str


class ApplicationInputCoverageOut(BaseModel):
    gap_type: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    application_id: UUID
    application_name: str
    application_path: str
    ecosystem: str | None = None
    technology_count: int
    detected_sources: list[str] = Field(default_factory=list)
    detail: str


class ContainerInputCoverageOut(BaseModel):
    gap_type: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    application_id: UUID
    application_name: str
    application_path: str
    application_type: models.ApplicationType
    latest_scan_id: UUID | None = None
    latest_scan_status: models.ScanStatus | None = None
    has_container_input: bool
    has_container_artifact: bool
    artifact_types: list[str] = Field(default_factory=list)
    detail: str


class ScheduledScanCoverageOut(BaseModel):
    application_id: UUID
    application_name: str
    application_path: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    latest_scheduled_scan_id: UUID | None
    latest_scheduled_scan_status: models.ScanStatus | None
    latest_scheduled_scan_created_at: datetime | None
    latest_scan_id: UUID | None
    latest_scan_status: models.ScanStatus | None
    latest_scan_trigger_type: models.TriggerType | None
    manual_only: bool
    missing_recent_schedule: bool


class FindingResolutionCandidateOut(BaseModel):
    finding_id: UUID
    severity: models.Severity
    status: models.FindingStatus
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    component_name: str
    vulnerability_external_id: str
    last_seen_scan_id: UUID | None
    latest_successful_scan_id: UUID
    latest_successful_scan_created_at: datetime


class BackupReadinessOut(BaseModel):
    check: str
    status: str
    count: int
    detail: str


class NotificationSloOut(BaseModel):
    finding_id: UUID
    severity: models.Severity
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    component_name: str
    vulnerability_external_id: str
    finding_created_at: datetime
    deadline_at: datetime
    notified_at: datetime | None = None
    breached: bool
    status: str


class RemediationPrOut(BaseModel):
    action_id: UUID
    action_type: str
    action_status: str
    finding_id: UUID
    severity: models.Severity
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    provider_id: str | None = None
    branch: str | None = None
    url: str | None = None
    ci_passed: bool | None = None
    created_at: datetime
    updated_at: datetime


class FixableGapOut(BaseModel):
    gap_type: str
    finding_id: UUID
    severity: models.Severity
    risk_score: float
    fixed_version: str
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    component_name: str
    component_version: str | None = None
    vulnerability_external_id: str
    action_id: UUID | None = None
    action_type: str | None = None
    action_status: str | None = None
    updated_at: datetime
    detail: str


class PrCiFailureOut(BaseModel):
    action_id: UUID
    action_type: str
    action_status: str
    finding_id: UUID
    severity: models.Severity
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    provider: str | None = None
    provider_id: str | None = None
    branch: str | None = None
    url: str | None = None
    ci_passed: bool | None = None
    detail: str
    updated_at: datetime


class IssueCreationSloOut(BaseModel):
    finding_id: UUID
    severity: models.Severity
    finding_status: models.FindingStatus
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    component_name: str
    vulnerability_external_id: str
    created_at: datetime
    deadline_at: datetime
    first_evidence_at: datetime | None = None
    evidence_type: str | None = None
    action_id: UUID | None = None
    breached: bool
    detail: str


class AutoResolutionEvidenceOut(BaseModel):
    finding_id: UUID
    severity: models.Severity
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    component_name: str
    vulnerability_external_id: str
    resolved_at: datetime | None = None
    successful_action_id: UUID | None = None
    validation_scan_id: UUID | None = None
    validation_scan_status: models.ScanStatus | None = None
    issue_action_id: UUID | None = None
    close_state: str
    complete: bool
    detail: str


class RemediationBacklogOut(BaseModel):
    action_id: UUID
    action_type: str
    action_status: str
    finding_id: UUID
    severity: models.Severity
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    age_days: int
    reason: str
    detail: str | None = None
    updated_at: datetime


class RemediationRescanOut(BaseModel):
    action_id: UUID
    action_type: str
    action_status: str
    finding_id: UUID
    severity: models.Severity
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    validation_status: str
    validation_scan_id: UUID | None = None
    validation_scan_status: models.ScanStatus | None = None
    latest_rescan_id: UUID | None = None
    latest_rescan_status: models.ScanStatus | None = None
    latest_rescan_created_at: datetime | None = None
    missing_rescan: bool


class WeeklyReviewOut(BaseModel):
    item: str
    status: str
    count: int
    detail: str


class ManualActionOut(BaseModel):
    id: UUID
    actor: str
    role: str
    action: str
    resource_type: str
    resource_id: str | None
    metadata_json: dict[str, Any]
    created_at: datetime
    reason: str


class GovernanceOwnershipOut(BaseModel):
    issue_type: str
    application_id: UUID
    application_name: str
    application_path: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    owner: str | None
    criticality: str
    production: bool
    lifecycle: models.Lifecycle
    support_status: str
    detail: str


class ExposureReviewOut(BaseModel):
    application_id: UUID
    application_name: str
    application_path: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    internet_exposed: bool
    production: bool
    latest_scan_id: UUID | None
    latest_scan_status: models.ScanStatus | None
    latest_scan_created_at: datetime | None
    open_critical_high_count: int
    has_active_source_sbom: bool
    reasons: list[str] = Field(default_factory=list)


class AutoMergeScopeOut(BaseModel):
    application_id: UUID
    application_name: str
    application_path: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    auto_merge_enabled: bool
    production: bool
    criticality: str
    internet_exposed: bool
    recent_validation: bool
    blocked_action_count: int
    reasons: list[str] = Field(default_factory=list)


class DataProtectionOut(BaseModel):
    check: str
    status: str
    configured: bool
    count: int
    detail: str


class RetentionReviewOut(BaseModel):
    item: str
    status: str
    count: int
    detail: str


class ArtifactSbomCoverageOut(BaseModel):
    application_id: UUID
    application_name: str
    application_path: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    has_artifact_sbom: bool
    latest_artifact_sbom_id: UUID | None = None
    latest_artifact_sbom_generated_at: datetime | None = None
    artifact_types: list[str] = Field(default_factory=list)


class LicenseReviewOut(BaseModel):
    issue_type: str
    component_id: UUID
    purl: str
    ecosystem: str | None
    component_name: str
    component_version: str | None
    license: str | None
    application_id: UUID | None = None
    application_name: str | None = None
    repository_id: UUID | None = None
    repository_owner: str | None = None
    repository_name: str | None = None


class SecurityFindingOut(BaseModel):
    finding_type: str
    severity: str | None = None
    title: str
    detail: str | None = None
    scan_id: UUID
    scan_status: models.ScanStatus
    scan_created_at: datetime
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str


class DuplicateReviewOut(BaseModel):
    duplicate_type: str
    key: str
    count: int
    finding_id: UUID | None = None
    action_type: str | None = None
    channel: str | None = None
    subject: str | None = None
    application_id: UUID | None = None
    application_name: str | None = None
    repository_id: UUID | None = None
    repository_owner: str | None = None
    repository_name: str | None = None
    detail: str


class ReopenRiskOut(BaseModel):
    finding_id: UUID
    severity: models.Severity
    status: models.FindingStatus
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    component_name: str
    vulnerability_external_id: str
    resolved_at: datetime | None
    last_seen_scan_id: UUID | None = None
    last_seen_scan_created_at: datetime | None = None
    reason: str


class ScannerVersionOut(BaseModel):
    tool: str | None
    tool_version: str | None
    scan_count: int
    latest_scan_id: UUID
    latest_scan_status: models.ScanStatus
    latest_scan_created_at: datetime
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    missing_version: bool
    stale: bool


class RuntimeEolOut(BaseModel):
    source: str
    source_id: UUID
    issue_type: str
    name: str
    version: str | None = None
    category: str | None = None
    ecosystem: str | None = None
    application_id: UUID | None = None
    application_name: str | None = None
    repository_id: UUID | None = None
    repository_owner: str | None = None
    repository_name: str | None = None
    detail: str


class AuditReviewOut(BaseModel):
    id: UUID
    actor: str
    role: str
    action: str
    resource_type: str
    resource_id: str | None
    reason: str
    metadata_json: dict[str, Any]
    created_at: datetime


class RbacReviewOut(BaseModel):
    check: str
    status: str
    count: int
    detail: str


class RestoreReadinessOut(BaseModel):
    check: str
    status: str
    count: int
    detail: str


class RiskAcceptanceReviewOut(BaseModel):
    source: str
    finding_id: UUID
    severity: models.Severity
    status: models.FindingStatus | models.VexStatus
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    component_name: str
    vulnerability_external_id: str
    review_date: datetime | None = None
    expired: bool | None = None
    approved_by: str | None = None
    justification: str | None = None


class RolloutGapOut(BaseModel):
    issue_type: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    application_id: UUID | None = None
    application_name: str | None = None
    latest_scan_id: UUID | None = None
    latest_scan_status: models.ScanStatus | None = None
    latest_scan_created_at: datetime | None = None
    count: int
    detail: str


class GitHubIntegrationHealthOut(BaseModel):
    check: str
    status: str
    count: int
    detail: str


class WebhookIntakeOut(BaseModel):
    job_id: UUID
    event: str | None = None
    repository: str | None = None
    status: models.JobStatus
    error: str | None = None
    duplicate_candidate: bool
    created_at: datetime


class ScannerFailureOut(BaseModel):
    scan_id: UUID
    tool: str | None = None
    failure_type: str
    error: str
    status: models.ScanStatus
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    created_at: datetime


class DependencyUpdateOut(BaseModel):
    action_id: UUID
    provider: str | None = None
    update_source: str
    action_status: str
    ci_passed: bool | None = None
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    branch: str | None = None
    url: str | None = None
    detail: str


class VulnerabilityEnrichmentCoverageOut(BaseModel):
    gap_type: str
    vulnerability_id: UUID
    source: str
    external_id: str
    severity: models.Severity
    cvss_score: float | None = None
    reference_count: int
    affected_finding_count: int
    has_epss: bool
    has_kev: bool
    has_exploit: bool
    has_raw_data_location: bool
    application_id: UUID | None = None
    application_name: str | None = None
    repository_id: UUID | None = None
    repository_owner: str | None = None
    repository_name: str | None = None
    detail: str


class RiskScoreExplanationOut(BaseModel):
    gap_type: str
    finding_id: UUID
    status: models.FindingStatus
    severity: models.Severity
    risk_score: float
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    criticality: str
    internet_exposed: bool
    production: bool
    fixed_version: str | None = None
    has_kev: bool
    has_epss: bool
    priority_factors: list[str] = Field(default_factory=list)
    detail: str
    updated_at: datetime


class FailureSignalOut(BaseModel):
    signal_type: str
    source: str
    source_id: str
    status: str
    detail: str
    repository_id: UUID | None = None
    repository_owner: str | None = None
    repository_name: str | None = None
    application_id: UUID | None = None
    application_name: str | None = None
    created_at: datetime


class IsolatedSafeguardOut(BaseModel):
    issue_type: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    repository_provider: models.RepositoryProvider
    source_classification: models.SourceClassification
    application_id: UUID
    application_name: str
    latest_scan_id: UUID | None = None
    latest_scan_status: models.ScanStatus | None = None
    active_source_sbom_count: int
    has_artifact_storage: bool
    detail: str


class IsolatedScanHealthOut(BaseModel):
    health_type: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    repository_provider: models.RepositoryProvider
    source_classification: models.SourceClassification
    application_id: UUID
    application_name: str
    latest_scan_id: UUID | None = None
    latest_scan_status: models.ScanStatus | None = None
    latest_scan_created_at: datetime | None = None
    active_source_sbom_count: int
    has_artifact_storage: bool
    detail: str


class SecretReviewOut(BaseModel):
    source: str
    source_id: str
    severity: str | None = None
    title: str
    detail: str | None = None
    application_id: UUID | None = None
    application_name: str | None = None
    repository_id: UUID | None = None
    repository_owner: str | None = None
    repository_name: str | None = None
    created_at: datetime


class WorkerPostureOut(BaseModel):
    check: str
    status: str
    count: int
    detail: str


class ExploitIntelOut(BaseModel):
    finding_id: UUID
    severity: models.Severity
    risk_score: float
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    component_name: str
    vulnerability_external_id: str
    cvss_score: float | None = None
    kev: bool
    epss_signal: bool
    detail: str


class QuarterlyReviewOut(BaseModel):
    item: str
    status: str
    count: int
    detail: str


class RolloutBaselineOut(BaseModel):
    check: str
    status: str
    count: int
    target: int | None = None
    percent: float | None = None
    detail: str


class ApplicationReadinessOut(BaseModel):
    issue_type: str
    application_id: UUID
    application_name: str
    application_path: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    owner: str | None = None
    criticality: str
    lifecycle: models.Lifecycle
    latest_scan_id: UUID | None = None
    latest_scan_status: models.ScanStatus | None = None
    latest_scan_created_at: datetime | None = None
    has_active_source_sbom: bool
    detail: str


class ScanTargetOut(BaseModel):
    check: str
    status: str
    count: int
    target_percent: float | None = None
    actual_percent: float | None = None
    detail: str


class RemediationCoverageOut(BaseModel):
    finding_id: UUID
    severity: models.Severity
    risk_score: float
    fixed_version: str
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    component_name: str
    vulnerability_external_id: str
    has_issue_or_pr: bool
    action_id: UUID | None = None
    action_type: str | None = None
    action_status: str | None = None
    provider: str | None = None
    url: str | None = None
    coverage_percent: float


class DependencyUpdateCoverageOut(BaseModel):
    gap_type: str
    finding_id: UUID
    severity: models.Severity
    status: models.FindingStatus
    risk_score: float
    fixed_version: str
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    component_name: str
    vulnerability_external_id: str
    provider: str | None = None
    update_source: str | None = None
    action_id: UUID | None = None
    action_type: str | None = None
    action_status: str | None = None
    validation_status: str | None = None
    validation_scan_id: UUID | None = None
    age_days: int
    detail: str


class RemediationPriorityQueueOut(BaseModel):
    finding_id: UUID
    severity: models.Severity
    status: models.FindingStatus
    risk_score: float
    priority_rank: int
    priority_reason: str
    sla_breached: bool
    fix_available: bool
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    component_name: str
    vulnerability_external_id: str
    production: bool
    internet_exposed: bool
    has_kev: bool
    has_exploit: bool
    fixed_version: str | None = None
    created_at: datetime


class ResolutionVerificationOut(BaseModel):
    issue_type: str
    finding_id: UUID
    severity: models.Severity
    finding_status: models.FindingStatus
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    action_id: UUID
    action_type: str
    action_status: str
    validation_status: str
    validation_scan_id: UUID | None = None
    validation_scan_status: models.ScanStatus | None = None
    latest_rescan_id: UUID | None = None
    latest_rescan_status: models.ScanStatus | None = None
    close_state: str | None = None
    detail: str


class MonthlyReviewOut(BaseModel):
    item: str
    status: str
    count: int
    detail: str


class ToolchainPostureOut(BaseModel):
    check: str
    status: str
    count: int
    detail: str


class RemediationAgingOut(BaseModel):
    action_id: UUID
    action_type: str
    action_status: str
    finding_id: UUID
    severity: models.Severity
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    age_days: int
    age_bucket: str
    url: str | None = None
    updated_at: datetime


class NotificationDigestReadinessOut(BaseModel):
    issue_type: str
    severity: models.Severity
    finding_id: UUID | None = None
    application_id: UUID | None = None
    application_name: str | None = None
    repository_id: UUID | None = None
    repository_owner: str | None = None
    repository_name: str | None = None
    notification_id: UUID | None = None
    channel: str | None = None
    status: str
    detail: str
    created_at: datetime


class PhaseReadinessOut(BaseModel):
    phase: str
    check: str
    status: str
    count: int
    detail: str


class FindingLifecycleReviewOut(BaseModel):
    issue_type: str
    finding_id: UUID
    severity: models.Severity
    status: models.FindingStatus
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    component_name: str
    vulnerability_external_id: str
    age_days: int
    updated_at: datetime
    detail: str


class VexInvalidationCandidateOut(BaseModel):
    reason: str
    vex_id: UUID
    finding_id: UUID
    status: models.VexStatus
    finding_status: models.FindingStatus
    severity: models.Severity
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    component_name: str
    component_version: str | None = None
    vulnerability_external_id: str
    review_date: datetime
    expired: bool
    detail: str


class RepositoryDriftOut(BaseModel):
    issue_type: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    provider: models.RepositoryProvider
    source_classification: models.SourceClassification
    application_id: UUID | None = None
    application_name: str | None = None
    latest_scan_id: UUID | None = None
    latest_scan_created_at: datetime | None = None
    count: int
    detail: str


class AutoMergePilotReadinessOut(BaseModel):
    action_id: UUID
    action_type: str
    action_status: str
    finding_id: UUID
    severity: models.Severity
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    allowed: bool
    reason: str
    ci_passed: bool
    validation_scan_resolved: bool
    tier_allows: bool
    touches_forbidden_path: bool


class ControlEvidenceOut(BaseModel):
    check: str
    status: str
    count: int
    detail: str


class FindingEvidenceGapOut(BaseModel):
    gap_type: str
    finding_id: UUID
    severity: models.Severity
    status: models.FindingStatus
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    component_name: str
    vulnerability_external_id: str
    detail: str
    updated_at: datetime


class JobBacklogOut(BaseModel):
    id: UUID
    job_type: models.JobType
    status: models.JobStatus
    repository_id: UUID | None = None
    repository_owner: str | None = None
    repository_name: str | None = None
    application_id: UUID | None = None
    application_name: str | None = None
    attempts: int
    max_attempts: int
    run_after: datetime
    locked_by: str | None = None
    age_hours: int
    reason: str
    last_error: str | None = None
    created_at: datetime


class AuditEvidenceGapOut(BaseModel):
    gap_type: str
    resource_type: str
    resource_id: str
    expected_action: str
    actor: str | None = None
    audit_log_id: UUID | None = None
    detail: str
    created_at: datetime


class ScanEvidenceQualityOut(BaseModel):
    gap_type: str
    scan_id: UUID
    status: models.ScanStatus
    tool: str | None = None
    tool_version: str | None = None
    commit_sha: str | None = None
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    detail: str
    created_at: datetime


class RawScanArtifactOut(BaseModel):
    gap_type: str
    scan_id: UUID
    status: models.ScanStatus
    artifact_type: str | None = None
    storage_key: str | None = None
    digest: str | None = None
    size_bytes: int | None = None
    encrypted: bool
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    detail: str
    created_at: datetime


class AutomationGuardrailOut(BaseModel):
    check: str
    status: str
    count: int
    detail: str


class AutoMergePolicyViolationOut(BaseModel):
    violation_type: str
    action_id: UUID
    action_type: str
    action_status: str
    finding_id: UUID
    severity: models.Severity
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    ci_passed: bool | None = None
    validation_status: str | None = None
    auto_merge_allowed: bool | None = None
    detail: str
    updated_at: datetime


class AutoMergeDryRunOut(BaseModel):
    action_id: UUID
    action_type: str
    action_status: str
    finding_id: UUID
    severity: models.Severity
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    decision: str
    mismatch: bool
    auto_merge_allowed: bool | None = None
    policy_reason: str | None = None
    ci_passed: bool | None = None
    validation_status: str | None = None
    detail: str
    updated_at: datetime


class RollbackReadinessOut(BaseModel):
    check: str
    status: str
    count: int
    detail: str


class AutomationSuppressionOut(BaseModel):
    reason: str
    action_id: UUID
    action_type: str
    action_status: str
    finding_id: UUID
    severity: models.Severity
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    duplicate_of: str | None = None
    policy_reason: str | None = None
    detail: str
    updated_at: datetime


class RolloutWaveOut(BaseModel):
    wave: str
    repository_count: int
    application_count: int
    owner_completeness_percent: float
    active_sbom_coverage_percent: float
    fresh_scan_percent: float
    open_critical_high_count: int
    gap_count: int
    detail: str


class MvpTargetReadinessOut(BaseModel):
    issue_type: str
    ready: bool
    repository_id: UUID
    repository_owner: str
    repository_name: str
    application_count: int
    owner_completeness_percent: float
    active_sbom_coverage_percent: float
    latest_scan_created_at: datetime | None = None
    open_critical_high_count: int
    detail: str


class MvpReadinessDrilldownOut(BaseModel):
    repository_id: UUID
    repository_owner: str
    repository_name: str
    ready: bool
    failing_checks: list[str]
    visibility: str | None = None
    source_classification: models.SourceClassification | None = None
    application_count: int
    owner_completeness_percent: float
    active_sbom_coverage_percent: float
    latest_scan_status: models.ScanStatus | None = None
    latest_scan_created_at: datetime | None = None
    open_critical_high_count: int
    detail: str


class KpiEvidenceOut(BaseModel):
    metric: str
    record_type: str
    record_id: str
    included: bool
    status: str
    application_id: UUID | None = None
    application_name: str | None = None
    repository_id: UUID | None = None
    repository_owner: str | None = None
    repository_name: str | None = None
    detail: str


class MvpTargetComplianceOut(BaseModel):
    target: str
    status: str
    current_value: float
    target_value: float
    unit: str
    breached: bool
    detail: str


class EfficiencyTimelineOut(BaseModel):
    finding_id: UUID
    metric: str
    severity: models.Severity
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    first_scan_at: datetime | None = None
    finding_created_at: datetime
    notification_sent_at: datetime | None = None
    first_action_at: datetime | None = None
    resolved_at: datetime | None = None
    duration_hours: float | None = None
    breached: bool
    detail: str


class InitialInventoryOut(BaseModel):
    issue_type: str
    complete: bool
    repository_id: UUID
    repository_owner: str
    repository_name: str
    application_id: UUID | None = None
    application_name: str | None = None
    latest_scan_id: UUID | None = None
    latest_scan_created_at: datetime | None = None
    open_critical_high_count: int
    has_notification_or_action: bool
    has_exception: bool
    detail: str


class RepositoryInventoryGapOut(BaseModel):
    gap_type: str
    repository_id: UUID | None = None
    repository_owner: str | None = None
    repository_name: str | None = None
    provider: models.RepositoryProvider | None = None
    visibility: str | None = None
    source_classification: models.SourceClassification | None = None
    count: int
    target: int | None = None
    detail: str


class DailyScanSloOut(BaseModel):
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    latest_scheduled_scan_id: UUID | None = None
    latest_scheduled_scan_status: models.ScanStatus | None = None
    latest_scheduled_scan_created_at: datetime | None = None
    latest_scan_id: UUID | None = None
    latest_scan_status: models.ScanStatus | None = None
    latest_scan_trigger_type: models.TriggerType | None = None
    manual_only: bool
    breached: bool
    detail: str


class DependencyRelationshipOut(BaseModel):
    gap_type: str
    component_id: UUID
    purl: str
    ecosystem: str | None = None
    component_name: str
    component_version: str | None = None
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    active_sbom_id: UUID
    direct_dependency: bool | None = None
    dependency_scope: str | None = None
    dependency_path: str | None = None
    development_dependency: bool | None = None
    optional_dependency: bool | None = None
    detail: str


class QueuePressureOut(BaseModel):
    job_type: models.JobType
    status: models.JobStatus
    count: int
    stale_count: int
    overdue_count: int
    retry_exhausted_count: int
    oldest_age_hours: int
    detail: str


class SchedulerDriftOut(BaseModel):
    drift_type: str
    job_type: models.JobType | None = None
    application_id: UUID | None = None
    application_name: str | None = None
    repository_id: UUID | None = None
    repository_owner: str | None = None
    repository_name: str | None = None
    latest_job_id: UUID | None = None
    latest_job_status: models.JobStatus | None = None
    latest_job_created_at: datetime | None = None
    count: int
    detail: str


class StoragePressureOut(BaseModel):
    check: str
    status: str
    count: int
    estimated_bytes: int
    detail: str


class RepositorySyncLagOut(BaseModel):
    lag_type: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    provider: models.RepositoryProvider
    last_synced_at: datetime | None = None
    pushed_at: datetime | None = None
    latest_scan_id: UUID | None = None
    latest_scan_created_at: datetime | None = None
    detail: str


class CredentialFailureOut(BaseModel):
    failure_type: str
    source: str
    source_id: str
    status: str
    detail: str
    repository_id: UUID | None = None
    repository_owner: str | None = None
    repository_name: str | None = None
    application_id: UUID | None = None
    application_name: str | None = None
    created_at: datetime


class SecurityScanCoverageOut(BaseModel):
    gap_type: str
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    latest_scan_id: UUID | None = None
    latest_scan_status: models.ScanStatus | None = None
    latest_scan_tool: str | None = None
    latest_scan_created_at: datetime | None = None
    has_scan_evidence: bool
    finding_count: int
    max_severity: str | None = None
    detail: str


class ContainerCoverageOut(BaseModel):
    gap_type: str
    application_id: UUID
    application_name: str
    application_type: models.ApplicationType
    repository_id: UUID
    repository_owner: str
    repository_name: str
    latest_scan_id: UUID | None = None
    latest_scan_status: models.ScanStatus | None = None
    latest_scan_created_at: datetime | None = None
    has_container_artifact: bool
    has_container_sbom: bool
    artifact_types: list[str]
    detail: str


class OperationEvidenceOut(BaseModel):
    evidence_type: str
    status: str
    count: int
    action: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    latest_evidence_at: datetime | None = None
    detail: str


class JobConcurrencyRiskOut(BaseModel):
    risk_type: str
    job_id: UUID
    job_type: models.JobType
    status: models.JobStatus
    repository_id: UUID | None = None
    repository_owner: str | None = None
    repository_name: str | None = None
    application_id: UUID | None = None
    application_name: str | None = None
    duplicate_count: int
    locked_by: str | None = None
    locked_at: datetime | None = None
    attempts: int
    max_attempts: int
    detail: str
    created_at: datetime


class ImportFailureOut(BaseModel):
    failure_type: str
    source: str
    source_id: str
    status: str
    repository_id: UUID | None = None
    repository_owner: str | None = None
    repository_name: str | None = None
    provider: models.RepositoryProvider | None = None
    source_classification: models.SourceClassification | None = None
    application_id: UUID | None = None
    application_name: str | None = None
    error: str | None = None
    created_at: datetime


class ScannerDatabaseFreshnessOut(BaseModel):
    gap_type: str
    scan_id: UUID
    tool: str | None = None
    status: models.ScanStatus
    database_updated_at: datetime | None = None
    database_age_days: int | None = None
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    detail: str
    created_at: datetime


class RepositoryClassificationReviewOut(BaseModel):
    gap_type: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    provider: models.RepositoryProvider
    visibility: str | None = None
    source_classification: models.SourceClassification
    archived: bool
    fork: bool
    application_id: UUID | None = None
    application_name: str | None = None
    detail: str


class GitHubPermissionPostureOut(BaseModel):
    check: str
    status: str
    count: int
    action: str | None = None
    actor: str | None = None
    role: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    created_at: datetime | None = None
    detail: str


class PrStalenessOut(BaseModel):
    staleness_type: str
    action_id: UUID
    action_type: str
    action_status: str
    finding_id: UUID
    severity: models.Severity
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    provider_id: str | None = None
    branch: str | None = None
    url: str | None = None
    ci_passed: bool | None = None
    age_days: int
    detail: str
    updated_at: datetime


class MediumFindingReviewOut(BaseModel):
    review_type: str
    finding_id: UUID
    status: models.FindingStatus
    severity: models.Severity
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    component_name: str
    vulnerability_external_id: str
    has_notification: bool
    has_action: bool
    has_vex: bool
    age_days: int
    detail: str
    updated_at: datetime


class FalsePositiveReviewOut(BaseModel):
    review_type: str
    source: str
    finding_id: UUID
    status: models.FindingStatus
    severity: models.Severity
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    component_name: str
    vulnerability_external_id: str
    vex_id: UUID | None = None
    review_date: datetime | None = None
    expired: bool
    reappeared: bool
    detail: str


class WorkerHardeningOut(BaseModel):
    check: str
    status: str
    count: int
    evidence_type: str | None = None
    detail: str


class StorageEncryptionPostureOut(BaseModel):
    check: str
    status: str
    count: int
    detail: str


class SbomNormalizationQualityOut(BaseModel):
    gap_type: str
    sbom_id: UUID
    component_id: UUID
    purl: str
    ecosystem: str | None = None
    component_name: str
    component_version: str | None = None
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    detail: str
    generated_at: datetime


class VulnerabilityReevaluationCoverageOut(BaseModel):
    gap_type: str
    finding_id: UUID
    status: models.FindingStatus
    severity: models.Severity
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    component_name: str
    component_version: str | None = None
    vulnerability_id: UUID
    vulnerability_external_id: str
    vulnerability_modified_at: datetime | None = None
    latest_scan_id: UUID | None = None
    latest_scan_created_at: datetime | None = None
    last_seen_scan_id: UUID | None = None
    last_seen_scan_created_at: datetime | None = None
    detail: str
    updated_at: datetime


class SecurityPostureOut(BaseModel):
    check: str
    status: str
    count: int
    detail: str


class CredentialExposureOut(BaseModel):
    source: str
    source_id: str
    exposure_type: str
    severity: str
    field: str | None = None
    application_id: UUID | None = None
    application_name: str | None = None
    repository_id: UUID | None = None
    repository_owner: str | None = None
    repository_name: str | None = None
    detail: str
    created_at: datetime


class ObservabilityPostureOut(BaseModel):
    check: str
    status: str
    count: int
    detail: str


class IncidentReadinessOut(BaseModel):
    incident_type: str
    status: str
    source: str
    source_id: str
    application_id: UUID | None = None
    application_name: str | None = None
    repository_id: UUID | None = None
    repository_owner: str | None = None
    repository_name: str | None = None
    has_response_audit: bool
    detail: str
    created_at: datetime


class CompletionReadinessOut(BaseModel):
    check: str
    status: str
    count: int
    target: float | int | None = None
    percent: float | None = None
    detail: str


class E2eEvidenceOut(BaseModel):
    stage: str
    status: str
    finding_id: UUID
    severity: models.Severity
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    evidence_source: str | None = None
    evidence_id: str | None = None
    detail: str
    created_at: datetime


class FailureDrillOut(BaseModel):
    drill_type: str
    status: str
    evidence_source: str | None = None
    evidence_id: str | None = None
    detail: str
    observed_at: datetime | None = None


class RepositoryOnboardingProofOut(BaseModel):
    repository_id: UUID
    repository_owner: str
    repository_name: str
    provider: models.RepositoryProvider
    ready: bool
    visibility: str | None = None
    default_branch: str | None = None
    primary_language: str | None = None
    topic_count: int
    application_count: int
    active_source_sbom_count: int
    latest_scan_status: models.ScanStatus | None = None
    latest_scan_created_at: datetime | None = None
    open_critical_high_count: int
    missing_checks: list[str] = Field(default_factory=list)
    detail: str


class RunbookEvidenceOut(BaseModel):
    cadence: str
    check: str
    status: str
    count: int
    detail: str
    latest_evidence_at: datetime | None = None


class ArtifactProvenanceOut(BaseModel):
    gap_type: str
    source: str
    source_id: str
    artifact_type: str | None = None
    storage_key: str | None = None
    digest: str | None = None
    scan_id: UUID | None = None
    application_id: UUID | None = None
    application_name: str | None = None
    repository_id: UUID | None = None
    repository_owner: str | None = None
    repository_name: str | None = None
    detail: str
    created_at: datetime


class ScanFormatComplianceOut(BaseModel):
    gap_type: str
    scan_id: UUID
    status: models.ScanStatus
    tool: str | None = None
    artifact_type: str | None = None
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    detail: str
    created_at: datetime


class WorkerCleanupOut(BaseModel):
    gap_type: str
    status: str
    job_id: UUID
    job_type: models.JobType
    job_status: models.JobStatus
    repository_id: UUID | None = None
    repository_name: str | None = None
    application_id: UUID | None = None
    application_name: str | None = None
    detail: str
    created_at: datetime


class IdempotencySafetyOut(BaseModel):
    issue_type: str
    source: str
    source_id: str
    status: str
    repository_id: UUID | None = None
    repository_name: str | None = None
    application_id: UUID | None = None
    application_name: str | None = None
    detail: str
    created_at: datetime


class VulnerabilitySourceProvenanceOut(BaseModel):
    gap_type: str
    vulnerability_id: UUID
    source: str
    external_id: str
    severity: models.Severity
    reference_count: int
    affected_finding_count: int
    has_raw_data_location: bool
    published_at: datetime | None = None
    modified_at: datetime | None = None
    detail: str


class JobRetryPostureOut(BaseModel):
    gap_type: str
    job_id: UUID
    job_type: models.JobType
    status: models.JobStatus
    repository_id: UUID | None = None
    repository_owner: str | None = None
    repository_name: str | None = None
    application_id: UUID | None = None
    application_name: str | None = None
    attempts: int
    max_attempts: int
    run_after: datetime
    locked_at: datetime | None = None
    age_hours: int
    detail: str
    created_at: datetime


class ScanFreshnessBucketOut(BaseModel):
    bucket: str
    gap: bool
    application_id: UUID
    application_name: str
    lifecycle: models.Lifecycle
    repository_id: UUID
    repository_owner: str
    repository_name: str
    latest_scan_id: UUID | None = None
    latest_scan_status: models.ScanStatus | None = None
    latest_scan_created_at: datetime | None = None
    age_days: int | None = None
    detail: str


class ProviderSyncEvidenceOut(BaseModel):
    gap_type: str
    action_id: UUID
    action_type: str
    action_status: str
    provider: str | None = None
    provider_id: str | None = None
    url: str | None = None
    finding_id: UUID
    severity: models.Severity
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    detail: str
    updated_at: datetime


class AuditActionCoverageOut(BaseModel):
    gap_type: str
    resource_type: str
    resource_id: str
    expected_action: str
    audit_log_id: UUID | None = None
    actor: str | None = None
    detail: str
    created_at: datetime


class ReviewCalendarOut(BaseModel):
    review_type: str
    status: str
    source: str
    source_id: str
    due_at: datetime
    application_id: UUID | None = None
    application_name: str | None = None
    repository_id: UUID | None = None
    repository_owner: str | None = None
    repository_name: str | None = None
    severity: models.Severity | None = None
    detail: str


class FindingTraceabilityOut(BaseModel):
    gap_type: str
    finding_id: UUID
    severity: models.Severity
    status: models.FindingStatus
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    first_seen_scan_id: UUID | None = None
    last_seen_scan_id: UUID | None = None
    notification_id: UUID | None = None
    remediation_action_id: UUID | None = None
    validation_scan_id: UUID | None = None
    detail: str
    updated_at: datetime


class NotificationRetryPostureOut(BaseModel):
    gap_type: str
    notification_id: UUID
    channel: str
    severity: models.Severity
    status: str
    finding_id: UUID | None = None
    application_id: UUID | None = None
    application_name: str | None = None
    repository_id: UUID | None = None
    repository_owner: str | None = None
    repository_name: str | None = None
    retry_job_id: UUID | None = None
    duplicate_count: int = 0
    detail: str
    created_at: datetime


class ScannerExecutionMatrixOut(BaseModel):
    gap_type: str
    tool: str
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    latest_scan_id: UUID | None = None
    latest_scan_status: models.ScanStatus | None = None
    latest_scan_created_at: datetime | None = None
    tool_version: str | None = None
    detail: str


class RetentionExecutionOut(BaseModel):
    gap_type: str
    reason: str
    source_id: str
    storage_key: str | None = None
    scan_id: UUID | None = None
    sbom_id: UUID | None = None
    application_id: UUID | None = None
    application_name: str | None = None
    repository_id: UUID | None = None
    repository_owner: str | None = None
    repository_name: str | None = None
    audit_log_id: UUID | None = None
    detail: str
    created_at: datetime


class RepositoryWorkflowTraceOut(BaseModel):
    gap_type: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    provider: models.RepositoryProvider
    source_classification: models.SourceClassification
    application_count: int
    active_source_sbom_count: int
    latest_scan_id: UUID | None = None
    latest_scan_status: models.ScanStatus | None = None
    latest_scan_created_at: datetime | None = None
    open_critical_high_count: int
    detail: str


class StateConsistencyOut(BaseModel):
    gap_type: str
    resource_type: str
    resource_id: str
    status: str
    detail: str
    created_at: datetime


class MetadataCompletenessOut(BaseModel):
    gap_type: str
    resource_type: str
    resource_id: str
    application_id: UUID | None = None
    application_name: str | None = None
    repository_id: UUID | None = None
    repository_owner: str | None = None
    repository_name: str | None = None
    detail: str
    created_at: datetime


class OrphanEvidenceOut(BaseModel):
    gap_type: str
    resource_type: str
    resource_id: str
    application_id: UUID | None = None
    application_name: str | None = None
    repository_id: UUID | None = None
    repository_owner: str | None = None
    repository_name: str | None = None
    detail: str
    created_at: datetime


class ScanResultConsistencyOut(BaseModel):
    gap_type: str
    scan_id: UUID
    status: models.ScanStatus
    tool: str | None = None
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    detail: str
    created_at: datetime


class ApplicationMappingQualityOut(BaseModel):
    gap_type: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    provider: models.RepositoryProvider
    source_classification: models.SourceClassification
    application_id: UUID | None = None
    application_name: str | None = None
    application_path: str | None = None
    application_type: models.ApplicationType | None = None
    lifecycle: models.Lifecycle | None = None
    detail: str


class OperationalActionQueueOut(BaseModel):
    action_type: str
    priority: str
    resource_type: str
    resource_id: str
    status: str | None = None
    severity: models.Severity | None = None
    application_id: UUID | None = None
    application_name: str | None = None
    repository_id: UUID | None = None
    repository_owner: str | None = None
    repository_name: str | None = None
    detail: str
    created_at: datetime


class EvidenceFreshnessOut(BaseModel):
    check: str
    cadence: str
    status: str
    count: int
    last_evidence_at: datetime | None = None
    detail: str


class RemediationEvidenceChainOut(BaseModel):
    finding_id: UUID
    severity: models.Severity
    status: models.FindingStatus
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    notification_id: UUID | None = None
    issue_or_pr_action_id: UUID | None = None
    validation_status: str | None = None
    validation_scan_id: UUID | None = None
    validation_scan_status: models.ScanStatus | None = None
    closure_status: str
    missing_stages: list[str]
    detail: str


class OwnerHandoffReadinessOut(BaseModel):
    issue_type: str
    application_id: UUID
    application_name: str
    repository_id: UUID
    repository_owner: str
    repository_name: str
    owner: str | None = None
    lifecycle: models.Lifecycle
    latest_scan_status: models.ScanStatus | None = None
    latest_scan_created_at: datetime | None = None
    open_critical_high_count: int
    detail: str


class RepositoryInventoryAssuranceOut(BaseModel):
    gap_type: str
    repository_id: UUID | None = None
    repository_owner: str | None = None
    repository_name: str | None = None
    provider: models.RepositoryProvider | None = None
    visibility: str | None = None
    default_branch: str | None = None
    primary_language: str | None = None
    last_synced_at: datetime | None = None
    target: int | None = None
    count: int
    detail: str


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
    manual_workload_items: int
    missing_scheduled_scans: int
    notification_slo_breaches: int
    stale_remediation_items: int
    manual_action_count: int
    exposure_review_items: int
    retention_review_items: int
    reopen_risk_items: int
    rbac_review_items: int
    rollout_gap_items: int
    github_integration_issues: int
    failure_signal_items: int
    isolated_safeguard_items: int
    quarterly_review_items: int
    application_readiness_items: int
    remediation_coverage_items: int
    monthly_review_items: int
    phase_readiness_items: int
    control_evidence_items: int
    automation_guardrail_items: int
    rollback_readiness_items: int
    rollout_wave_gap_items: int
    queue_pressure_items: int
    storage_pressure_items: int
    fixable_gap_items: int
    pr_ci_failure_items: int
    isolated_scan_health_items: int
    mvp_target_breaches: int
    repository_inventory_gap_items: int
    daily_scan_slo_breaches: int
    issue_slo_breaches: int
    auto_resolution_gap_items: int
    secret_scan_gap_items: int
    sast_coverage_gap_items: int
    container_coverage_gap_items: int
    backup_evidence_gap_items: int
    restore_evidence_gap_items: int
    job_concurrency_risk_items: int
    import_failure_items: int
    scanner_database_freshness_items: int
    repository_classification_gap_items: int
    github_permission_issue_items: int
    pr_staleness_items: int
    medium_review_items: int
    false_positive_review_items: int
    worker_hardening_items: int
    storage_encryption_items: int
    input_coverage_gap_items: int
    container_input_gap_items: int
    sbom_normalization_gap_items: int
    raw_artifact_gap_items: int
    vulnerability_reevaluation_gap_items: int
    vulnerability_enrichment_gap_items: int
    risk_score_gap_items: int
    dependency_relationship_gap_items: int
    dependency_update_gap_items: int
    remediation_priority_items: int
    secret_management_gap_items: int
    credential_exposure_items: int
    auth_deployment_gap_items: int
    observability_gap_items: int
    incident_readiness_gap_items: int
    completion_readiness_gap_items: int
    e2e_evidence_gap_items: int
    failure_drill_gap_items: int
    repository_onboarding_gap_items: int
    runbook_evidence_gap_items: int
    artifact_provenance_gap_items: int
    scan_format_gap_items: int
    worker_cleanup_gap_items: int
    idempotency_gap_items: int
    vulnerability_provenance_gap_items: int
    job_retry_gap_items: int
    scan_freshness_gap_items: int
    provider_sync_gap_items: int
    audit_action_gap_items: int
    review_calendar_due_items: int
    finding_traceability_gap_items: int
    notification_retry_gap_items: int
    scanner_execution_gap_items: int
    retention_execution_gap_items: int
    workflow_trace_gap_items: int
    state_consistency_gap_items: int
    metadata_completeness_gap_items: int
    orphan_evidence_gap_items: int
    scan_result_consistency_gap_items: int
    application_mapping_gap_items: int
    operational_action_items: int
    evidence_freshness_gap_items: int
    mvp_readiness_gap_items: int
    remediation_evidence_gap_items: int
    owner_handoff_gap_items: int
    repository_inventory_assurance_gap_items: int
