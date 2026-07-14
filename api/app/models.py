import enum
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from api.app.database import Base


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


class RepositoryProvider(str, enum.Enum):
    github = "github"
    manual = "manual"
    local = "local"
    isolated = "isolated"


class SourceClassification(str, enum.Enum):
    public = "public"
    private = "private"
    restricted = "restricted"
    isolated = "isolated"


class ApplicationType(str, enum.Enum):
    web = "web"
    api = "api"
    batch = "batch"
    cli = "cli"
    browser_extension = "browser-extension"
    desktop = "desktop"
    library = "library"
    container = "container"
    serverless = "serverless"
    security_research = "security-research"
    unknown = "unknown"


class Lifecycle(str, enum.Enum):
    experimental = "experimental"
    active = "active"
    maintenance = "maintenance"
    deprecated = "deprecated"
    archived = "archived"
    research = "research"


class JobStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    succeeded = "succeeded"
    failed = "failed"
    cancelled = "cancelled"
    timed_out = "timed_out"


class JobType(str, enum.Enum):
    repository_sync = "repository-sync"
    scan = "scan"
    remediation_validation = "remediation-validation"
    issue_create = "issue-create"
    notification = "notification"
    ai_fix = "ai-fix"


class ScanStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    succeeded = "succeeded"
    partially_succeeded = "partially_succeeded"
    failed = "failed"
    cancelled = "cancelled"
    timed_out = "timed_out"


class TriggerType(str, enum.Enum):
    initial_import = "initial-import"
    pull_request = "pull-request"
    push = "push"
    release = "release"
    schedule = "schedule"
    advisory_update = "advisory-update"
    manual = "manual"
    remediation_validation = "remediation-validation"


class Severity(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"
    unknown = "unknown"


class FindingStatus(str, enum.Enum):
    open = "open"
    triaged = "triaged"
    in_progress = "in_progress"
    resolved = "resolved"
    accepted_risk = "accepted_risk"
    false_positive = "false_positive"


class VexStatus(str, enum.Enum):
    not_affected = "not_affected"
    affected = "affected"
    fixed = "fixed"
    under_investigation = "under_investigation"


class Repository(Base):
    __tablename__ = "repositories"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    provider: Mapped[RepositoryProvider] = mapped_column(Enum(RepositoryProvider), index=True)
    provider_repository_id: Mapped[str | None] = mapped_column(String(255), index=True)
    owner: Mapped[str] = mapped_column(String(255), index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    url: Mapped[str | None] = mapped_column(Text)
    local_path: Mapped[str | None] = mapped_column(Text)
    visibility: Mapped[str | None] = mapped_column(String(50))
    default_branch: Mapped[str | None] = mapped_column(String(255))
    archived: Mapped[bool] = mapped_column(Boolean, default=False)
    fork: Mapped[bool] = mapped_column(Boolean, default=False)
    topics: Mapped[list[str]] = mapped_column(JSON, default=list)
    primary_language: Mapped[str | None] = mapped_column(String(100))
    source_classification: Mapped[SourceClassification] = mapped_column(Enum(SourceClassification), index=True)
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    pushed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)

    applications: Mapped[list["Application"]] = relationship(back_populates="repository")

    __table_args__ = (
        UniqueConstraint("provider", "provider_repository_id", name="uq_repository_provider_id"),
        UniqueConstraint("provider", "owner", "name", name="uq_repository_provider_owner_name"),
    )


class Application(Base):
    __tablename__ = "applications"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    repository_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("repositories.id"), index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    path: Mapped[str] = mapped_column(String(1024), default=".")
    application_type: Mapped[ApplicationType] = mapped_column(Enum(ApplicationType), default=ApplicationType.unknown)
    lifecycle: Mapped[Lifecycle] = mapped_column(Enum(Lifecycle), default=Lifecycle.experimental)
    criticality: Mapped[str] = mapped_column(String(50), default="medium")
    internet_exposed: Mapped[bool] = mapped_column(Boolean, default=False)
    production: Mapped[bool] = mapped_column(Boolean, default=False)
    auto_fix_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    auto_merge_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    owner: Mapped[str | None] = mapped_column(String(255))
    support_status: Mapped[str] = mapped_column(String(50), default="supported")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)

    repository: Mapped[Repository] = relationship(back_populates="applications")
    scans: Mapped[list["Scan"]] = relationship(back_populates="application")
    findings: Mapped[list["Finding"]] = relationship(back_populates="application")

    __table_args__ = (UniqueConstraint("repository_id", "path", name="uq_application_repository_path"),)


class Technology(Base):
    __tablename__ = "technologies"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    application_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("applications.id"), index=True)
    category: Mapped[str] = mapped_column(String(100), index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    version: Mapped[str | None] = mapped_column(String(255))
    detection_source: Mapped[str] = mapped_column(String(255))
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class Job(Base):
    __tablename__ = "jobs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    job_type: Mapped[JobType] = mapped_column(Enum(JobType), index=True)
    status: Mapped[JobStatus] = mapped_column(Enum(JobStatus), default=JobStatus.queued, index=True)
    repository_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("repositories.id"), index=True)
    application_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("applications.id"), index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, default=3)
    locked_by: Mapped[str | None] = mapped_column(String(255))
    locked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    run_after: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)

    __table_args__ = (Index("ix_jobs_queue", "status", "run_after", "created_at"),)


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    application_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("applications.id"), index=True)
    scan_type: Mapped[str] = mapped_column(String(100), default="source")
    trigger_type: Mapped[TriggerType] = mapped_column(Enum(TriggerType), default=TriggerType.manual)
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus), default=ScanStatus.queued, index=True)
    commit_sha: Mapped[str | None] = mapped_column(String(64), index=True)
    branch: Mapped[str | None] = mapped_column(String(255))
    tool: Mapped[str | None] = mapped_column(String(100))
    tool_version: Mapped[str | None] = mapped_column(String(100))
    result_summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    error_message: Mapped[str | None] = mapped_column(Text)
    retry_count: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, index=True)

    application: Mapped[Application] = relationship(back_populates="scans")


class Sbom(Base):
    __tablename__ = "sboms"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    application_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("applications.id"), index=True)
    scan_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("scans.id"), index=True)
    sbom_kind: Mapped[str] = mapped_column(String(50), default="source")
    format: Mapped[str] = mapped_column(String(100), default="cyclonedx-json")
    specification_version: Mapped[str | None] = mapped_column(String(50))
    commit_sha: Mapped[str | None] = mapped_column(String(64))
    artifact_digest: Mapped[str | None] = mapped_column(String(128))
    sbom_digest: Mapped[str] = mapped_column(String(128), index=True)
    storage_key: Mapped[str] = mapped_column(Text)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)


class Component(Base):
    __tablename__ = "components"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    purl: Mapped[str] = mapped_column(Text, unique=True, index=True)
    ecosystem: Mapped[str | None] = mapped_column(String(100), index=True)
    namespace: Mapped[str | None] = mapped_column(String(255))
    name: Mapped[str] = mapped_column(String(255), index=True)
    version: Mapped[str | None] = mapped_column(String(255), index=True)
    supplier: Mapped[str | None] = mapped_column(String(255))
    license: Mapped[str | None] = mapped_column(String(255))
    cpe: Mapped[str | None] = mapped_column(Text)
    hash: Mapped[str | None] = mapped_column(String(128))


class SbomComponent(Base):
    __tablename__ = "sbom_components"

    sbom_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("sboms.id"), primary_key=True)
    component_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("components.id"), primary_key=True)


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source: Mapped[str] = mapped_column(String(100), index=True)
    external_id: Mapped[str] = mapped_column(String(255), index=True)
    title: Mapped[str | None] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), default=Severity.unknown, index=True)
    cvss_score: Mapped[float | None] = mapped_column(Float)
    references: Mapped[list[str]] = mapped_column(JSON, default=list)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (UniqueConstraint("source", "external_id", name="uq_vulnerability_source_external_id"),)


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    application_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("applications.id"), index=True)
    component_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("components.id"), index=True)
    vulnerability_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("vulnerabilities.id"), index=True)
    status: Mapped[FindingStatus] = mapped_column(Enum(FindingStatus), default=FindingStatus.open, index=True)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), default=Severity.unknown, index=True)
    first_seen_scan_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("scans.id"))
    last_seen_scan_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("scans.id"))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    fixed_version: Mapped[str | None] = mapped_column(String(255))
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)

    application: Mapped[Application] = relationship(back_populates="findings")

    __table_args__ = (
        UniqueConstraint("application_id", "component_id", "vulnerability_id", name="uq_finding_identity"),
    )


class RemediationAction(Base):
    __tablename__ = "remediation_actions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    finding_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("findings.id"), index=True)
    action_type: Mapped[str] = mapped_column(String(100), index=True)
    status: Mapped[str] = mapped_column(String(100), index=True)
    provider: Mapped[str | None] = mapped_column(String(100))
    provider_id: Mapped[str | None] = mapped_column(String(255))
    url: Mapped[str | None] = mapped_column(Text)
    branch: Mapped[str | None] = mapped_column(String(255))
    fixed_version: Mapped[str | None] = mapped_column(String(255))
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)


class VexStatement(Base):
    __tablename__ = "vex_statements"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    finding_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("findings.id"), index=True)
    status: Mapped[VexStatus] = mapped_column(Enum(VexStatus), index=True)
    justification: Mapped[str] = mapped_column(Text)
    impact_statement: Mapped[str | None] = mapped_column(Text)
    approved_by: Mapped[str] = mapped_column(String(255))
    review_date: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)


class Notification(Base):
    __tablename__ = "notifications"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    channel: Mapped[str] = mapped_column(String(100), index=True)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), default=Severity.unknown)
    subject: Mapped[str] = mapped_column(Text)
    body: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(100), default="queued", index=True)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    actor: Mapped[str] = mapped_column(String(255), index=True)
    role: Mapped[str] = mapped_column(String(50), index=True)
    action: Mapped[str] = mapped_column(String(255), index=True)
    resource_type: Mapped[str] = mapped_column(String(100), index=True)
    resource_id: Mapped[str | None] = mapped_column(String(255))
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, index=True)

