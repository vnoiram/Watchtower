from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.config import Settings, get_settings
from api.app.database import get_db
from api.app.deps import Principal, get_principal
from api.app.routers.audit import audit_action_gap_count
from api.app.routers.auto_merge import automation_guardrail_count
from api.app.routers.artifacts import artifact_provenance_gap_count, container_coverage_count
from api.app.routers.application_detection import application_input_coverage_count, container_input_coverage_count
from api.app.routers.components import dependency_relationship_gap_count
from api.app.routers.governance import exposure_review_count, owner_handoff_gap_count, quarterly_review_count
from api.app.routers.integrations import github_integration_issue_count, github_permission_issue_count
from api.app.routers.isolated_lane import (
    count_isolated_applications,
    isolated_safeguard_count,
    isolated_scan_health_count,
)
from api.app.routers.job_health import job_health_reason
from api.app.routers.jobs import job_concurrency_risk_count, job_retry_gap_count
from api.app.routers.kpis import mvp_target_breach_count, notification_failure_count, scan_failure_rate_percent
from api.app.routers.notifications import notification_retry_gap_count, notification_slo_breach_count
from api.app.routers.findings import critical_high_triage_gap_count, finding_traceability_gap_count, medium_review_count, risk_score_gap_count
from api.app.routers.operations import (
    completion_readiness_gap_count,
    e2e_evidence_gap_count,
    evidence_freshness_gap_count,
    failure_drill_gap_count,
    idempotency_gap_count,
    incident_readiness_gap_count,
    observability_gap_count,
    review_calendar_due_count,
    runbook_evidence_gap_count,
    worker_cleanup_gap_count,
    control_evidence_count,
    backup_evidence_count,
    failure_signal_count,
    manual_action_count,
    manual_workload_count,
    monthly_review_count,
    operational_action_count,
    phase_readiness_count,
    queue_pressure_count,
    rollback_readiness_count,
    restore_evidence_count,
    worker_hardening_count,
)
from api.app.routers.quality import (
    false_positive_review_count,
    metadata_completeness_gap_count,
    orphan_evidence_gap_count,
    reopen_risk_count,
    state_consistency_gap_count,
)
from api.app.routers.remediation import (
    fixable_gap_count,
    auto_resolution_gap_count,
    dependency_update_gap_count,
    issue_slo_breach_count,
    pr_ci_failure_count,
    pr_staleness_count,
    provider_sync_gap_count,
    remediation_evidence_gap_count,
    remediation_coverage_count,
    remediation_priority_count,
    stale_remediation_count,
)
from api.app.routers.rollout import (
    application_readiness_count,
    mvp_readiness_gap_count,
    repository_inventory_assurance_gap_count,
    repository_onboarding_gap_count,
    repository_inventory_gap_count,
    rollout_gap_count,
    rollout_wave_gap_count,
    application_mapping_gap_count,
    workflow_trace_gap_count,
)
from api.app.routers.repository_sync import import_failure_count
from api.app.routers.repositories import repository_classification_gap_count
from api.app.routers.scans import (
    daily_scan_slo_breach_count,
    daily_scan_execution_gap_count,
    raw_scan_artifact_gap_count,
    scan_format_gap_count,
    scan_freshness_gap_count,
    scan_result_consistency_gap_count,
)
from api.app.routers.scanners import scanner_database_freshness_count, scanner_execution_gap_count
from api.app.routers.scheduled_scan_coverage import missing_scheduled_scan_count
from api.app.routers.security import (
    auth_deployment_gap_count,
    credential_exposure_count,
    rbac_review_count,
    sast_coverage_count,
    secret_management_gap_count,
    secret_scan_coverage_count,
)
from api.app.routers.sla import count_sla_breached_findings
from api.app.routers.sboms import sbom_normalization_quality_count
from api.app.routers.storage import retention_execution_gap_count, retention_review_count, storage_encryption_count, storage_pressure_count
from api.app.routers.vulnerabilities import (
    vulnerability_enrichment_gap_count,
    vulnerability_provenance_gap_count,
    vulnerability_reevaluation_gap_count,
)

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary", response_model=schemas.DashboardSummary)
def dashboard_summary(
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _: Principal = Depends(get_principal),
):
    if not isinstance(settings, Settings):
        settings = get_settings()
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    repositories = db.scalar(select(func.count()).select_from(models.Repository)) or 0
    applications = db.scalar(select(func.count()).select_from(models.Application)) or 0
    open_critical = db.scalar(select(func.count()).select_from(models.Finding).where(models.Finding.status == models.FindingStatus.open, models.Finding.severity == models.Severity.critical)) or 0
    open_high = db.scalar(select(func.count()).select_from(models.Finding).where(models.Finding.status == models.FindingStatus.open, models.Finding.severity == models.Severity.high)) or 0
    failed_jobs = db.scalar(select(func.count()).select_from(models.Job).where(models.Job.status == models.JobStatus.failed)) or 0
    expired_vex = db.scalar(select(func.count()).select_from(models.VexStatement).where(models.VexStatement.review_date < datetime.now(timezone.utc))) or 0
    stale_scans = db.scalar(select(func.count()).select_from(models.Application).where(~models.Application.scans.any(models.Scan.created_at >= cutoff))) or 0
    missing_active_sbom = (
        db.scalar(
            select(func.count()).select_from(models.Application).where(
                ~models.Application.id.in_(
                    select(models.Sbom.application_id).where(
                        models.Sbom.active.is_(True),
                        models.Sbom.sbom_kind == "source",
                    )
                )
            )
        )
        or 0
    )
    sbom_coverage_percent = (
        round(((applications - missing_active_sbom) / applications) * 100, 1) if applications else 0.0
    )
    now = datetime.now(timezone.utc)
    unhealthy_jobs = sum(1 for job in db.execute(select(models.Job)).scalars() if job_health_reason(job, now))
    sla_breached_findings = count_sla_breached_findings(db, now)
    isolated_applications = count_isolated_applications(db)
    scan_failure_rate = scan_failure_rate_percent(db)
    notification_failures = notification_failure_count(db)
    manual_workload_items = manual_workload_count(db)
    missing_scheduled_scans = missing_scheduled_scan_count(db)
    notification_slo_breaches = notification_slo_breach_count(db)
    stale_remediation_items = stale_remediation_count(db)
    manual_actions = manual_action_count(db)
    exposure_items = exposure_review_count(db)
    retention_items = retention_review_count(db)
    reopen_risk_items = reopen_risk_count(db)
    rbac_review_items = rbac_review_count(db, settings)
    rollout_gap_items = rollout_gap_count(db)
    rollout_wave_gap_items = rollout_wave_gap_count(db)
    github_integration_issues = github_integration_issue_count(db, settings)
    failure_signal_items = failure_signal_count(db)
    isolated_safeguard_items = isolated_safeguard_count(db)
    quarterly_review_items = quarterly_review_count(db)
    application_readiness_items = application_readiness_count(db)
    remediation_coverage_items = remediation_coverage_count(db)
    monthly_review_items = monthly_review_count(db)
    phase_readiness_items = phase_readiness_count(db)
    control_evidence_items = control_evidence_count(db)
    automation_guardrail_items = automation_guardrail_count(db)
    rollback_readiness_items = rollback_readiness_count(db)
    queue_pressure_items = queue_pressure_count(db)
    storage_pressure_items = storage_pressure_count(db)
    fixable_gap_items = fixable_gap_count(db)
    pr_ci_failure_items = pr_ci_failure_count(db)
    isolated_scan_health_items = isolated_scan_health_count(db)
    mvp_target_breaches = mvp_target_breach_count(db)
    repository_inventory_gap_items = repository_inventory_gap_count(db)
    daily_scan_slo_breaches = daily_scan_slo_breach_count(db)
    issue_slo_breaches = issue_slo_breach_count(db)
    auto_resolution_gap_items = auto_resolution_gap_count(db)
    secret_scan_gap_items = secret_scan_coverage_count(db)
    sast_coverage_gap_items = sast_coverage_count(db)
    container_coverage_gap_items = container_coverage_count(db)
    backup_evidence_gap_items = backup_evidence_count(db, settings)
    restore_evidence_gap_items = restore_evidence_count(db, settings)
    job_concurrency_risk_items = job_concurrency_risk_count(db)
    import_failure_items = import_failure_count(db)
    scanner_database_freshness_items = scanner_database_freshness_count(db)
    repository_classification_gap_items = repository_classification_gap_count(db)
    github_permission_issue_items = github_permission_issue_count(db, settings)
    pr_staleness_items = pr_staleness_count(db)
    medium_review_items = medium_review_count(db)
    false_positive_review_items = false_positive_review_count(db)
    worker_hardening_items = worker_hardening_count(db, settings)
    storage_encryption_items = storage_encryption_count(db, settings)
    input_coverage_gap_items = application_input_coverage_count(db)
    container_input_gap_items = container_input_coverage_count(db)
    sbom_normalization_gap_items = sbom_normalization_quality_count(db)
    raw_artifact_gap_items = raw_scan_artifact_gap_count(db)
    vulnerability_reevaluation_gap_items = vulnerability_reevaluation_gap_count(db)
    vulnerability_enrichment_gap_items = vulnerability_enrichment_gap_count(db)
    risk_score_gap_items = risk_score_gap_count(db)
    dependency_relationship_gap_items = dependency_relationship_gap_count(db)
    dependency_update_gap_items = dependency_update_gap_count(db)
    remediation_priority_items = remediation_priority_count(db)
    secret_management_gap_items = secret_management_gap_count(db, settings)
    credential_exposure_items = credential_exposure_count(db)
    auth_deployment_gap_items = auth_deployment_gap_count(db, settings)
    observability_gap_items = observability_gap_count(db)
    incident_readiness_gap_items = incident_readiness_gap_count(db)
    completion_readiness_gap_items = completion_readiness_gap_count(db, settings)
    e2e_evidence_gap_items = e2e_evidence_gap_count(db)
    failure_drill_gap_items = failure_drill_gap_count(db)
    repository_onboarding_gap_items = repository_onboarding_gap_count(db)
    runbook_evidence_gap_items = runbook_evidence_gap_count(db)
    artifact_provenance_gap_items = artifact_provenance_gap_count(db)
    scan_format_gap_items = scan_format_gap_count(db)
    worker_cleanup_gap_items = worker_cleanup_gap_count(db)
    idempotency_gap_items = idempotency_gap_count(db)
    vulnerability_provenance_gap_items = vulnerability_provenance_gap_count(db)
    job_retry_gap_items = job_retry_gap_count(db)
    scan_freshness_gap_items = scan_freshness_gap_count(db)
    provider_sync_gap_items = provider_sync_gap_count(db)
    audit_action_gap_items = audit_action_gap_count(db)
    review_calendar_due_items = review_calendar_due_count(db)
    finding_traceability_gap_items = finding_traceability_gap_count(db)
    notification_retry_gap_items = notification_retry_gap_count(db)
    scanner_execution_gap_items = scanner_execution_gap_count(db)
    retention_execution_gap_items = retention_execution_gap_count(db)
    workflow_trace_gap_items = workflow_trace_gap_count(db)
    state_consistency_gap_items = state_consistency_gap_count(db)
    metadata_completeness_gap_items = metadata_completeness_gap_count(db)
    orphan_evidence_gap_items = orphan_evidence_gap_count(db)
    scan_result_consistency_gap_items = scan_result_consistency_gap_count(db)
    application_mapping_gap_items = application_mapping_gap_count(db)
    operational_action_items = operational_action_count(db)
    evidence_freshness_gap_items = evidence_freshness_gap_count(db)
    mvp_readiness_gap_items = mvp_readiness_gap_count(db)
    remediation_evidence_gap_items = remediation_evidence_gap_count(db)
    owner_handoff_gap_items = owner_handoff_gap_count(db)
    repository_inventory_assurance_gap_items = repository_inventory_assurance_gap_count(db)
    daily_scan_execution_gap_items = daily_scan_execution_gap_count(db)
    critical_high_triage_gap_items = critical_high_triage_gap_count(db)
    return schemas.DashboardSummary(
        repositories=repositories,
        applications=applications,
        open_critical=open_critical,
        open_high=open_high,
        stale_scans=stale_scans,
        failed_jobs=failed_jobs,
        expired_vex=expired_vex,
        sbom_coverage_percent=sbom_coverage_percent,
        missing_active_sbom=missing_active_sbom,
        unhealthy_jobs=unhealthy_jobs,
        sla_breached_findings=sla_breached_findings,
        isolated_applications=isolated_applications,
        scan_failure_rate_percent=scan_failure_rate,
        notification_failure_count=notification_failures,
        manual_workload_items=manual_workload_items,
        missing_scheduled_scans=missing_scheduled_scans,
        notification_slo_breaches=notification_slo_breaches,
        stale_remediation_items=stale_remediation_items,
        manual_action_count=manual_actions,
        exposure_review_items=exposure_items,
        retention_review_items=retention_items,
        reopen_risk_items=reopen_risk_items,
        rbac_review_items=rbac_review_items,
        rollout_gap_items=rollout_gap_items,
        rollout_wave_gap_items=rollout_wave_gap_items,
        github_integration_issues=github_integration_issues,
        failure_signal_items=failure_signal_items,
        isolated_safeguard_items=isolated_safeguard_items,
        quarterly_review_items=quarterly_review_items,
        application_readiness_items=application_readiness_items,
        remediation_coverage_items=remediation_coverage_items,
        monthly_review_items=monthly_review_items,
        phase_readiness_items=phase_readiness_items,
        control_evidence_items=control_evidence_items,
        automation_guardrail_items=automation_guardrail_items,
        rollback_readiness_items=rollback_readiness_items,
        queue_pressure_items=queue_pressure_items,
        storage_pressure_items=storage_pressure_items,
        fixable_gap_items=fixable_gap_items,
        pr_ci_failure_items=pr_ci_failure_items,
        isolated_scan_health_items=isolated_scan_health_items,
        mvp_target_breaches=mvp_target_breaches,
        repository_inventory_gap_items=repository_inventory_gap_items,
        daily_scan_slo_breaches=daily_scan_slo_breaches,
        issue_slo_breaches=issue_slo_breaches,
        auto_resolution_gap_items=auto_resolution_gap_items,
        secret_scan_gap_items=secret_scan_gap_items,
        sast_coverage_gap_items=sast_coverage_gap_items,
        container_coverage_gap_items=container_coverage_gap_items,
        backup_evidence_gap_items=backup_evidence_gap_items,
        restore_evidence_gap_items=restore_evidence_gap_items,
        job_concurrency_risk_items=job_concurrency_risk_items,
        import_failure_items=import_failure_items,
        scanner_database_freshness_items=scanner_database_freshness_items,
        repository_classification_gap_items=repository_classification_gap_items,
        github_permission_issue_items=github_permission_issue_items,
        pr_staleness_items=pr_staleness_items,
        medium_review_items=medium_review_items,
        false_positive_review_items=false_positive_review_items,
        worker_hardening_items=worker_hardening_items,
        storage_encryption_items=storage_encryption_items,
        input_coverage_gap_items=input_coverage_gap_items,
        container_input_gap_items=container_input_gap_items,
        sbom_normalization_gap_items=sbom_normalization_gap_items,
        raw_artifact_gap_items=raw_artifact_gap_items,
        vulnerability_reevaluation_gap_items=vulnerability_reevaluation_gap_items,
        vulnerability_enrichment_gap_items=vulnerability_enrichment_gap_items,
        risk_score_gap_items=risk_score_gap_items,
        dependency_relationship_gap_items=dependency_relationship_gap_items,
        dependency_update_gap_items=dependency_update_gap_items,
        remediation_priority_items=remediation_priority_items,
        secret_management_gap_items=secret_management_gap_items,
        credential_exposure_items=credential_exposure_items,
        auth_deployment_gap_items=auth_deployment_gap_items,
        observability_gap_items=observability_gap_items,
        incident_readiness_gap_items=incident_readiness_gap_items,
        completion_readiness_gap_items=completion_readiness_gap_items,
        e2e_evidence_gap_items=e2e_evidence_gap_items,
        failure_drill_gap_items=failure_drill_gap_items,
        repository_onboarding_gap_items=repository_onboarding_gap_items,
        runbook_evidence_gap_items=runbook_evidence_gap_items,
        artifact_provenance_gap_items=artifact_provenance_gap_items,
        scan_format_gap_items=scan_format_gap_items,
        worker_cleanup_gap_items=worker_cleanup_gap_items,
        idempotency_gap_items=idempotency_gap_items,
        vulnerability_provenance_gap_items=vulnerability_provenance_gap_items,
        job_retry_gap_items=job_retry_gap_items,
        scan_freshness_gap_items=scan_freshness_gap_items,
        provider_sync_gap_items=provider_sync_gap_items,
        audit_action_gap_items=audit_action_gap_items,
        review_calendar_due_items=review_calendar_due_items,
        finding_traceability_gap_items=finding_traceability_gap_items,
        notification_retry_gap_items=notification_retry_gap_items,
        scanner_execution_gap_items=scanner_execution_gap_items,
        retention_execution_gap_items=retention_execution_gap_items,
        workflow_trace_gap_items=workflow_trace_gap_items,
        state_consistency_gap_items=state_consistency_gap_items,
        metadata_completeness_gap_items=metadata_completeness_gap_items,
        orphan_evidence_gap_items=orphan_evidence_gap_items,
        scan_result_consistency_gap_items=scan_result_consistency_gap_items,
        application_mapping_gap_items=application_mapping_gap_items,
        operational_action_items=operational_action_items,
        evidence_freshness_gap_items=evidence_freshness_gap_items,
        mvp_readiness_gap_items=mvp_readiness_gap_items,
        remediation_evidence_gap_items=remediation_evidence_gap_items,
        owner_handoff_gap_items=owner_handoff_gap_items,
        repository_inventory_assurance_gap_items=repository_inventory_assurance_gap_items,
        daily_scan_execution_gap_items=daily_scan_execution_gap_items,
        critical_high_triage_gap_items=critical_high_triage_gap_items,
    )
