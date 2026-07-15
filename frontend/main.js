const apiBase = "http://localhost:8000/v1";
const tokenInput = document.querySelector("#token");
const metrics = document.querySelector("#metrics");
const findings = document.querySelector("#findings");
const applications = document.querySelector("#applications");
const technologies = document.querySelector("#technologies");
const sboms = document.querySelector("#sboms");
const components = document.querySelector("#components");
const componentUsage = document.querySelector("#component-usage");
const vulnerabilities = document.querySelector("#vulnerabilities");
const vulnerabilityImpact = document.querySelector("#vulnerability-impact");
const remediationActions = document.querySelector("#remediation-actions");
const vexReviews = document.querySelector("#vex-reviews");
const scanHealth = document.querySelector("#scan-health");
const sbomCoverage = document.querySelector("#sbom-coverage");
const notifications = document.querySelector("#notifications");
const maintenanceCandidates = document.querySelector("#maintenance-candidates");
const remediationCandidates = document.querySelector("#remediation-candidates");
const githubIssueActions = document.querySelector("#github-issue-actions");
const remediationValidations = document.querySelector("#remediation-validations");
const issueClosures = document.querySelector("#issue-closures");
const jobHealth = document.querySelector("#job-health");
const scanArtifacts = document.querySelector("#scan-artifacts");
const aiFixActions = document.querySelector("#ai-fix-actions");
const aiFixCandidates = document.querySelector("#ai-fix-candidates");
const autoMergeEligibility = document.querySelector("#auto-merge-eligibility");
const isolatedLane = document.querySelector("#isolated-lane");
const slaFindings = document.querySelector("#sla-findings");
const auditLogs = document.querySelector("#audit-logs");
const operationsReadiness = document.querySelector("#operations-readiness");
const dailyOperations = document.querySelector("#daily-operations");
const kpiSummary = document.querySelector("#kpi-summary");
const mvpTargetCompliance = document.querySelector("#mvp-target-compliance");
const repositoryRollout = document.querySelector("#repository-rollout");
const repositoryInventoryGaps = document.querySelector("#repository-inventory-gaps");
const retryCandidates = document.querySelector("#retry-candidates");
const scannerInventory = document.querySelector("#scanner-inventory");
const exceptionReview = document.querySelector("#exception-review");
const storageCleanup = document.querySelector("#storage-cleanup");
const operationalWorkload = document.querySelector("#operational-workload");
const repositorySync = document.querySelector("#repository-sync");
const applicationDetection = document.querySelector("#application-detection");
const scheduledScanCoverage = document.querySelector("#scheduled-scan-coverage");
const dailyScanSlo = document.querySelector("#daily-scan-slo");
const resolutionCandidates = document.querySelector("#resolution-candidates");
const backupReadiness = document.querySelector("#backup-readiness");
const notificationSlo = document.querySelector("#notification-slo");
const remediationPrs = document.querySelector("#remediation-prs");
const remediationBacklog = document.querySelector("#remediation-backlog");
const remediationRescans = document.querySelector("#remediation-rescans");
const weeklyReview = document.querySelector("#weekly-review");
const efficiencyKpis = document.querySelector("#efficiency-kpis");
const manualActions = document.querySelector("#manual-actions");
const ownershipReview = document.querySelector("#ownership-review");
const exposureReview = document.querySelector("#exposure-review");
const autoMergeScope = document.querySelector("#auto-merge-scope");
const dataProtection = document.querySelector("#data-protection");
const retentionReview = document.querySelector("#retention-review");
const artifactSbomCoverage = document.querySelector("#artifact-sbom-coverage");
const licenseReview = document.querySelector("#license-review");
const securityFindings = document.querySelector("#security-findings");
const duplicateReview = document.querySelector("#duplicate-review");
const reopenRisk = document.querySelector("#reopen-risk");
const qualityKpis = document.querySelector("#quality-kpis");
const scannerVersions = document.querySelector("#scanner-versions");
const runtimeEol = document.querySelector("#runtime-eol");
const auditReview = document.querySelector("#audit-review");
const rbacReview = document.querySelector("#rbac-review");
const restoreReadiness = document.querySelector("#restore-readiness");
const riskAcceptance = document.querySelector("#risk-acceptance");
const rolloutGaps = document.querySelector("#rollout-gaps");
const githubHealth = document.querySelector("#github-health");
const webhookIntake = document.querySelector("#webhook-intake");
const scannerFailures = document.querySelector("#scanner-failures");
const dependencyUpdates = document.querySelector("#dependency-updates");
const failureSignals = document.querySelector("#failure-signals");
const isolatedSafeguards = document.querySelector("#isolated-safeguards");
const isolatedScanHealth = document.querySelector("#isolated-scan-health");
const secretsReview = document.querySelector("#secrets-review");
const workerPosture = document.querySelector("#worker-posture");
const exploitIntel = document.querySelector("#exploit-intel");
const quarterlyReview = document.querySelector("#quarterly-review");
const rolloutBaseline = document.querySelector("#rollout-baseline");
const applicationReadiness = document.querySelector("#application-readiness");
const scanTargets = document.querySelector("#scan-targets");
const remediationCoverage = document.querySelector("#remediation-coverage");
const fixableGaps = document.querySelector("#fixable-gaps");
const prCiFailures = document.querySelector("#pr-ci-failures");
const issueCreationSlo = document.querySelector("#issue-creation-slo");
const autoResolutionEvidence = document.querySelector("#auto-resolution-evidence");
const resolutionVerification = document.querySelector("#resolution-verification");
const monthlyReview = document.querySelector("#monthly-review");
const operationalLoadKpis = document.querySelector("#operational-load-kpis");
const remediationAging = document.querySelector("#remediation-aging");
const toolchainPosture = document.querySelector("#toolchain-posture");
const notificationDigest = document.querySelector("#notification-digest");
const phaseReadiness = document.querySelector("#phase-readiness");
const findingLifecycle = document.querySelector("#finding-lifecycle");
const vexInvalidation = document.querySelector("#vex-invalidation");
const repositoryDrift = document.querySelector("#repository-drift");
const autoMergePilot = document.querySelector("#auto-merge-pilot");
const controlEvidence = document.querySelector("#control-evidence");
const findingEvidenceGaps = document.querySelector("#finding-evidence-gaps");
const jobBacklog = document.querySelector("#job-backlog");
const auditEvidenceGaps = document.querySelector("#audit-evidence-gaps");
const scanEvidenceQuality = document.querySelector("#scan-evidence-quality");
const automationGuardrails = document.querySelector("#automation-guardrails");
const policyViolations = document.querySelector("#policy-violations");
const dryRunDecisions = document.querySelector("#dry-run-decisions");
const rollbackReadiness = document.querySelector("#rollback-readiness");
const automationSuppressions = document.querySelector("#automation-suppressions");
const rolloutWaves = document.querySelector("#rollout-waves");
const mvpTargets = document.querySelector("#mvp-targets");
const kpiEvidence = document.querySelector("#kpi-evidence");
const efficiencyTimeline = document.querySelector("#efficiency-timeline");
const initialInventory = document.querySelector("#initial-inventory");
const queuePressure = document.querySelector("#queue-pressure");
const schedulerDrift = document.querySelector("#scheduler-drift");
const storagePressure = document.querySelector("#storage-pressure");
const githubSyncLag = document.querySelector("#github-sync-lag");
const credentialFailures = document.querySelector("#credential-failures");

const severityRank = { critical: 0, high: 1 };

function authHeaders() {
  return { Authorization: `Bearer ${tokenInput.value || "change-me"}` };
}

async function loadJson(path) {
  const response = await fetch(`${apiBase}${path}`, { headers: authHeaders() });
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return response.json();
}

async function postJson(path) {
  const response = await fetch(`${apiBase}${path}`, {
    method: "POST",
    headers: authHeaders(),
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload.detail || `${response.status} ${response.statusText}`);
  }
  return response.json();
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function formatDateTime(value) {
  if (!value) {
    return "Never scanned";
  }
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

function renderMetrics(summary) {
  const cards = [
    ["repositories", "Repositories", ""],
    ["applications", "Applications", ""],
    ["open_critical", "Critical", "danger"],
    ["open_high", "High", "warn"],
    ["stale_scans", "Stale scans", "warn"],
    ["failed_jobs", "Failed jobs", "danger"],
    ["expired_vex", "Expired VEX", "warn"],
    ["missing_active_sbom", "Missing SBOM", "warn"],
    ["sbom_coverage_percent", "SBOM coverage %", ""],
    ["unhealthy_jobs", "Unhealthy jobs", "danger"],
    ["sla_breached_findings", "SLA breaches", "danger"],
    ["isolated_applications", "Isolated apps", "warn"],
    ["scan_failure_rate_percent", "Scan failure %", "warn"],
    ["notification_failure_count", "Notification failures", "danger"],
    ["manual_workload_items", "Manual workload", "warn"],
    ["missing_scheduled_scans", "Missing schedules", "warn"],
    ["notification_slo_breaches", "SLO breaches", "danger"],
    ["stale_remediation_items", "Stale remediation", "danger"],
    ["manual_action_count", "Manual actions", "warn"],
    ["exposure_review_items", "Exposure review", "danger"],
    ["retention_review_items", "Retention review", "warn"],
    ["reopen_risk_items", "Reopen risk", "danger"],
    ["rbac_review_items", "RBAC review", "warn"],
    ["rollout_gap_items", "Rollout gaps", "warn"],
    ["github_integration_issues", "GitHub issues", "warn"],
    ["failure_signal_items", "Failure signals", "danger"],
    ["isolated_safeguard_items", "Isolation safeguards", "warn"],
    ["quarterly_review_items", "Quarterly review", "warn"],
    ["application_readiness_items", "App readiness", "warn"],
    ["remediation_coverage_items", "Remediation coverage", "danger"],
    ["monthly_review_items", "Monthly review", "warn"],
    ["phase_readiness_items", "Phase readiness", "warn"],
    ["control_evidence_items", "Control evidence", "warn"],
    ["automation_guardrail_items", "Automation guards", "warn"],
    ["rollback_readiness_items", "Rollback readiness", "warn"],
    ["rollout_wave_gap_items", "Wave gaps", "warn"],
    ["queue_pressure_items", "Queue pressure", "warn"],
    ["storage_pressure_items", "Storage pressure", "warn"],
    ["fixable_gap_items", "Fixable gaps", "danger"],
    ["pr_ci_failure_items", "PR CI failures", "danger"],
    ["isolated_scan_health_items", "Isolated scan health", "warn"],
    ["mvp_target_breaches", "MVP target breaches", "danger"],
    ["repository_inventory_gap_items", "Inventory gaps", "warn"],
    ["daily_scan_slo_breaches", "Daily scan SLO", "danger"],
    ["issue_slo_breaches", "Issue SLO", "danger"],
    ["auto_resolution_gap_items", "Auto-resolution gaps", "warn"],
  ];
  metrics.innerHTML = cards
    .map(([key, label, tone]) => `<article class="metric ${tone}"><strong>${summary[key] ?? 0}</strong><span>${label}</span></article>`)
    .join("");
}

function renderFindings(page) {
  const rows = (page.items || []).sort((a, b) => {
    const severityDelta = (severityRank[a.severity] ?? 99) - (severityRank[b.severity] ?? 99);
    if (severityDelta !== 0) {
      return severityDelta;
    }
    return Number(b.risk_score ?? 0) - Number(a.risk_score ?? 0);
  });
  findings.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.severity)}</td><td>${escapeHtml(item.status)}</td><td>${escapeHtml(item.risk_score)}</td><td>${escapeHtml(item.id)}</td><td><button class="small" data-issue-finding="${escapeHtml(item.id)}" title="Queue GitHub issue">Queue</button></td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No findings</td></tr>`;
}

function renderApplications(page) {
  const rows = page.items || [];
  applications.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.name)}</td><td>${escapeHtml(item.path)}</td><td>${escapeHtml(item.application_type)}</td><td>${escapeHtml(formatDateTime(item.latest_scan_at))}</td><td>${escapeHtml(item.latest_scan_status || "-")}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No applications</td></tr>`;
}

function renderTechnologies(page) {
  const rows = page.items || [];
  technologies.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.name)}</td><td>${escapeHtml(item.category)}</td><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.repository_owner)}/${escapeHtml(item.repository_name)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="4">No detected technologies</td></tr>`;
}

function renderSboms(page) {
  const rows = page.items || [];
  sboms.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.repository_owner)}/${escapeHtml(item.repository_name)}</td><td>${escapeHtml(item.component_count)}</td><td>${escapeHtml(formatDateTime(item.generated_at))}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="4">No active SBOMs</td></tr>`;
}

function renderComponents(page) {
  const rows = page.items || [];
  components.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.name)} ${escapeHtml(item.version || "")}</td><td>${escapeHtml(item.ecosystem || "-")}</td><td>${escapeHtml(item.application_count)}</td><td>${escapeHtml(item.active_sbom_count)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="4">No components</td></tr>`;
}

function renderComponentUsage(page) {
  const rows = page.items || [];
  componentUsage.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.component_name)} ${escapeHtml(item.component_version || "")}</td><td>${escapeHtml(item.ecosystem || "-")}</td><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.repository_owner)}/${escapeHtml(item.repository_name)}</td><td>${escapeHtml(formatDateTime(item.generated_at))}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No component usage records</td></tr>`;
}

function renderVulnerabilities(page) {
  const rows = page.items || [];
  vulnerabilities.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.external_id)}</td><td>${escapeHtml(item.severity)}</td><td>${escapeHtml(item.open_finding_count)}</td><td>${escapeHtml(item.affected_application_count)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="4">No vulnerabilities</td></tr>`;
}

function renderVulnerabilityImpact(page) {
  const rows = page.items || [];
  vulnerabilityImpact.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.vulnerability_external_id)}</td><td>${escapeHtml(item.severity)}</td><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.component_name)} ${escapeHtml(item.component_version || "")}</td><td>${escapeHtml(item.fixed_version || "-")}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No vulnerability impact records</td></tr>`;
}

function renderRemediationActions(page) {
  const rows = page.items || [];
  remediationActions.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.action_type)}</td><td>${escapeHtml(item.status)}</td><td>${escapeHtml(item.finding_id)}</td><td>${escapeHtml(item.vulnerability_external_id || item.component_name || "-")}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="4">No remediation actions</td></tr>`;
}

function renderVexReviews(page) {
  const rows = page.items || [];
  vexReviews.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.status)}</td><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.vulnerability_external_id)}</td><td>${escapeHtml(item.component_name)} ${escapeHtml(item.component_version || "")}</td><td>${escapeHtml(formatDateTime(item.review_date))}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No VEX reviews due</td></tr>`;
}

function renderScanHealth(page) {
  const rows = page.items || [];
  scanHealth.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.repository_owner)}/${escapeHtml(item.repository_name)}</td><td>${escapeHtml(item.latest_scan_status || "missing")}</td><td>${escapeHtml(item.scanner_failures.length)}</td><td>${escapeHtml(item.latest_scan_error_message || (item.stale ? "stale" : "-"))}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No scan health issues</td></tr>`;
}

function renderSbomCoverage(page) {
  const rows = page.items || [];
  sbomCoverage.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.repository_owner)}/${escapeHtml(item.repository_name)}</td><td>${escapeHtml(item.has_active_source_sbom ? "covered" : "missing")}</td><td>${escapeHtml(item.component_count)}</td><td>${escapeHtml(item.latest_sbom_generated_at ? formatDateTime(item.latest_sbom_generated_at) : "-")}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No SBOM coverage gaps</td></tr>`;
}

function renderNotifications(page) {
  const rows = page.items || [];
  notifications.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.channel)}</td><td>${escapeHtml(item.status)}</td><td>${escapeHtml(item.severity)}</td><td>${escapeHtml(item.application_name || "-")}</td><td>${escapeHtml(item.vulnerability_external_id || item.subject)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No notifications</td></tr>`;
}

function renderMaintenanceCandidates(page) {
  const rows = page.items || [];
  maintenanceCandidates.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.repository_owner)}/${escapeHtml(item.repository_name)}</td><td>${escapeHtml(item.owner || "-")}</td><td>${escapeHtml(item.lifecycle)}</td><td>${escapeHtml(item.reasons.join(", "))}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No maintenance candidates</td></tr>`;
}

function renderRemediationCandidates(page) {
  const rows = page.items || [];
  remediationCandidates.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.severity)}</td><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.vulnerability_external_id)}</td><td>${escapeHtml(item.component_name)}</td><td>${escapeHtml(item.fixed_version)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No fixable findings without issue</td></tr>`;
}

function renderGitHubIssueActions(page) {
  const rows = page.items || [];
  githubIssueActions.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.status)}</td><td>${escapeHtml(item.provider_id || "-")}</td><td>${escapeHtml(item.application_name || "-")}</td><td>${escapeHtml(item.vulnerability_external_id || item.component_name || "-")}</td><td>${escapeHtml(item.error || item.close_error || item.url || "-")}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No GitHub issue actions</td></tr>`;
}

function renderRemediationValidations(page) {
  const rows = page.items || [];
  remediationValidations.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.validation_status)}</td><td>${escapeHtml(item.action_type)}</td><td>${escapeHtml(item.application_name || "-")}</td><td>${escapeHtml(item.validation_scan_status || "-")}</td><td>${escapeHtml(item.validation_error || "-")}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No remediation validations</td></tr>`;
}

function renderIssueClosures(page) {
  const rows = page.items || [];
  issueClosures.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.close_state)}</td><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.vulnerability_external_id)}</td><td>${escapeHtml(item.provider_id || "-")}</td><td>${escapeHtml(item.close_error || item.github_issue_closed_at || "-")}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No issue closure backlog</td></tr>`;
}

function renderJobHealth(page) {
  const rows = page.items || [];
  jobHealth.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.job_type)}</td><td>${escapeHtml(item.status)}</td><td>${escapeHtml(item.health_reason)}</td><td>${escapeHtml(item.application_name || item.repository_name || "-")}</td><td>${escapeHtml(item.last_error || formatDateTime(item.run_after))}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No unhealthy jobs</td></tr>`;
}

function renderScanArtifacts(page) {
  const rows = page.items || [];
  scanArtifacts.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.artifact_type)}</td><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.repository_owner)}/${escapeHtml(item.repository_name)}</td><td>${escapeHtml(item.scan_status)}</td><td>${escapeHtml(item.storage_key)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No scan artifacts</td></tr>`;
}

function renderAiFixActions(page) {
  const rows = page.items || [];
  aiFixActions.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.status)}</td><td>${escapeHtml(item.finding_severity || "-")}</td><td>${escapeHtml(item.application_name || "-")}</td><td>${escapeHtml(item.vulnerability_external_id || item.component_name || "-")}</td><td>${escapeHtml(item.requested_fixed_version || item.fixed_version || "-")}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No AI fix actions</td></tr>`;
}

function renderAiFixCandidates(page) {
  const rows = page.items || [];
  aiFixCandidates.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.severity)}</td><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.vulnerability_external_id)}</td><td>${escapeHtml(item.component_name)}</td><td>${escapeHtml(item.fixed_version)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No AI fix candidates</td></tr>`;
}

function renderAutoMergeEligibility(page) {
  const rows = page.items || [];
  autoMergeEligibility.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.allowed ? "allowed" : "blocked")}</td><td>${escapeHtml(item.reason)}</td><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.update_kind)}</td><td>${escapeHtml(item.validation_scan_resolved ? "validated" : "not validated")}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No auto merge candidates</td></tr>`;
}

function renderIsolatedLane(page) {
  const rows = page.items || [];
  isolatedLane.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.repository_owner)}/${escapeHtml(item.repository_name)}</td><td>${escapeHtml(item.repository_provider)}</td><td>${escapeHtml(item.source_classification)}</td><td>${escapeHtml(item.latest_scan_status || "missing")}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No isolated lane applications</td></tr>`;
}

function renderSlaFindings(page) {
  const rows = page.items || [];
  slaFindings.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.severity)}</td><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.vulnerability_external_id)}</td><td>${escapeHtml(item.age_days)}/${escapeHtml(item.sla_days)}</td><td>${escapeHtml(item.breached ? "breached" : "within SLA")}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No SLA breaches</td></tr>`;
}

function renderAuditLogs(page) {
  const rows = page.items || [];
  auditLogs.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.action)}</td><td>${escapeHtml(item.resource_type)}</td><td>${escapeHtml(item.actor)}</td><td>${escapeHtml(item.role)}</td><td>${escapeHtml(formatDateTime(item.created_at))}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No audit logs</td></tr>`;
}

function renderOperationsReadiness(rows) {
  operationsReadiness.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.check)}</td><td>${escapeHtml(item.status)}</td><td>${escapeHtml(item.configured ? "configured" : "missing")}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="4">No readiness checks</td></tr>`;
}

function renderDailyOperations(rows) {
  dailyOperations.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.check)}</td><td>${escapeHtml(item.status)}</td><td>${escapeHtml(item.count)}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="4">No daily checks</td></tr>`;
}

function renderKpiSummary(rows) {
  kpiSummary.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.metric)}</td><td>${escapeHtml(item.value)}</td><td>${escapeHtml(item.unit)}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="4">No KPI metrics</td></tr>`;
}

function renderMvpTargetCompliance(rows) {
  mvpTargetCompliance.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.target)}</td><td>${escapeHtml(item.status)}</td><td>${escapeHtml(item.current_value)}</td><td>${escapeHtml(item.target_value)} ${escapeHtml(item.unit)}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No MVP target checks</td></tr>`;
}

function renderRepositoryRollout(page) {
  const rows = page.items || [];
  repositoryRollout.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.repository_owner)}/${escapeHtml(item.repository_name)}</td><td>${escapeHtml(item.provider)}</td><td>${escapeHtml(item.application_count)}</td><td>${escapeHtml(item.active_sbom_coverage_percent)}</td><td>${escapeHtml(item.open_critical_high_count)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No repositories</td></tr>`;
}

function renderRepositoryInventoryGaps(page) {
  const rows = page.items || [];
  repositoryInventoryGaps.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.gap_type)}</td><td>${escapeHtml(item.repository_name || "-")}</td><td>${escapeHtml(item.provider || "-")}</td><td>${escapeHtml(item.count)}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No repository inventory gaps</td></tr>`;
}

function renderRetryCandidates(page) {
  const rows = page.items || [];
  retryCandidates.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.job_type)}</td><td>${escapeHtml(item.status)}</td><td>${escapeHtml(item.attempts)}/${escapeHtml(item.max_attempts)}</td><td>${escapeHtml(item.application_name || item.repository_name || "-")}</td><td>${escapeHtml(item.last_error || formatDateTime(item.run_after))}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No retry candidates</td></tr>`;
}

function renderScannerInventory(page) {
  const rows = page.items || [];
  scannerInventory.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.tool || "-")}</td><td>${escapeHtml(item.tool_version || "-")}</td><td>${escapeHtml(item.status)}</td><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.scanner_failures.length || (item.scanner_failure ? 1 : 0))}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No scanner runs</td></tr>`;
}

function renderExceptionReview(page) {
  const rows = page.items || [];
  exceptionReview.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.exception_type)}</td><td>${escapeHtml(item.severity)}</td><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.vulnerability_external_id || item.component_name)}</td><td>${escapeHtml(item.review_date ? formatDateTime(item.review_date) : item.status)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No exceptions</td></tr>`;
}

function renderStorageCleanup(page) {
  const rows = page.items || [];
  storageCleanup.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.reason)}</td><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.storage_key || "-")}</td><td>${escapeHtml(item.scan_id || "-")}</td><td>${escapeHtml(formatDateTime(item.created_at))}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No cleanup candidates</td></tr>`;
}

function renderOperationalWorkload(rows) {
  operationalWorkload.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.item)}</td><td>${escapeHtml(item.status)}</td><td>${escapeHtml(item.count)}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="4">No workload items</td></tr>`;
}

function renderRepositorySync(page) {
  const rows = page.items || [];
  repositorySync.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.repository_owner)}/${escapeHtml(item.repository_name)}</td><td>${escapeHtml(item.provider)}</td><td>${escapeHtml(formatDateTime(item.last_synced_at))}</td><td>${escapeHtml(item.latest_sync_job_status || "-")}</td><td>${escapeHtml(item.reasons.join(", ") || "ok")}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No repository sync issues</td></tr>`;
}

function renderApplicationDetection(page) {
  const rows = page.items || [];
  applicationDetection.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.issue_type)}</td><td>${escapeHtml(item.repository_owner)}/${escapeHtml(item.repository_name)}</td><td>${escapeHtml(item.application_name || "-")}</td><td>${escapeHtml(item.application_type || "-")}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No application detection gaps</td></tr>`;
}

function renderScheduledScanCoverage(page) {
  const rows = page.items || [];
  scheduledScanCoverage.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.repository_owner)}/${escapeHtml(item.repository_name)}</td><td>${escapeHtml(item.latest_scheduled_scan_status || "missing")}</td><td>${escapeHtml(item.latest_scan_trigger_type || "-")}</td><td>${escapeHtml(item.missing_recent_schedule ? "missing" : "covered")}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No scheduled scan coverage gaps</td></tr>`;
}

function renderDailyScanSlo(page) {
  const rows = page.items || [];
  dailyScanSlo.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.breached ? "breached" : "ok")}</td><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.repository_owner)}/${escapeHtml(item.repository_name)}</td><td>${escapeHtml(item.latest_scheduled_scan_status || "missing")}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No daily scan SLO records</td></tr>`;
}

function renderResolutionCandidates(page) {
  const rows = page.items || [];
  resolutionCandidates.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.severity)}</td><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.vulnerability_external_id)}</td><td>${escapeHtml(item.component_name)}</td><td>${escapeHtml(formatDateTime(item.latest_successful_scan_created_at))}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No resolution candidates</td></tr>`;
}

function renderBackupReadiness(rows) {
  backupReadiness.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.check)}</td><td>${escapeHtml(item.status)}</td><td>${escapeHtml(item.count)}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="4">No backup readiness checks</td></tr>`;
}

function renderNotificationSlo(page) {
  const rows = page.items || [];
  notificationSlo.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.severity)}</td><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.vulnerability_external_id)}</td><td>${escapeHtml(formatDateTime(item.deadline_at))}</td><td>${escapeHtml(item.breached ? "breached" : item.status)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No notification SLO breaches</td></tr>`;
}

function renderRemediationPrs(page) {
  const rows = page.items || [];
  remediationPrs.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.action_type)}</td><td>${escapeHtml(item.action_status)}</td><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.provider_id || item.branch || item.url || "-")}</td><td>${escapeHtml(item.ci_passed === null || item.ci_passed === undefined ? "unknown" : item.ci_passed ? "passed" : "failed")}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No PR/CI actions</td></tr>`;
}

function renderFixableGaps(page) {
  const rows = page.items || [];
  fixableGaps.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.gap_type)}</td><td>${escapeHtml(item.severity)}</td><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.vulnerability_external_id)}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No fixable remediation gaps</td></tr>`;
}

function renderPrCiFailures(page) {
  const rows = page.items || [];
  prCiFailures.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.action_type)}</td><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.provider_id || item.branch || "-")}</td><td>${escapeHtml(item.action_status)}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No PR CI failures</td></tr>`;
}

function renderIssueCreationSlo(page) {
  const rows = page.items || [];
  issueCreationSlo.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.breached ? "breached" : "ok")}</td><td>${escapeHtml(item.severity)}</td><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.evidence_type || "missing")}</td><td>${escapeHtml(formatDateTime(item.deadline_at))}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No issue creation SLO records</td></tr>`;
}

function renderAutoResolutionEvidence(page) {
  const rows = page.items || [];
  autoResolutionEvidence.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.complete ? "complete" : "gap")}</td><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.vulnerability_external_id)}</td><td>${escapeHtml(item.validation_scan_status || "missing")}</td><td>${escapeHtml(item.close_state)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No auto-resolution evidence records</td></tr>`;
}

function renderRemediationBacklog(page) {
  const rows = page.items || [];
  remediationBacklog.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.action_type)}</td><td>${escapeHtml(item.action_status)}</td><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.age_days)}d</td><td>${escapeHtml(item.reason)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No remediation backlog</td></tr>`;
}

function renderRemediationRescans(page) {
  const rows = page.items || [];
  remediationRescans.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.action_type)}</td><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.validation_status)}</td><td>${escapeHtml(item.latest_rescan_status || "missing")}</td><td>${escapeHtml(item.missing_rescan ? "missing" : "present")}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No missing remediation rescans</td></tr>`;
}

function renderWeeklyReview(rows) {
  weeklyReview.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.item)}</td><td>${escapeHtml(item.status)}</td><td>${escapeHtml(item.count)}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="4">No weekly review checks</td></tr>`;
}

function renderEfficiencyKpis(rows) {
  efficiencyKpis.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.metric)}</td><td>${escapeHtml(item.value)}</td><td>${escapeHtml(item.unit)}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="4">No efficiency KPIs</td></tr>`;
}

function renderManualActions(page) {
  const rows = page.items || [];
  manualActions.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.action)}</td><td>${escapeHtml(item.actor)}</td><td>${escapeHtml(item.resource_type)}</td><td>${escapeHtml(item.reason)}</td><td>${escapeHtml(formatDateTime(item.created_at))}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No manual actions</td></tr>`;
}

function renderOwnershipReview(page) {
  const rows = page.items || [];
  ownershipReview.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.issue_type)}</td><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.owner || "-")}</td><td>${escapeHtml(item.criticality)}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No ownership review items</td></tr>`;
}

function renderExposureReview(page) {
  const rows = page.items || [];
  exposureReview.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.repository_owner)}/${escapeHtml(item.repository_name)}</td><td>${escapeHtml(item.internet_exposed ? "internet" : "production")}</td><td>${escapeHtml(item.open_critical_high_count)}</td><td>${escapeHtml(item.reasons.join(", "))}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No exposure review items</td></tr>`;
}

function renderAutoMergeScope(page) {
  const rows = page.items || [];
  autoMergeScope.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.repository_owner)}/${escapeHtml(item.repository_name)}</td><td>${escapeHtml(item.criticality)}</td><td>${escapeHtml(item.recent_validation ? "recent" : "missing")}</td><td>${escapeHtml(item.reasons.join(", ") || "ok")}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No auto-merge scope items</td></tr>`;
}

function renderDataProtection(rows) {
  dataProtection.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.check)}</td><td>${escapeHtml(item.status)}</td><td>${escapeHtml(item.configured ? "configured" : "missing")}</td><td>${escapeHtml(item.count)}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No data protection checks</td></tr>`;
}

function renderRetentionReview(rows) {
  retentionReview.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.item)}</td><td>${escapeHtml(item.status)}</td><td>${escapeHtml(item.count)}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="4">No retention checks</td></tr>`;
}

function renderArtifactSbomCoverage(page) {
  const rows = page.items || [];
  artifactSbomCoverage.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.repository_owner)}/${escapeHtml(item.repository_name)}</td><td>${escapeHtml(item.has_artifact_sbom ? "covered" : "missing")}</td><td>${escapeHtml(item.artifact_types.join(", ") || "-")}</td><td>${escapeHtml(item.latest_artifact_sbom_generated_at ? formatDateTime(item.latest_artifact_sbom_generated_at) : "-")}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No artifact SBOM gaps</td></tr>`;
}

function renderLicenseReview(page) {
  const rows = page.items || [];
  licenseReview.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.issue_type)}</td><td>${escapeHtml(item.component_name)} ${escapeHtml(item.component_version || "")}</td><td>${escapeHtml(item.license || "-")}</td><td>${escapeHtml(item.application_name || "-")}</td><td>${escapeHtml(item.repository_name || "-")}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No license review items</td></tr>`;
}

function renderSecurityFindings(page) {
  const rows = page.items || [];
  securityFindings.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.finding_type)}</td><td>${escapeHtml(item.severity || "-")}</td><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.title)}</td><td>${escapeHtml(item.scan_status)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No security findings</td></tr>`;
}

function renderDuplicateReview(page) {
  const rows = page.items || [];
  duplicateReview.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.duplicate_type)}</td><td>${escapeHtml(item.count)}</td><td>${escapeHtml(item.application_name || "-")}</td><td>${escapeHtml(item.action_type || item.channel || "-")}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No duplicate review items</td></tr>`;
}

function renderReopenRisk(page) {
  const rows = page.items || [];
  reopenRisk.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.severity)}</td><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.vulnerability_external_id)}</td><td>${escapeHtml(item.reason)}</td><td>${escapeHtml(item.last_seen_scan_created_at ? formatDateTime(item.last_seen_scan_created_at) : "-")}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No reopen risk items</td></tr>`;
}

function renderQualityKpis(rows) {
  qualityKpis.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.metric)}</td><td>${escapeHtml(item.value)}</td><td>${escapeHtml(item.unit)}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="4">No quality KPIs</td></tr>`;
}

function renderScannerVersions(page) {
  const rows = page.items || [];
  scannerVersions.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.tool || "-")}</td><td>${escapeHtml(item.tool_version || "-")}</td><td>${escapeHtml(item.scan_count)}</td><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.missing_version ? "missing version" : item.stale ? "stale" : "current")}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No scanner version review items</td></tr>`;
}

function renderRuntimeEol(page) {
  const rows = page.items || [];
  runtimeEol.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.issue_type)}</td><td>${escapeHtml(item.name)} ${escapeHtml(item.version || "")}</td><td>${escapeHtml(item.source)}</td><td>${escapeHtml(item.application_name || "-")}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No runtime EOL review items</td></tr>`;
}

function renderAuditReview(page) {
  const rows = page.items || [];
  auditReview.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.reason)}</td><td>${escapeHtml(item.action)}</td><td>${escapeHtml(item.actor)}</td><td>${escapeHtml(item.role)}</td><td>${escapeHtml(formatDateTime(item.created_at))}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No audit review items</td></tr>`;
}

function renderRbacReview(rows) {
  rbacReview.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.check)}</td><td>${escapeHtml(item.status)}</td><td>${escapeHtml(item.count)}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="4">No RBAC review items</td></tr>`;
}

function renderRestoreReadiness(rows) {
  restoreReadiness.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.check)}</td><td>${escapeHtml(item.status)}</td><td>${escapeHtml(item.count)}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="4">No restore readiness checks</td></tr>`;
}

function renderRiskAcceptance(page) {
  const rows = page.items || [];
  riskAcceptance.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.source)}</td><td>${escapeHtml(item.severity)}</td><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.vulnerability_external_id)}</td><td>${escapeHtml(item.review_date ? formatDateTime(item.review_date) : item.status)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No risk acceptance review items</td></tr>`;
}

function renderRolloutGaps(page) {
  const rows = page.items || [];
  rolloutGaps.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.issue_type)}</td><td>${escapeHtml(item.repository_owner)}/${escapeHtml(item.repository_name)}</td><td>${escapeHtml(item.application_name || "-")}</td><td>${escapeHtml(item.count)}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No rollout gaps</td></tr>`;
}

function renderGithubHealth(rows) {
  githubHealth.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.check)}</td><td>${escapeHtml(item.status)}</td><td>${escapeHtml(item.count)}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="4">No GitHub integration checks</td></tr>`;
}

function renderWebhookIntake(page) {
  const rows = page.items || [];
  webhookIntake.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.event || "-")}</td><td>${escapeHtml(item.repository || "-")}</td><td>${escapeHtml(item.status)}</td><td>${escapeHtml(item.duplicate_candidate ? "duplicate" : "unique")}</td><td>${escapeHtml(item.error || formatDateTime(item.created_at))}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No webhook intake jobs</td></tr>`;
}

function renderScannerFailures(page) {
  const rows = page.items || [];
  scannerFailures.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.tool || "-")}</td><td>${escapeHtml(item.failure_type)}</td><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.status)}</td><td>${escapeHtml(item.error)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No scanner failures</td></tr>`;
}

function renderDependencyUpdates(page) {
  const rows = page.items || [];
  dependencyUpdates.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.update_source)}</td><td>${escapeHtml(item.action_status)}</td><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.ci_passed === null || item.ci_passed === undefined ? "unknown" : item.ci_passed ? "passed" : "failed")}</td><td>${escapeHtml(item.url || item.branch || item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No dependency update PRs</td></tr>`;
}

function renderFailureSignals(page) {
  const rows = page.items || [];
  failureSignals.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.signal_type)}</td><td>${escapeHtml(item.source)}</td><td>${escapeHtml(item.application_name || item.repository_name || "-")}</td><td>${escapeHtml(item.status)}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No failure signals</td></tr>`;
}

function renderIsolatedSafeguards(page) {
  const rows = page.items || [];
  isolatedSafeguards.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.issue_type)}</td><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.repository_owner)}/${escapeHtml(item.repository_name)}</td><td>${escapeHtml(item.latest_scan_status || "missing")}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No isolated safeguard issues</td></tr>`;
}

function renderIsolatedScanHealth(page) {
  const rows = page.items || [];
  isolatedScanHealth.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.health_type)}</td><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.repository_owner)}/${escapeHtml(item.repository_name)}</td><td>${escapeHtml(item.latest_scan_status || "missing")}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No isolated scan health issues</td></tr>`;
}

function renderSecretsReview(page) {
  const rows = page.items || [];
  secretsReview.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.source)}</td><td>${escapeHtml(item.severity || "-")}</td><td>${escapeHtml(item.application_name || "-")}</td><td>${escapeHtml(item.title)}</td><td>${escapeHtml(item.detail || "-")}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No secret review items</td></tr>`;
}

function renderWorkerPosture(rows) {
  workerPosture.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.check)}</td><td>${escapeHtml(item.status)}</td><td>${escapeHtml(item.count)}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="4">No worker posture checks</td></tr>`;
}

function renderExploitIntel(page) {
  const rows = page.items || [];
  exploitIntel.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.severity)}</td><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.vulnerability_external_id)}</td><td>${escapeHtml(item.kev ? "KEV" : item.epss_signal ? "EPSS" : "-")}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No exploit intelligence items</td></tr>`;
}

function renderQuarterlyReview(rows) {
  quarterlyReview.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.item)}</td><td>${escapeHtml(item.status)}</td><td>${escapeHtml(item.count)}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="4">No quarterly review items</td></tr>`;
}

function renderRolloutBaseline(rows) {
  rolloutBaseline.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.check)}</td><td>${escapeHtml(item.status)}</td><td>${escapeHtml(item.count)}</td><td>${escapeHtml(item.target ?? "-")}</td><td>${escapeHtml(item.percent === null || item.percent === undefined ? "-" : item.percent)}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="6">No rollout baseline checks</td></tr>`;
}

function renderApplicationReadiness(page) {
  const rows = page.items || [];
  applicationReadiness.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.issue_type)}</td><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.repository_owner)}/${escapeHtml(item.repository_name)}</td><td>${escapeHtml(item.latest_scan_status || "missing")}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No application readiness issues</td></tr>`;
}

function renderScanTargets(rows) {
  scanTargets.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.check)}</td><td>${escapeHtml(item.status)}</td><td>${escapeHtml(item.count)}</td><td>${escapeHtml(item.actual_percent === null || item.actual_percent === undefined ? "-" : item.actual_percent)}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No scan target checks</td></tr>`;
}

function renderRemediationCoverage(page) {
  const rows = page.items || [];
  remediationCoverage.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.has_issue_or_pr ? "covered" : "missing")}</td><td>${escapeHtml(item.severity)}</td><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.vulnerability_external_id)}</td><td>${escapeHtml(item.action_status || "-")}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No remediation coverage items</td></tr>`;
}

function renderResolutionVerification(page) {
  const rows = page.items || [];
  resolutionVerification.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.issue_type)}</td><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.severity)}</td><td>${escapeHtml(item.validation_status)}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No resolution verification issues</td></tr>`;
}

function renderMonthlyReview(rows) {
  monthlyReview.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.item)}</td><td>${escapeHtml(item.status)}</td><td>${escapeHtml(item.count)}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="4">No monthly review checks</td></tr>`;
}

function renderOperationalLoadKpis(rows) {
  operationalLoadKpis.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.metric)}</td><td>${escapeHtml(item.value)}</td><td>${escapeHtml(item.unit)}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="4">No operational load KPIs</td></tr>`;
}

function renderRemediationAging(page) {
  const rows = page.items || [];
  remediationAging.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.age_bucket)}</td><td>${escapeHtml(item.age_days)}</td><td>${escapeHtml(item.severity)}</td><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.action_status)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No stale remediation actions</td></tr>`;
}

function renderToolchainPosture(rows) {
  toolchainPosture.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.check)}</td><td>${escapeHtml(item.status)}</td><td>${escapeHtml(item.count)}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="4">No toolchain posture checks</td></tr>`;
}

function renderNotificationDigest(page) {
  const rows = page.items || [];
  notificationDigest.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.issue_type)}</td><td>${escapeHtml(item.severity)}</td><td>${escapeHtml(item.application_name || "-")}</td><td>${escapeHtml(item.status)}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No notification digest issues</td></tr>`;
}

function renderPhaseReadiness(rows) {
  phaseReadiness.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.phase)}</td><td>${escapeHtml(item.check)}</td><td>${escapeHtml(item.status)}</td><td>${escapeHtml(item.count)}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No phase readiness checks</td></tr>`;
}

function renderFindingLifecycle(page) {
  const rows = page.items || [];
  findingLifecycle.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.issue_type)}</td><td>${escapeHtml(item.severity)}</td><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.age_days)}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No finding lifecycle issues</td></tr>`;
}

function renderVexInvalidation(page) {
  const rows = page.items || [];
  vexInvalidation.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.reason)}</td><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.vulnerability_external_id)}</td><td>${escapeHtml(item.expired ? "expired" : "active")}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No VEX invalidation candidates</td></tr>`;
}

function renderRepositoryDrift(page) {
  const rows = page.items || [];
  repositoryDrift.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.issue_type)}</td><td>${escapeHtml(item.repository_owner)}/${escapeHtml(item.repository_name)}</td><td>${escapeHtml(item.provider)}</td><td>${escapeHtml(item.application_name || "-")}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No repository drift items</td></tr>`;
}

function renderAutoMergePilot(page) {
  const rows = page.items || [];
  autoMergePilot.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.allowed ? "allowed" : "blocked")}</td><td>${escapeHtml(item.reason)}</td><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.action_status)}</td><td>${escapeHtml(item.validation_scan_resolved ? "validated" : "missing validation")}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No auto-merge pilot items</td></tr>`;
}

function renderControlEvidence(rows) {
  controlEvidence.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.check)}</td><td>${escapeHtml(item.status)}</td><td>${escapeHtml(item.count)}</td><td colspan="2">${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No control evidence gaps</td></tr>`;
}

function renderFindingEvidenceGaps(page) {
  const rows = page.items || [];
  findingEvidenceGaps.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.gap_type)}</td><td>${escapeHtml(item.severity)}</td><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.status)}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No finding evidence gaps</td></tr>`;
}

function renderJobBacklog(page) {
  const rows = page.items || [];
  jobBacklog.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.reason)}</td><td>${escapeHtml(item.job_type)}</td><td>${escapeHtml(item.status)}</td><td>${escapeHtml(item.age_hours)}h</td><td>${escapeHtml(item.last_error || "-")}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No job backlog items</td></tr>`;
}

function renderAuditEvidenceGaps(page) {
  const rows = page.items || [];
  auditEvidenceGaps.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.gap_type)}</td><td>${escapeHtml(item.resource_type)}</td><td>${escapeHtml(item.expected_action)}</td><td>${escapeHtml(item.actor || "-")}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No audit evidence gaps</td></tr>`;
}

function renderScanEvidenceQuality(page) {
  const rows = page.items || [];
  scanEvidenceQuality.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.gap_type)}</td><td>${escapeHtml(item.status)}</td><td>${escapeHtml(item.tool || "-")}</td><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No scan evidence quality gaps</td></tr>`;
}

function renderAutomationGuardrails(rows) {
  automationGuardrails.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.check)}</td><td>${escapeHtml(item.status)}</td><td>${escapeHtml(item.count)}</td><td colspan="2">${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No automation guardrail gaps</td></tr>`;
}

function renderPolicyViolations(page) {
  const rows = page.items || [];
  policyViolations.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.violation_type)}</td><td>${escapeHtml(item.severity)}</td><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.action_status)}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No policy violations</td></tr>`;
}

function renderDryRunDecisions(page) {
  const rows = page.items || [];
  dryRunDecisions.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.decision)}</td><td>${escapeHtml(item.mismatch ? "mismatch" : "matched")}</td><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.action_status)}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No dry-run decisions</td></tr>`;
}

function renderRollbackReadiness(rows) {
  rollbackReadiness.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.check)}</td><td>${escapeHtml(item.status)}</td><td>${escapeHtml(item.count)}</td><td colspan="2">${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No rollback readiness gaps</td></tr>`;
}

function renderAutomationSuppressions(page) {
  const rows = page.items || [];
  automationSuppressions.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.reason)}</td><td>${escapeHtml(item.action_type)}</td><td>${escapeHtml(item.severity)}</td><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No automation suppressions</td></tr>`;
}

function renderRolloutWaves(rows) {
  rolloutWaves.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.wave)}</td><td>${escapeHtml(item.repository_count)}</td><td>${escapeHtml(item.active_sbom_coverage_percent)}%</td><td>${escapeHtml(item.fresh_scan_percent)}%</td><td>${escapeHtml(item.gap_count)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No rollout wave records</td></tr>`;
}

function renderMvpTargets(page) {
  const rows = page.items || [];
  mvpTargets.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.ready ? "ready" : item.issue_type)}</td><td>${escapeHtml(item.repository_owner)}/${escapeHtml(item.repository_name)}</td><td>${escapeHtml(item.application_count)}</td><td>${escapeHtml(item.active_sbom_coverage_percent)}%</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No MVP target records</td></tr>`;
}

function renderKpiEvidence(page) {
  const rows = page.items || [];
  kpiEvidence.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.metric)}</td><td>${escapeHtml(item.included ? "included" : "excluded")}</td><td>${escapeHtml(item.status)}</td><td>${escapeHtml(item.application_name || item.record_type)}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No KPI evidence records</td></tr>`;
}

function renderEfficiencyTimeline(page) {
  const rows = page.items || [];
  efficiencyTimeline.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.metric)}</td><td>${escapeHtml(item.severity)}</td><td>${escapeHtml(item.application_name)}</td><td>${escapeHtml(item.duration_hours ?? "-")}</td><td>${escapeHtml(item.breached ? "breached" : "ok")}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No efficiency timeline records</td></tr>`;
}

function renderInitialInventory(page) {
  const rows = page.items || [];
  initialInventory.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.complete ? "complete" : item.issue_type)}</td><td>${escapeHtml(item.repository_owner)}/${escapeHtml(item.repository_name)}</td><td>${escapeHtml(item.application_name || "-")}</td><td>${escapeHtml(item.open_critical_high_count)}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No initial inventory records</td></tr>`;
}

function renderQueuePressure(rows) {
  queuePressure.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.job_type)}</td><td>${escapeHtml(item.status)}</td><td>${escapeHtml(item.count)}</td><td>${escapeHtml(item.oldest_age_hours)}h</td><td>${escapeHtml(item.stale_count + item.overdue_count + item.retry_exhausted_count)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No queue pressure records</td></tr>`;
}

function renderSchedulerDrift(page) {
  const rows = page.items || [];
  schedulerDrift.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.drift_type)}</td><td>${escapeHtml(item.job_type || "-")}</td><td>${escapeHtml(item.application_name || item.repository_name || "-")}</td><td>${escapeHtml(item.count)}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No scheduler drift records</td></tr>`;
}

function renderStoragePressure(rows) {
  storagePressure.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.check)}</td><td>${escapeHtml(item.status)}</td><td>${escapeHtml(item.count)}</td><td>${escapeHtml(item.estimated_bytes)}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No storage pressure records</td></tr>`;
}

function renderGithubSyncLag(page) {
  const rows = page.items || [];
  githubSyncLag.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.lag_type)}</td><td>${escapeHtml(item.repository_owner)}/${escapeHtml(item.repository_name)}</td><td>${escapeHtml(item.provider)}</td><td>${escapeHtml(formatDateTime(item.last_synced_at))}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No GitHub sync lag records</td></tr>`;
}

function renderCredentialFailures(page) {
  const rows = page.items || [];
  credentialFailures.innerHTML = rows.length
    ? rows
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.failure_type)}</td><td>${escapeHtml(item.source)}</td><td>${escapeHtml(item.status)}</td><td>${escapeHtml(item.repository_name || item.application_name || "-")}</td><td>${escapeHtml(item.detail)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="5">No credential failure records</td></tr>`;
}

async function refresh() {
  metrics.innerHTML = "";
  findings.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  applications.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  technologies.innerHTML = `<tr><td colspan="4">Loading</td></tr>`;
  sboms.innerHTML = `<tr><td colspan="4">Loading</td></tr>`;
  components.innerHTML = `<tr><td colspan="4">Loading</td></tr>`;
  componentUsage.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  vulnerabilities.innerHTML = `<tr><td colspan="4">Loading</td></tr>`;
  vulnerabilityImpact.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  remediationActions.innerHTML = `<tr><td colspan="4">Loading</td></tr>`;
  vexReviews.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  scanHealth.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  sbomCoverage.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  notifications.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  maintenanceCandidates.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  remediationCandidates.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  githubIssueActions.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  remediationValidations.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  issueClosures.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  jobHealth.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  scanArtifacts.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  aiFixActions.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  aiFixCandidates.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  autoMergeEligibility.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  isolatedLane.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  slaFindings.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  auditLogs.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  operationsReadiness.innerHTML = `<tr><td colspan="4">Loading</td></tr>`;
  dailyOperations.innerHTML = `<tr><td colspan="4">Loading</td></tr>`;
  kpiSummary.innerHTML = `<tr><td colspan="4">Loading</td></tr>`;
  mvpTargetCompliance.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  repositoryRollout.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  repositoryInventoryGaps.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  retryCandidates.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  scannerInventory.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  exceptionReview.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  storageCleanup.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  operationalWorkload.innerHTML = `<tr><td colspan="4">Loading</td></tr>`;
  repositorySync.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  applicationDetection.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  scheduledScanCoverage.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  dailyScanSlo.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  resolutionCandidates.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  backupReadiness.innerHTML = `<tr><td colspan="4">Loading</td></tr>`;
  notificationSlo.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  remediationPrs.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  fixableGaps.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  prCiFailures.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  issueCreationSlo.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  autoResolutionEvidence.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  remediationBacklog.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  remediationRescans.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  weeklyReview.innerHTML = `<tr><td colspan="4">Loading</td></tr>`;
  efficiencyKpis.innerHTML = `<tr><td colspan="4">Loading</td></tr>`;
  manualActions.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  ownershipReview.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  exposureReview.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  autoMergeScope.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  dataProtection.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  retentionReview.innerHTML = `<tr><td colspan="4">Loading</td></tr>`;
  artifactSbomCoverage.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  licenseReview.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  securityFindings.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  duplicateReview.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  reopenRisk.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  qualityKpis.innerHTML = `<tr><td colspan="4">Loading</td></tr>`;
  scannerVersions.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  runtimeEol.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  auditReview.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  rbacReview.innerHTML = `<tr><td colspan="4">Loading</td></tr>`;
  restoreReadiness.innerHTML = `<tr><td colspan="4">Loading</td></tr>`;
  riskAcceptance.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  rolloutGaps.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  githubHealth.innerHTML = `<tr><td colspan="4">Loading</td></tr>`;
  webhookIntake.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  scannerFailures.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  dependencyUpdates.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  failureSignals.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  isolatedSafeguards.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  isolatedScanHealth.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  secretsReview.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  workerPosture.innerHTML = `<tr><td colspan="4">Loading</td></tr>`;
  exploitIntel.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  quarterlyReview.innerHTML = `<tr><td colspan="4">Loading</td></tr>`;
  rolloutBaseline.innerHTML = `<tr><td colspan="6">Loading</td></tr>`;
  applicationReadiness.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  scanTargets.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  remediationCoverage.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  resolutionVerification.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  monthlyReview.innerHTML = `<tr><td colspan="4">Loading</td></tr>`;
  operationalLoadKpis.innerHTML = `<tr><td colspan="4">Loading</td></tr>`;
  remediationAging.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  toolchainPosture.innerHTML = `<tr><td colspan="4">Loading</td></tr>`;
  notificationDigest.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  phaseReadiness.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  findingLifecycle.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  vexInvalidation.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  repositoryDrift.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  autoMergePilot.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  controlEvidence.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  findingEvidenceGaps.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  jobBacklog.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  auditEvidenceGaps.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  scanEvidenceQuality.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  automationGuardrails.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  policyViolations.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  dryRunDecisions.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  rollbackReadiness.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  automationSuppressions.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  rolloutWaves.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  mvpTargets.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  kpiEvidence.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  efficiencyTimeline.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  initialInventory.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  queuePressure.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  schedulerDrift.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  storagePressure.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  githubSyncLag.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  credentialFailures.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  try {
    const [
      summary,
      criticalFindings,
      highFindings,
      applicationPage,
      technologyPage,
      sbomPage,
      componentPage,
      componentUsagePage,
      vulnerabilityPage,
      vulnerabilityImpactPage,
      remediationActionPage,
      vexPage,
      scanHealthPage,
      sbomCoveragePage,
      notificationPage,
      maintenancePage,
      remediationCandidatePage,
      githubIssueActionPage,
      remediationValidationPage,
      issueClosurePage,
      jobHealthPage,
      artifactPage,
      aiFixActionPage,
      aiFixCandidatePage,
      autoMergePage,
      isolatedLanePage,
      slaFindingPage,
      auditLogPage,
      readinessPage,
      dailyPage,
      kpiPage,
      mvpTargetCompliancePage,
      rolloutPage,
      repositoryInventoryGapPage,
      retryCandidatePage,
      scannerInventoryPage,
      exceptionReviewPage,
      storageCleanupPage,
      operationalWorkloadPage,
      repositorySyncPage,
      applicationDetectionPage,
      scheduledScanCoveragePage,
      dailyScanSloPage,
      resolutionCandidatePage,
      backupReadinessPage,
      notificationSloPage,
      remediationPrPage,
      fixableGapPage,
      prCiFailurePage,
      issueCreationSloPage,
      autoResolutionEvidencePage,
      remediationBacklogPage,
      remediationRescanPage,
      weeklyReviewPage,
      efficiencyKpiPage,
      manualActionPage,
      ownershipReviewPage,
      exposureReviewPage,
      autoMergeScopePage,
      dataProtectionPage,
      retentionReviewPage,
      artifactSbomCoveragePage,
      licenseReviewPage,
      securityFindingPage,
      duplicateReviewPage,
      reopenRiskPage,
      qualityKpiPage,
      scannerVersionPage,
      runtimeEolPage,
      auditReviewPage,
      rbacReviewPage,
      restoreReadinessPage,
      riskAcceptancePage,
      rolloutGapPage,
      githubHealthPage,
      webhookIntakePage,
      scannerFailurePage,
      dependencyUpdatePage,
      failureSignalPage,
      isolatedSafeguardPage,
      isolatedScanHealthPage,
      secretsReviewPage,
      workerPosturePage,
      exploitIntelPage,
      quarterlyReviewPage,
      rolloutBaselinePage,
      applicationReadinessPage,
      scanTargetPage,
      remediationCoveragePage,
      resolutionVerificationPage,
      monthlyReviewPage,
      operationalLoadPage,
      remediationAgingPage,
      toolchainPosturePage,
      notificationDigestPage,
      phaseReadinessPage,
      findingLifecyclePage,
      vexInvalidationPage,
      repositoryDriftPage,
      autoMergePilotPage,
      controlEvidencePage,
      findingEvidenceGapPage,
      jobBacklogPage,
      auditEvidenceGapPage,
      scanEvidenceQualityPage,
      automationGuardrailPage,
      policyViolationPage,
      dryRunDecisionPage,
      rollbackReadinessPage,
      automationSuppressionPage,
      rolloutWavePage,
      mvpTargetPage,
      kpiEvidencePage,
      efficiencyTimelinePage,
      initialInventoryPage,
      queuePressurePage,
      schedulerDriftPage,
      storagePressurePage,
      githubSyncLagPage,
      credentialFailurePage,
    ] = await Promise.all([
      loadJson("/dashboard/summary"),
      loadJson("/findings?status=open&severity=critical&limit=10"),
      loadJson("/findings?status=open&severity=high&limit=10"),
      loadJson("/applications?limit=10"),
      loadJson("/technologies?limit=10"),
      loadJson("/sboms?active=true&limit=10"),
      loadJson("/components?limit=10"),
      loadJson("/components/usage?limit=10"),
      loadJson("/vulnerabilities?limit=10"),
      loadJson("/vulnerabilities/impact?limit=10"),
      loadJson("/remediation-actions?limit=10"),
      loadJson("/vex?expired=true&limit=10"),
      loadJson("/scan-health?limit=10"),
      loadJson("/sbom-coverage?missing=true&limit=10"),
      loadJson("/notifications?limit=10"),
      loadJson("/maintenance/applications?limit=10"),
      loadJson("/remediation/candidates?limit=10"),
      loadJson("/remediation/issues?limit=10"),
      loadJson("/remediation/validations?limit=10"),
      loadJson("/remediation/closures?limit=10"),
      loadJson("/job-health?limit=10"),
      loadJson("/artifacts?limit=10"),
      loadJson("/ai-fix?limit=10"),
      loadJson("/ai-fix/candidates?limit=10"),
      loadJson("/auto-merge/eligibility?limit=10"),
      loadJson("/isolated-lane?limit=10"),
      loadJson("/sla/findings?breached=true&limit=10"),
      loadJson("/audit-logs?limit=10"),
      loadJson("/operations/readiness"),
      loadJson("/operations/daily"),
      loadJson("/kpis/summary"),
      loadJson("/kpis/targets"),
      loadJson("/rollout/repositories?limit=10"),
      loadJson("/rollout/repository-inventory-gaps?limit=10"),
      loadJson("/jobs/retry-candidates?limit=10"),
      loadJson("/scanner-inventory?limit=10"),
      loadJson("/exceptions?limit=10"),
      loadJson("/storage/cleanup-candidates?limit=10"),
      loadJson("/operations/workload"),
      loadJson("/repository-sync?stale=true&limit=10"),
      loadJson("/application-detection?limit=10"),
      loadJson("/scheduled-scan-coverage?missing=true&limit=10"),
      loadJson("/scans/daily-slo?breached=true&limit=10"),
      loadJson("/findings/resolution-candidates?limit=10"),
      loadJson("/operations/backup-readiness"),
      loadJson("/notifications/slo?breached=true&limit=10"),
      loadJson("/remediation/prs?limit=10"),
      loadJson("/remediation/fixable-gaps?limit=10"),
      loadJson("/remediation/pr-ci-failures?limit=10"),
      loadJson("/remediation/issue-slo?breached=true&limit=10"),
      loadJson("/remediation/auto-resolution?complete=false&limit=10"),
      loadJson("/remediation/backlog?limit=10"),
      loadJson("/remediation/rescans?missing=true&limit=10"),
      loadJson("/operations/weekly-review"),
      loadJson("/kpis/efficiency"),
      loadJson("/operations/manual-actions?limit=10"),
      loadJson("/governance/ownership?limit=10"),
      loadJson("/governance/exposure?limit=10"),
      loadJson("/governance/auto-merge-scope?limit=10"),
      loadJson("/security/data-protection"),
      loadJson("/storage/retention"),
      loadJson("/artifacts/sbom-coverage?missing=true&limit=10"),
      loadJson("/components/licenses?limit=10"),
      loadJson("/security/findings?limit=10"),
      loadJson("/quality/duplicates?limit=10"),
      loadJson("/quality/reopen-risk?limit=10"),
      loadJson("/kpis/quality"),
      loadJson("/scanner-versions?limit=10"),
      loadJson("/governance/runtime-eol?limit=10"),
      loadJson("/audit/review?limit=10"),
      loadJson("/security/rbac-review"),
      loadJson("/operations/restore-readiness"),
      loadJson("/governance/risk-acceptance?limit=10"),
      loadJson("/rollout/gaps?limit=10"),
      loadJson("/integrations/github-health"),
      loadJson("/integrations/webhooks?limit=10"),
      loadJson("/scanners/failures?limit=10"),
      loadJson("/remediation/dependency-updates?limit=10"),
      loadJson("/operations/failure-signals?limit=10"),
      loadJson("/isolated-lane/safeguards?limit=10"),
      loadJson("/isolated-lane/scan-health?limit=10"),
      loadJson("/security/secrets-review?limit=10"),
      loadJson("/operations/worker-posture"),
      loadJson("/security/exploit-intel?limit=10"),
      loadJson("/governance/quarterly-review"),
      loadJson("/rollout/baseline"),
      loadJson("/rollout/application-readiness?limit=10"),
      loadJson("/operations/scan-targets"),
      loadJson("/remediation/coverage?missing_action=true&limit=10"),
      loadJson("/remediation/resolution-verification?limit=10"),
      loadJson("/operations/monthly-review"),
      loadJson("/kpis/operational-load"),
      loadJson("/remediation/aging?limit=10"),
      loadJson("/operations/toolchain-posture"),
      loadJson("/notifications/digest-readiness?limit=10"),
      loadJson("/operations/phase-readiness"),
      loadJson("/findings/lifecycle-review?limit=10"),
      loadJson("/vex/invalidation-candidates?limit=10"),
      loadJson("/rollout/repository-drift?limit=10"),
      loadJson("/auto-merge/pilot-readiness?limit=10"),
      loadJson("/operations/control-evidence"),
      loadJson("/findings/evidence-gaps?limit=10"),
      loadJson("/jobs/backlog?limit=10"),
      loadJson("/audit/evidence-gaps?limit=10"),
      loadJson("/scans/evidence-quality?limit=10"),
      loadJson("/auto-merge/guardrails"),
      loadJson("/auto-merge/policy-violations?limit=10"),
      loadJson("/auto-merge/dry-runs?limit=10"),
      loadJson("/operations/rollback-readiness"),
      loadJson("/remediation/suppressions?limit=10"),
      loadJson("/rollout/waves"),
      loadJson("/rollout/mvp-targets?limit=10"),
      loadJson("/kpis/evidence?limit=10"),
      loadJson("/kpis/timeline?limit=10"),
      loadJson("/rollout/initial-inventory?limit=10"),
      loadJson("/operations/queue-pressure"),
      loadJson("/operations/scheduler-drift?limit=10"),
      loadJson("/storage/pressure"),
      loadJson("/repository-sync/lag?limit=10"),
      loadJson("/operations/credential-failures?limit=10"),
    ]);
    renderMetrics(summary);
    renderFindings({ items: [...(criticalFindings.items || []), ...(highFindings.items || [])] });
    renderApplications(applicationPage);
    renderTechnologies(technologyPage);
    renderSboms(sbomPage);
    renderComponents(componentPage);
    renderComponentUsage(componentUsagePage);
    renderVulnerabilities(vulnerabilityPage);
    renderVulnerabilityImpact(vulnerabilityImpactPage);
    renderRemediationActions(remediationActionPage);
    renderVexReviews(vexPage);
    renderScanHealth(scanHealthPage);
    renderSbomCoverage(sbomCoveragePage);
    renderNotifications(notificationPage);
    renderMaintenanceCandidates(maintenancePage);
    renderRemediationCandidates(remediationCandidatePage);
    renderGitHubIssueActions(githubIssueActionPage);
    renderRemediationValidations(remediationValidationPage);
    renderIssueClosures(issueClosurePage);
    renderJobHealth(jobHealthPage);
    renderScanArtifacts(artifactPage);
    renderAiFixActions(aiFixActionPage);
    renderAiFixCandidates(aiFixCandidatePage);
    renderAutoMergeEligibility(autoMergePage);
    renderIsolatedLane(isolatedLanePage);
    renderSlaFindings(slaFindingPage);
    renderAuditLogs(auditLogPage);
    renderOperationsReadiness(readinessPage);
    renderDailyOperations(dailyPage);
    renderKpiSummary(kpiPage);
    renderMvpTargetCompliance(mvpTargetCompliancePage);
    renderRepositoryRollout(rolloutPage);
    renderRepositoryInventoryGaps(repositoryInventoryGapPage);
    renderRetryCandidates(retryCandidatePage);
    renderScannerInventory(scannerInventoryPage);
    renderExceptionReview(exceptionReviewPage);
    renderStorageCleanup(storageCleanupPage);
    renderOperationalWorkload(operationalWorkloadPage);
    renderRepositorySync(repositorySyncPage);
    renderApplicationDetection(applicationDetectionPage);
    renderScheduledScanCoverage(scheduledScanCoveragePage);
    renderDailyScanSlo(dailyScanSloPage);
    renderResolutionCandidates(resolutionCandidatePage);
    renderBackupReadiness(backupReadinessPage);
    renderNotificationSlo(notificationSloPage);
    renderRemediationPrs(remediationPrPage);
    renderFixableGaps(fixableGapPage);
    renderPrCiFailures(prCiFailurePage);
    renderIssueCreationSlo(issueCreationSloPage);
    renderAutoResolutionEvidence(autoResolutionEvidencePage);
    renderRemediationBacklog(remediationBacklogPage);
    renderRemediationRescans(remediationRescanPage);
    renderWeeklyReview(weeklyReviewPage);
    renderEfficiencyKpis(efficiencyKpiPage);
    renderManualActions(manualActionPage);
    renderOwnershipReview(ownershipReviewPage);
    renderExposureReview(exposureReviewPage);
    renderAutoMergeScope(autoMergeScopePage);
    renderDataProtection(dataProtectionPage);
    renderRetentionReview(retentionReviewPage);
    renderArtifactSbomCoverage(artifactSbomCoveragePage);
    renderLicenseReview(licenseReviewPage);
    renderSecurityFindings(securityFindingPage);
    renderDuplicateReview(duplicateReviewPage);
    renderReopenRisk(reopenRiskPage);
    renderQualityKpis(qualityKpiPage);
    renderScannerVersions(scannerVersionPage);
    renderRuntimeEol(runtimeEolPage);
    renderAuditReview(auditReviewPage);
    renderRbacReview(rbacReviewPage);
    renderRestoreReadiness(restoreReadinessPage);
    renderRiskAcceptance(riskAcceptancePage);
    renderRolloutGaps(rolloutGapPage);
    renderGithubHealth(githubHealthPage);
    renderWebhookIntake(webhookIntakePage);
    renderScannerFailures(scannerFailurePage);
    renderDependencyUpdates(dependencyUpdatePage);
    renderFailureSignals(failureSignalPage);
    renderIsolatedSafeguards(isolatedSafeguardPage);
    renderIsolatedScanHealth(isolatedScanHealthPage);
    renderSecretsReview(secretsReviewPage);
    renderWorkerPosture(workerPosturePage);
    renderExploitIntel(exploitIntelPage);
    renderQuarterlyReview(quarterlyReviewPage);
    renderRolloutBaseline(rolloutBaselinePage);
    renderApplicationReadiness(applicationReadinessPage);
    renderScanTargets(scanTargetPage);
    renderRemediationCoverage(remediationCoveragePage);
    renderResolutionVerification(resolutionVerificationPage);
    renderMonthlyReview(monthlyReviewPage);
    renderOperationalLoadKpis(operationalLoadPage);
    renderRemediationAging(remediationAgingPage);
    renderToolchainPosture(toolchainPosturePage);
    renderNotificationDigest(notificationDigestPage);
    renderPhaseReadiness(phaseReadinessPage);
    renderFindingLifecycle(findingLifecyclePage);
    renderVexInvalidation(vexInvalidationPage);
    renderRepositoryDrift(repositoryDriftPage);
    renderAutoMergePilot(autoMergePilotPage);
    renderControlEvidence(controlEvidencePage);
    renderFindingEvidenceGaps(findingEvidenceGapPage);
    renderJobBacklog(jobBacklogPage);
    renderAuditEvidenceGaps(auditEvidenceGapPage);
    renderScanEvidenceQuality(scanEvidenceQualityPage);
    renderAutomationGuardrails(automationGuardrailPage);
    renderPolicyViolations(policyViolationPage);
    renderDryRunDecisions(dryRunDecisionPage);
    renderRollbackReadiness(rollbackReadinessPage);
    renderAutomationSuppressions(automationSuppressionPage);
    renderRolloutWaves(rolloutWavePage);
    renderMvpTargets(mvpTargetPage);
    renderKpiEvidence(kpiEvidencePage);
    renderEfficiencyTimeline(efficiencyTimelinePage);
    renderInitialInventory(initialInventoryPage);
    renderQueuePressure(queuePressurePage);
    renderSchedulerDrift(schedulerDriftPage);
    renderStoragePressure(storagePressurePage);
    renderGithubSyncLag(githubSyncLagPage);
    renderCredentialFailures(credentialFailurePage);
  } catch (error) {
    metrics.innerHTML = `<article class="metric danger"><strong>!</strong><span>${error.message}</span></article>`;
    findings.innerHTML = `<tr><td colspan="5">Unable to load findings</td></tr>`;
    applications.innerHTML = `<tr><td colspan="5">Unable to load applications</td></tr>`;
    technologies.innerHTML = `<tr><td colspan="4">Unable to load technologies</td></tr>`;
    sboms.innerHTML = `<tr><td colspan="4">Unable to load SBOMs</td></tr>`;
    components.innerHTML = `<tr><td colspan="4">Unable to load components</td></tr>`;
    componentUsage.innerHTML = `<tr><td colspan="5">Unable to load component usage</td></tr>`;
    vulnerabilities.innerHTML = `<tr><td colspan="4">Unable to load vulnerabilities</td></tr>`;
    vulnerabilityImpact.innerHTML = `<tr><td colspan="5">Unable to load vulnerability impact</td></tr>`;
    remediationActions.innerHTML = `<tr><td colspan="4">Unable to load remediation actions</td></tr>`;
    vexReviews.innerHTML = `<tr><td colspan="5">Unable to load VEX reviews</td></tr>`;
    scanHealth.innerHTML = `<tr><td colspan="5">Unable to load scan health</td></tr>`;
    sbomCoverage.innerHTML = `<tr><td colspan="5">Unable to load SBOM coverage</td></tr>`;
    notifications.innerHTML = `<tr><td colspan="5">Unable to load notifications</td></tr>`;
    maintenanceCandidates.innerHTML = `<tr><td colspan="5">Unable to load maintenance candidates</td></tr>`;
    remediationCandidates.innerHTML = `<tr><td colspan="5">Unable to load remediation candidates</td></tr>`;
    githubIssueActions.innerHTML = `<tr><td colspan="5">Unable to load GitHub issue actions</td></tr>`;
    remediationValidations.innerHTML = `<tr><td colspan="5">Unable to load remediation validations</td></tr>`;
    issueClosures.innerHTML = `<tr><td colspan="5">Unable to load issue closures</td></tr>`;
    jobHealth.innerHTML = `<tr><td colspan="5">Unable to load job health</td></tr>`;
    scanArtifacts.innerHTML = `<tr><td colspan="5">Unable to load scan artifacts</td></tr>`;
    aiFixActions.innerHTML = `<tr><td colspan="5">Unable to load AI fix actions</td></tr>`;
    aiFixCandidates.innerHTML = `<tr><td colspan="5">Unable to load AI fix candidates</td></tr>`;
    autoMergeEligibility.innerHTML = `<tr><td colspan="5">Unable to load auto merge eligibility</td></tr>`;
    isolatedLane.innerHTML = `<tr><td colspan="5">Unable to load isolated lane</td></tr>`;
    slaFindings.innerHTML = `<tr><td colspan="5">Unable to load SLA findings</td></tr>`;
    auditLogs.innerHTML = `<tr><td colspan="5">Unable to load audit logs</td></tr>`;
    operationsReadiness.innerHTML = `<tr><td colspan="4">Unable to load operations readiness</td></tr>`;
    dailyOperations.innerHTML = `<tr><td colspan="4">Unable to load daily operations</td></tr>`;
    kpiSummary.innerHTML = `<tr><td colspan="4">Unable to load KPI summary</td></tr>`;
    mvpTargetCompliance.innerHTML = `<tr><td colspan="5">Unable to load MVP target compliance</td></tr>`;
    repositoryRollout.innerHTML = `<tr><td colspan="5">Unable to load repository rollout</td></tr>`;
    repositoryInventoryGaps.innerHTML = `<tr><td colspan="5">Unable to load repository inventory gaps</td></tr>`;
    retryCandidates.innerHTML = `<tr><td colspan="5">Unable to load retry candidates</td></tr>`;
    scannerInventory.innerHTML = `<tr><td colspan="5">Unable to load scanner inventory</td></tr>`;
    exceptionReview.innerHTML = `<tr><td colspan="5">Unable to load exceptions</td></tr>`;
    storageCleanup.innerHTML = `<tr><td colspan="5">Unable to load cleanup candidates</td></tr>`;
    operationalWorkload.innerHTML = `<tr><td colspan="4">Unable to load operational workload</td></tr>`;
    repositorySync.innerHTML = `<tr><td colspan="5">Unable to load repository sync coverage</td></tr>`;
    applicationDetection.innerHTML = `<tr><td colspan="5">Unable to load application detection coverage</td></tr>`;
    scheduledScanCoverage.innerHTML = `<tr><td colspan="5">Unable to load scheduled scan coverage</td></tr>`;
    dailyScanSlo.innerHTML = `<tr><td colspan="5">Unable to load daily scan SLO</td></tr>`;
    resolutionCandidates.innerHTML = `<tr><td colspan="5">Unable to load resolution candidates</td></tr>`;
    backupReadiness.innerHTML = `<tr><td colspan="4">Unable to load backup readiness</td></tr>`;
    notificationSlo.innerHTML = `<tr><td colspan="5">Unable to load notification SLO</td></tr>`;
    remediationPrs.innerHTML = `<tr><td colspan="5">Unable to load PR/CI status</td></tr>`;
    fixableGaps.innerHTML = `<tr><td colspan="5">Unable to load fixable gaps</td></tr>`;
    prCiFailures.innerHTML = `<tr><td colspan="5">Unable to load PR CI failures</td></tr>`;
    issueCreationSlo.innerHTML = `<tr><td colspan="5">Unable to load issue creation SLO</td></tr>`;
    autoResolutionEvidence.innerHTML = `<tr><td colspan="5">Unable to load auto-resolution evidence</td></tr>`;
    remediationBacklog.innerHTML = `<tr><td colspan="5">Unable to load remediation backlog</td></tr>`;
    remediationRescans.innerHTML = `<tr><td colspan="5">Unable to load remediation rescans</td></tr>`;
    weeklyReview.innerHTML = `<tr><td colspan="4">Unable to load weekly review</td></tr>`;
    efficiencyKpis.innerHTML = `<tr><td colspan="4">Unable to load efficiency KPIs</td></tr>`;
    manualActions.innerHTML = `<tr><td colspan="5">Unable to load manual actions</td></tr>`;
    ownershipReview.innerHTML = `<tr><td colspan="5">Unable to load ownership review</td></tr>`;
    exposureReview.innerHTML = `<tr><td colspan="5">Unable to load exposure review</td></tr>`;
    autoMergeScope.innerHTML = `<tr><td colspan="5">Unable to load auto-merge scope</td></tr>`;
    dataProtection.innerHTML = `<tr><td colspan="5">Unable to load data protection</td></tr>`;
    retentionReview.innerHTML = `<tr><td colspan="4">Unable to load retention review</td></tr>`;
    artifactSbomCoverage.innerHTML = `<tr><td colspan="5">Unable to load artifact SBOM coverage</td></tr>`;
    licenseReview.innerHTML = `<tr><td colspan="5">Unable to load license review</td></tr>`;
    securityFindings.innerHTML = `<tr><td colspan="5">Unable to load security findings</td></tr>`;
    duplicateReview.innerHTML = `<tr><td colspan="5">Unable to load duplicate review</td></tr>`;
    reopenRisk.innerHTML = `<tr><td colspan="5">Unable to load reopen risk</td></tr>`;
    qualityKpis.innerHTML = `<tr><td colspan="4">Unable to load quality KPIs</td></tr>`;
    scannerVersions.innerHTML = `<tr><td colspan="5">Unable to load scanner versions</td></tr>`;
    runtimeEol.innerHTML = `<tr><td colspan="5">Unable to load runtime EOL review</td></tr>`;
    auditReview.innerHTML = `<tr><td colspan="5">Unable to load audit review</td></tr>`;
    rbacReview.innerHTML = `<tr><td colspan="4">Unable to load RBAC review</td></tr>`;
    restoreReadiness.innerHTML = `<tr><td colspan="4">Unable to load restore readiness</td></tr>`;
    riskAcceptance.innerHTML = `<tr><td colspan="5">Unable to load risk acceptance review</td></tr>`;
    rolloutGaps.innerHTML = `<tr><td colspan="5">Unable to load rollout gaps</td></tr>`;
    githubHealth.innerHTML = `<tr><td colspan="4">Unable to load GitHub integration health</td></tr>`;
    webhookIntake.innerHTML = `<tr><td colspan="5">Unable to load webhook intake</td></tr>`;
    scannerFailures.innerHTML = `<tr><td colspan="5">Unable to load scanner failures</td></tr>`;
    dependencyUpdates.innerHTML = `<tr><td colspan="5">Unable to load dependency updates</td></tr>`;
    failureSignals.innerHTML = `<tr><td colspan="5">Unable to load failure signals</td></tr>`;
    isolatedSafeguards.innerHTML = `<tr><td colspan="5">Unable to load isolated safeguards</td></tr>`;
    isolatedScanHealth.innerHTML = `<tr><td colspan="5">Unable to load isolated scan health</td></tr>`;
    secretsReview.innerHTML = `<tr><td colspan="5">Unable to load secrets review</td></tr>`;
    workerPosture.innerHTML = `<tr><td colspan="4">Unable to load worker posture</td></tr>`;
    exploitIntel.innerHTML = `<tr><td colspan="5">Unable to load exploit intelligence</td></tr>`;
    quarterlyReview.innerHTML = `<tr><td colspan="4">Unable to load quarterly review</td></tr>`;
    rolloutBaseline.innerHTML = `<tr><td colspan="6">Unable to load rollout baseline</td></tr>`;
    applicationReadiness.innerHTML = `<tr><td colspan="5">Unable to load application readiness</td></tr>`;
    scanTargets.innerHTML = `<tr><td colspan="5">Unable to load scan targets</td></tr>`;
    remediationCoverage.innerHTML = `<tr><td colspan="5">Unable to load remediation coverage</td></tr>`;
    resolutionVerification.innerHTML = `<tr><td colspan="5">Unable to load resolution verification</td></tr>`;
    monthlyReview.innerHTML = `<tr><td colspan="4">Unable to load monthly review</td></tr>`;
    operationalLoadKpis.innerHTML = `<tr><td colspan="4">Unable to load operational load KPIs</td></tr>`;
    remediationAging.innerHTML = `<tr><td colspan="5">Unable to load remediation aging</td></tr>`;
    toolchainPosture.innerHTML = `<tr><td colspan="4">Unable to load toolchain posture</td></tr>`;
    notificationDigest.innerHTML = `<tr><td colspan="5">Unable to load notification digest readiness</td></tr>`;
    phaseReadiness.innerHTML = `<tr><td colspan="5">Unable to load phase readiness</td></tr>`;
    findingLifecycle.innerHTML = `<tr><td colspan="5">Unable to load finding lifecycle review</td></tr>`;
    vexInvalidation.innerHTML = `<tr><td colspan="5">Unable to load VEX invalidation candidates</td></tr>`;
    repositoryDrift.innerHTML = `<tr><td colspan="5">Unable to load repository drift</td></tr>`;
    autoMergePilot.innerHTML = `<tr><td colspan="5">Unable to load auto-merge pilot readiness</td></tr>`;
    controlEvidence.innerHTML = `<tr><td colspan="5">Unable to load control evidence</td></tr>`;
    findingEvidenceGaps.innerHTML = `<tr><td colspan="5">Unable to load finding evidence gaps</td></tr>`;
    jobBacklog.innerHTML = `<tr><td colspan="5">Unable to load job backlog</td></tr>`;
    auditEvidenceGaps.innerHTML = `<tr><td colspan="5">Unable to load audit evidence gaps</td></tr>`;
    scanEvidenceQuality.innerHTML = `<tr><td colspan="5">Unable to load scan evidence quality</td></tr>`;
    automationGuardrails.innerHTML = `<tr><td colspan="5">Unable to load automation guardrails</td></tr>`;
    policyViolations.innerHTML = `<tr><td colspan="5">Unable to load policy violations</td></tr>`;
    dryRunDecisions.innerHTML = `<tr><td colspan="5">Unable to load dry-run decisions</td></tr>`;
    rollbackReadiness.innerHTML = `<tr><td colspan="5">Unable to load rollback readiness</td></tr>`;
    automationSuppressions.innerHTML = `<tr><td colspan="5">Unable to load automation suppressions</td></tr>`;
    rolloutWaves.innerHTML = `<tr><td colspan="5">Unable to load rollout waves</td></tr>`;
    mvpTargets.innerHTML = `<tr><td colspan="5">Unable to load MVP targets</td></tr>`;
    kpiEvidence.innerHTML = `<tr><td colspan="5">Unable to load KPI evidence</td></tr>`;
    efficiencyTimeline.innerHTML = `<tr><td colspan="5">Unable to load efficiency timeline</td></tr>`;
    initialInventory.innerHTML = `<tr><td colspan="5">Unable to load initial inventory</td></tr>`;
    queuePressure.innerHTML = `<tr><td colspan="5">Unable to load queue pressure</td></tr>`;
    schedulerDrift.innerHTML = `<tr><td colspan="5">Unable to load scheduler drift</td></tr>`;
    storagePressure.innerHTML = `<tr><td colspan="5">Unable to load storage pressure</td></tr>`;
    githubSyncLag.innerHTML = `<tr><td colspan="5">Unable to load GitHub sync lag</td></tr>`;
    credentialFailures.innerHTML = `<tr><td colspan="5">Unable to load credential failures</td></tr>`;
  }
}

document.querySelector("#refresh").addEventListener("click", refresh);
findings.addEventListener("click", async (event) => {
  if (!(event.target instanceof Element)) {
    return;
  }
  const button = event.target.closest("[data-issue-finding]");
  if (!button) {
    return;
  }
  button.disabled = true;
  button.textContent = "Queued";
  try {
    await postJson(`/findings/${button.dataset.issueFinding}/github-issue`);
    await refresh();
  } catch (error) {
    button.disabled = false;
    button.textContent = "Queue";
    metrics.innerHTML = `<article class="metric danger"><strong>!</strong><span>${escapeHtml(error.message)}</span></article>`;
  }
});
refresh();
