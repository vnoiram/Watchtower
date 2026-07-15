const apiBase = "http://localhost:8000/v1";
const tokenInput = document.querySelector("#token");
const metrics = document.querySelector("#metrics");
const findings = document.querySelector("#findings");
const applications = document.querySelector("#applications");
const technologies = document.querySelector("#technologies");
const sboms = document.querySelector("#sboms");
const components = document.querySelector("#components");
const vulnerabilities = document.querySelector("#vulnerabilities");
const remediationActions = document.querySelector("#remediation-actions");

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

async function refresh() {
  metrics.innerHTML = "";
  findings.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  applications.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  technologies.innerHTML = `<tr><td colspan="4">Loading</td></tr>`;
  sboms.innerHTML = `<tr><td colspan="4">Loading</td></tr>`;
  components.innerHTML = `<tr><td colspan="4">Loading</td></tr>`;
  vulnerabilities.innerHTML = `<tr><td colspan="4">Loading</td></tr>`;
  remediationActions.innerHTML = `<tr><td colspan="4">Loading</td></tr>`;
  try {
    const [
      summary,
      criticalFindings,
      highFindings,
      applicationPage,
      technologyPage,
      sbomPage,
      componentPage,
      vulnerabilityPage,
      remediationActionPage,
    ] = await Promise.all([
      loadJson("/dashboard/summary"),
      loadJson("/findings?status=open&severity=critical&limit=10"),
      loadJson("/findings?status=open&severity=high&limit=10"),
      loadJson("/applications?limit=10"),
      loadJson("/technologies?limit=10"),
      loadJson("/sboms?active=true&limit=10"),
      loadJson("/components?limit=10"),
      loadJson("/vulnerabilities?limit=10"),
      loadJson("/remediation-actions?limit=10"),
    ]);
    renderMetrics(summary);
    renderFindings({ items: [...(criticalFindings.items || []), ...(highFindings.items || [])] });
    renderApplications(applicationPage);
    renderTechnologies(technologyPage);
    renderSboms(sbomPage);
    renderComponents(componentPage);
    renderVulnerabilities(vulnerabilityPage);
    renderRemediationActions(remediationActionPage);
  } catch (error) {
    metrics.innerHTML = `<article class="metric danger"><strong>!</strong><span>${error.message}</span></article>`;
    findings.innerHTML = `<tr><td colspan="5">Unable to load findings</td></tr>`;
    applications.innerHTML = `<tr><td colspan="5">Unable to load applications</td></tr>`;
    technologies.innerHTML = `<tr><td colspan="4">Unable to load technologies</td></tr>`;
    sboms.innerHTML = `<tr><td colspan="4">Unable to load SBOMs</td></tr>`;
    components.innerHTML = `<tr><td colspan="4">Unable to load components</td></tr>`;
    vulnerabilities.innerHTML = `<tr><td colspan="4">Unable to load vulnerabilities</td></tr>`;
    remediationActions.innerHTML = `<tr><td colspan="4">Unable to load remediation actions</td></tr>`;
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
