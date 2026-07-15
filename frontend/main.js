const apiBase = "http://localhost:8000/v1";
const tokenInput = document.querySelector("#token");
const metrics = document.querySelector("#metrics");
const findings = document.querySelector("#findings");
const applications = document.querySelector("#applications");

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
            `<tr><td>${escapeHtml(item.severity)}</td><td>${escapeHtml(item.status)}</td><td>${escapeHtml(item.risk_score)}</td><td>${escapeHtml(item.id)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="4">No findings</td></tr>`;
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

async function refresh() {
  metrics.innerHTML = "";
  findings.innerHTML = `<tr><td colspan="4">Loading</td></tr>`;
  applications.innerHTML = `<tr><td colspan="5">Loading</td></tr>`;
  try {
    const [summary, criticalFindings, highFindings, applicationPage] = await Promise.all([
      loadJson("/dashboard/summary"),
      loadJson("/findings?status=open&severity=critical&limit=10"),
      loadJson("/findings?status=open&severity=high&limit=10"),
      loadJson("/applications?limit=10"),
    ]);
    renderMetrics(summary);
    renderFindings({ items: [...(criticalFindings.items || []), ...(highFindings.items || [])] });
    renderApplications(applicationPage);
  } catch (error) {
    metrics.innerHTML = `<article class="metric danger"><strong>!</strong><span>${error.message}</span></article>`;
    findings.innerHTML = `<tr><td colspan="4">Unable to load findings</td></tr>`;
    applications.innerHTML = `<tr><td colspan="5">Unable to load applications</td></tr>`;
  }
}

document.querySelector("#refresh").addEventListener("click", refresh);
refresh();
