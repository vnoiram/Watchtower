const apiBase = "http://localhost:8000/v1";
const tokenInput = document.querySelector("#token");
const metrics = document.querySelector("#metrics");
const findings = document.querySelector("#findings");

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
  const rows = page.items || [];
  findings.innerHTML = rows.length
    ? rows.map((item) => `<tr><td>${item.severity}</td><td>${item.status}</td><td>${item.risk_score}</td><td>${item.id}</td></tr>`).join("")
    : `<tr><td colspan="4">No findings</td></tr>`;
}

async function refresh() {
  metrics.innerHTML = "";
  findings.innerHTML = `<tr><td colspan="4">Loading</td></tr>`;
  try {
    const [summary, findingPage] = await Promise.all([loadJson("/dashboard/summary"), loadJson("/findings?limit=10")]);
    renderMetrics(summary);
    renderFindings(findingPage);
  } catch (error) {
    metrics.innerHTML = `<article class="metric danger"><strong>!</strong><span>${error.message}</span></article>`;
    findings.innerHTML = `<tr><td colspan="4">Unable to load findings</td></tr>`;
  }
}

document.querySelector("#refresh").addEventListener("click", refresh);
refresh();

