from fastapi import FastAPI

from api.app.errors import install_exception_handlers
from api.app.routers import (
    ai_fix,
    application_detection,
    applications,
    artifacts,
    audit_logs,
    auto_merge,
    components,
    dashboard,
    exceptions,
    findings,
    github,
    isolated_lane,
    job_health,
    jobs,
    kpis,
    maintenance,
    notifications,
    operations,
    remediation,
    remediation_actions,
    repositories,
    repository_sync,
    rollout,
    scheduled_scan_coverage,
    sbom_coverage,
    sboms,
    scan_health,
    scans,
    scanner_inventory,
    sla,
    storage,
    technologies,
    vex,
    vulnerabilities,
)

app = FastAPI(title="Watchtower Maintenance API", version="0.1.0")
install_exception_handlers(app)

api_prefix = "/v1"
app.include_router(repositories.router, prefix=api_prefix)
app.include_router(applications.router, prefix=api_prefix)
app.include_router(application_detection.router, prefix=api_prefix)
app.include_router(artifacts.router, prefix=api_prefix)
app.include_router(audit_logs.router, prefix=api_prefix)
app.include_router(jobs.router, prefix=api_prefix)
app.include_router(scans.router, prefix=api_prefix)
app.include_router(findings.router, prefix=api_prefix)
app.include_router(technologies.router, prefix=api_prefix)
app.include_router(sboms.router, prefix=api_prefix)
app.include_router(sbom_coverage.router, prefix=api_prefix)
app.include_router(components.router, prefix=api_prefix)
app.include_router(vulnerabilities.router, prefix=api_prefix)
app.include_router(remediation_actions.router, prefix=api_prefix)
app.include_router(remediation.router, prefix=api_prefix)
app.include_router(ai_fix.router, prefix=api_prefix)
app.include_router(auto_merge.router, prefix=api_prefix)
app.include_router(notifications.router, prefix=api_prefix)
app.include_router(dashboard.router, prefix=api_prefix)
app.include_router(github.router, prefix=api_prefix)
app.include_router(vex.router, prefix=api_prefix)
app.include_router(scan_health.router, prefix=api_prefix)
app.include_router(scanner_inventory.router, prefix=api_prefix)
app.include_router(maintenance.router, prefix=api_prefix)
app.include_router(job_health.router, prefix=api_prefix)
app.include_router(exceptions.router, prefix=api_prefix)
app.include_router(storage.router, prefix=api_prefix)
app.include_router(repository_sync.router, prefix=api_prefix)
app.include_router(scheduled_scan_coverage.router, prefix=api_prefix)
app.include_router(isolated_lane.router, prefix=api_prefix)
app.include_router(sla.router, prefix=api_prefix)
app.include_router(kpis.router, prefix=api_prefix)
app.include_router(operations.router, prefix=api_prefix)
app.include_router(rollout.router, prefix=api_prefix)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}
