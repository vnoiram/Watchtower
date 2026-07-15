from fastapi import FastAPI

from api.app.errors import install_exception_handlers
from api.app.routers import (
    applications,
    components,
    dashboard,
    findings,
    github,
    job_health,
    jobs,
    maintenance,
    notifications,
    remediation,
    remediation_actions,
    repositories,
    sbom_coverage,
    sboms,
    scan_health,
    scans,
    technologies,
    vex,
    vulnerabilities,
)

app = FastAPI(title="Watchtower Maintenance API", version="0.1.0")
install_exception_handlers(app)

api_prefix = "/v1"
app.include_router(repositories.router, prefix=api_prefix)
app.include_router(applications.router, prefix=api_prefix)
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
app.include_router(notifications.router, prefix=api_prefix)
app.include_router(dashboard.router, prefix=api_prefix)
app.include_router(github.router, prefix=api_prefix)
app.include_router(vex.router, prefix=api_prefix)
app.include_router(scan_health.router, prefix=api_prefix)
app.include_router(maintenance.router, prefix=api_prefix)
app.include_router(job_health.router, prefix=api_prefix)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}
