from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.database import get_db
from api.app.deps import Principal, get_principal

router = APIRouter(prefix="/application-detection", tags=["application-detection"])


@router.get("", response_model=schemas.CursorPage)
def list_application_detection(
    limit: int = 50,
    issue_type: str | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = []
    if issue_type in {None, "missing_application"}:
        items.extend(_repositories_without_applications(db))
    if issue_type in {None, "unknown_application_type", "missing_technology"}:
        items.extend(_application_issues(db, issue_type))
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/input-coverage", response_model=schemas.CursorPage)
def list_application_input_coverage(
    limit: int = 50,
    gap_type: str | None = None,
    ecosystem: str | None = None,
    repository_id: UUID | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = application_input_coverage_items(db)
    if gap_type:
        items = [item for item in items if item["gap_type"] == gap_type]
    if ecosystem:
        items = [item for item in items if item["ecosystem"] == ecosystem]
    if repository_id:
        items = [item for item in items if item["repository_id"] == str(repository_id)]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/container-inputs", response_model=schemas.CursorPage)
def list_container_input_coverage(
    limit: int = 50,
    gap_type: str | None = None,
    repository_id: UUID | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = container_input_coverage_items(db)
    if gap_type:
        items = [item for item in items if item["gap_type"] == gap_type]
    if repository_id:
        items = [item for item in items if item["repository_id"] == str(repository_id)]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


def application_input_coverage_count(db: Session) -> int:
    return len(application_input_coverage_items(db))


def container_input_coverage_count(db: Session) -> int:
    return len(container_input_coverage_items(db))


def application_input_coverage_items(db: Session) -> list[dict]:
    rows = _application_rows(db)
    application_ids = [application.id for application, _ in rows]
    technologies = _technologies_by_application(db, application_ids)
    latest_scans = _latest_scans_by_application(db, application_ids)
    items = []
    for application, repository in rows:
        app_technologies = technologies.get(application.id, [])
        latest_scan = latest_scans.get(application.id)
        haystack = _application_evidence_text(app_technologies, latest_scan.result_summary if latest_scan else None)
        sources = sorted({technology.detection_source for technology in app_technologies if technology.detection_source})
        package_ecosystems = sorted(
            {
                value
                for value in (_technology_ecosystem(technology) for technology in app_technologies)
                if value is not None
            }
        )
        ecosystem = package_ecosystems[0] if package_ecosystems else None
        context = (application, repository, ecosystem, app_technologies, sources)
        if not _contains_any(haystack, _MANIFEST_TOKENS):
            items.append(_input_coverage_item("missing_manifest", *context, "No manifest detection evidence recorded"))
        if ecosystem and not _contains_any(haystack, _LOCKFILE_TOKENS):
            items.append(_input_coverage_item("missing_lockfile", *context, "No lockfile detection evidence recorded"))
        if not ecosystem:
            items.append(_input_coverage_item("unknown_package_manager", *context, "No package manager or ecosystem detection evidence recorded"))
        if _contains_any(haystack, {"monorepo", "workspace", "workspaces"}) and application.path == ".":
            items.append(_input_coverage_item("monorepo_unclassified", *context, "Monorepo evidence exists but application path is repository root"))
    return items


def container_input_coverage_items(db: Session) -> list[dict]:
    rows = _application_rows(db)
    application_ids = [application.id for application, _ in rows]
    technologies = _technologies_by_application(db, application_ids)
    latest_scans = _latest_scans_by_application(db, application_ids)
    items = []
    for application, repository in rows:
        latest_scan = latest_scans.get(application.id)
        app_technologies = technologies.get(application.id, [])
        summary = latest_scan.result_summary if latest_scan else {}
        haystack = _application_evidence_text(app_technologies, summary)
        artifact_types = _artifact_types(summary)
        has_container_input = _contains_any(haystack, _CONTAINER_INPUT_TOKENS)
        has_container_artifact = any(_is_container_artifact(artifact_type) for artifact_type in artifact_types)
        context = (application, repository, latest_scan, has_container_input, has_container_artifact, artifact_types)
        if has_container_input and application.application_type != models.ApplicationType.container:
            items.append(_container_input_item("dockerfile_without_container_app", *context, "Container input detected on non-container application"))
        if application.application_type == models.ApplicationType.container and not has_container_input:
            items.append(_container_input_item("container_app_without_dockerfile", *context, "Container application has no Dockerfile or container manifest evidence"))
        if has_container_input and not has_container_artifact:
            items.append(_container_input_item("container_input_without_container_scan", *context, "Container input has no stored container scan artifact"))
    return items


def _repositories_without_applications(db: Session) -> list[dict]:
    application_exists = (
        select(models.Application.id)
        .where(models.Application.repository_id == models.Repository.id)
        .exists()
    )
    stmt = (
        select(models.Repository)
        .where(~application_exists)
        .order_by(models.Repository.owner.asc(), models.Repository.name.asc())
    )
    return [
        schemas.ApplicationDetectionOut(
            issue_type="missing_application",
            repository_id=repository.id,
            repository_owner=repository.owner,
            repository_name=repository.name,
            detail="Repository has no detected applications",
        ).model_dump(mode="json")
        for repository in db.execute(stmt).scalars()
    ]


def _application_issues(db: Session, issue_type: str | None) -> list[dict]:
    stmt = (
        select(
            models.Application,
            models.Repository,
            func.count(models.Technology.id).label("technology_count"),
        )
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
        .outerjoin(models.Technology, models.Technology.application_id == models.Application.id)
        .group_by(models.Application.id, models.Repository.id)
        .order_by(models.Repository.owner.asc(), models.Repository.name.asc(), models.Application.name.asc())
    )
    items = []
    for application, repository, technology_count in db.execute(stmt):
        if issue_type in {None, "unknown_application_type"} and (
            application.application_type == models.ApplicationType.unknown
        ):
            items.append(_application_issue("unknown_application_type", application, repository, technology_count))
        if issue_type in {None, "missing_technology"} and technology_count == 0:
            items.append(_application_issue("missing_technology", application, repository, technology_count))
    return items


def _application_issue(
    issue_type: str,
    application: models.Application,
    repository: models.Repository,
    technology_count: int,
) -> dict:
    detail = (
        "Application type is unknown"
        if issue_type == "unknown_application_type"
        else "Application has no detected technologies"
    )
    return schemas.ApplicationDetectionOut(
        issue_type=issue_type,
        repository_id=repository.id,
        repository_owner=repository.owner,
        repository_name=repository.name,
        application_id=application.id,
        application_name=application.name,
        application_path=application.path,
        application_type=application.application_type,
        technology_count=technology_count,
        detail=detail,
    ).model_dump(mode="json")


_MANIFEST_TOKENS = {
    "package.json",
    "pyproject.toml",
    "requirements.txt",
    "pom.xml",
    "build.gradle",
    "go.mod",
    "cargo.toml",
    "gemfile",
    "composer.json",
    "manifest",
}
_LOCKFILE_TOKENS = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "pipfile.lock",
    "go.sum",
    "cargo.lock",
    "gemfile.lock",
    "composer.lock",
    "lockfile",
}
_CONTAINER_INPUT_TOKENS = {"dockerfile", "containerfile", "compose.yaml", "compose.yml", "container manifest"}
_PACKAGE_MANAGER_TOKENS = {
    "npm",
    "yarn",
    "pnpm",
    "pip",
    "poetry",
    "maven",
    "gradle",
    "go",
    "cargo",
    "bundler",
    "composer",
}


def _application_rows(db: Session) -> list[tuple[models.Application, models.Repository]]:
    return list(
        db.execute(
            select(models.Application, models.Repository)
            .join(models.Repository, models.Application.repository_id == models.Repository.id)
            .order_by(models.Repository.owner.asc(), models.Repository.name.asc(), models.Application.name.asc())
        )
    )


def _technologies_by_application(db: Session, application_ids: list[UUID]) -> dict[UUID, list[models.Technology]]:
    if not application_ids:
        return {}
    technologies = db.scalars(
        select(models.Technology)
        .where(models.Technology.application_id.in_(application_ids))
        .order_by(models.Technology.application_id.asc(), models.Technology.name.asc())
    )
    by_application: dict[UUID, list[models.Technology]] = {}
    for technology in technologies:
        by_application.setdefault(technology.application_id, []).append(technology)
    return by_application


def _latest_scans_by_application(db: Session, application_ids: list[UUID]) -> dict[UUID, models.Scan]:
    if not application_ids:
        return {}
    scans = db.scalars(
        select(models.Scan)
        .where(models.Scan.application_id.in_(application_ids))
        .order_by(models.Scan.application_id.asc(), models.Scan.created_at.desc(), models.Scan.id.desc())
    )
    by_application: dict[UUID, models.Scan] = {}
    for scan in scans:
        by_application.setdefault(scan.application_id, scan)
    return by_application


def _application_evidence_text(technologies: list[models.Technology], summary: dict[str, Any] | None) -> str:
    values: list[Any] = []
    for technology in technologies:
        values.extend([technology.category, technology.name, technology.detection_source])
    values.append(summary or {})
    return _flatten_text(values)


def _flatten_text(value: Any) -> str:
    if isinstance(value, dict):
        return " ".join([str(key).lower() for key in value] + [_flatten_text(item) for item in value.values()])
    if isinstance(value, list | tuple | set):
        return " ".join(_flatten_text(item) for item in value)
    return str(value or "").lower()


def _contains_any(text: str, tokens: set[str]) -> bool:
    return any(token in text for token in tokens)


def _technology_ecosystem(technology: models.Technology) -> str | None:
    values = [technology.category, technology.name, technology.detection_source]
    text = _flatten_text(values)
    for token in sorted(_PACKAGE_MANAGER_TOKENS):
        if token in text:
            return token
    if "package-manager" in text or "ecosystem" in text:
        return technology.name.lower()
    return None


def _artifact_types(summary: dict[str, Any] | None) -> list[str]:
    artifacts = (summary or {}).get("artifacts") if isinstance(summary, dict) else None
    if isinstance(artifacts, dict):
        return sorted(str(key) for key in artifacts)
    if isinstance(artifacts, list):
        return sorted(str(item.get("type") or item.get("artifact_type")) for item in artifacts if isinstance(item, dict))
    return []


def _is_container_artifact(artifact_type: str) -> bool:
    text = artifact_type.lower()
    return "container" in text or "image" in text or "docker" in text


def _input_coverage_item(
    gap_type: str,
    application: models.Application,
    repository: models.Repository,
    ecosystem: str | None,
    technologies: list[models.Technology],
    sources: list[str],
    detail: str,
) -> dict:
    return schemas.ApplicationInputCoverageOut(
        gap_type=gap_type,
        repository_id=repository.id,
        repository_owner=repository.owner,
        repository_name=repository.name,
        application_id=application.id,
        application_name=application.name,
        application_path=application.path,
        ecosystem=ecosystem,
        technology_count=len(technologies),
        detected_sources=sources,
        detail=detail,
    ).model_dump(mode="json")


def _container_input_item(
    gap_type: str,
    application: models.Application,
    repository: models.Repository,
    latest_scan: models.Scan | None,
    has_container_input: bool,
    has_container_artifact: bool,
    artifact_types: list[str],
    detail: str,
) -> dict:
    return schemas.ContainerInputCoverageOut(
        gap_type=gap_type,
        repository_id=repository.id,
        repository_owner=repository.owner,
        repository_name=repository.name,
        application_id=application.id,
        application_name=application.name,
        application_path=application.path,
        application_type=application.application_type,
        latest_scan_id=latest_scan.id if latest_scan else None,
        latest_scan_status=latest_scan.status if latest_scan else None,
        has_container_input=has_container_input,
        has_container_artifact=has_container_artifact,
        artifact_types=artifact_types,
        detail=detail,
    ).model_dump(mode="json")
