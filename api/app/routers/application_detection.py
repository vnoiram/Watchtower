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
