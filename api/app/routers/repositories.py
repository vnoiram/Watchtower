from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.database import get_db
from api.app.deps import Principal, get_principal, require_role
from api.app.pagination import apply_cursor, encode_cursor
from api.app.services.audit import audit
from api.app.services.jobs import enqueue_job

router = APIRouter(prefix="/repositories", tags=["repositories"])


@router.post("", response_model=schemas.RepositoryOut)
def create_repository(
    payload: schemas.RepositoryCreate,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_role("operator")),
):
    repo = models.Repository(**payload.model_dump(), archived=False, fork=False, topics=[])
    db.add(repo)
    db.flush()
    audit(db, principal.actor, principal.role, "repository.create", "repository", str(repo.id))
    db.commit()
    db.refresh(repo)
    return repo


@router.post("/{repository_id}/scan", response_model=schemas.JobOut)
def enqueue_repository_scan(
    repository_id: str,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_role("operator")),
):
    job = enqueue_job(db, models.JobType.scan, payload={"repository_id": repository_id})
    audit(db, principal.actor, principal.role, "repository.scan.enqueue", "repository", repository_id, job_id=str(job.id))
    db.commit()
    db.refresh(job)
    return job


@router.get("", response_model=schemas.CursorPage)
def list_repositories(
    cursor: str | None = None,
    limit: int = 50,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    stmt = apply_cursor(select(models.Repository), models.Repository, cursor, limit)
    rows = list(db.execute(stmt).scalars())
    next_cursor = None
    if len(rows) > limit:
        last = rows[limit - 1]
        next_cursor = encode_cursor(last.created_at, last.id)
        rows = rows[:limit]
    return schemas.CursorPage(items=[schemas.RepositoryOut.model_validate(row).model_dump(mode="json") for row in rows], next_cursor=next_cursor)


@router.get("/classification-review", response_model=schemas.CursorPage)
def list_repository_classification_review(
    limit: int = 50,
    gap_type: str | None = None,
    provider: models.RepositoryProvider | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = repository_classification_review_items(db)
    if gap_type:
        items = [item for item in items if item["gap_type"] == gap_type]
    if provider:
        items = [item for item in items if item["provider"] == provider.value]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


def repository_classification_gap_count(db: Session) -> int:
    return len(repository_classification_review_items(db))


def repository_classification_review_items(db: Session) -> list[dict]:
    applications_by_repository: dict = {}
    for application in db.scalars(select(models.Application)):
        applications_by_repository.setdefault(application.repository_id, []).append(application)
    items = []
    for repository in db.scalars(select(models.Repository).order_by(models.Repository.owner.asc(), models.Repository.name.asc())):
        applications = applications_by_repository.get(repository.id, [])
        if not repository.visibility:
            items.append(_classification_item("missing_visibility", repository, None, "Repository visibility is not recorded"))
        if repository.visibility and _classification_mismatch(repository):
            items.append(_classification_item("classification_mismatch", repository, None, "Visibility and source classification look inconsistent"))
        if repository.source_classification == models.SourceClassification.isolated and repository.provider != models.RepositoryProvider.isolated:
            items.append(_classification_item("isolated_provider_mismatch", repository, None, "Isolated classification should use the isolated provider"))
        if repository.provider == models.RepositoryProvider.isolated and repository.source_classification != models.SourceClassification.isolated:
            items.append(_classification_item("isolated_provider_mismatch", repository, None, "Isolated provider should use isolated classification"))
        if repository.archived:
            for application in applications:
                if application.lifecycle not in {models.Lifecycle.archived, models.Lifecycle.deprecated}:
                    items.append(_classification_item("archived_active_app", repository, application, "Archived repository has an active application record"))
    return items


def _classification_mismatch(repository: models.Repository) -> bool:
    visibility = (repository.visibility or "").lower()
    if visibility == "public" and repository.source_classification in {
        models.SourceClassification.private,
        models.SourceClassification.restricted,
        models.SourceClassification.isolated,
    }:
        return True
    if visibility in {"private", "internal"} and repository.source_classification == models.SourceClassification.public:
        return True
    return False


def _classification_item(
    gap_type: str,
    repository: models.Repository,
    application: models.Application | None,
    detail: str,
) -> dict:
    return schemas.RepositoryClassificationReviewOut(
        gap_type=gap_type,
        repository_id=repository.id,
        repository_owner=repository.owner,
        repository_name=repository.name,
        provider=repository.provider,
        visibility=repository.visibility,
        source_classification=repository.source_classification,
        archived=repository.archived,
        fork=repository.fork,
        application_id=application.id if application else None,
        application_name=application.name if application else None,
        detail=detail,
    ).model_dump(mode="json")
