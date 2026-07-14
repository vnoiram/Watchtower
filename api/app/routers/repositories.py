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

