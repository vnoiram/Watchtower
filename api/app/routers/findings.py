from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.database import get_db
from api.app.deps import Principal, get_principal
from api.app.pagination import apply_cursor, encode_cursor

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("", response_model=schemas.CursorPage)
def list_findings(
    cursor: str | None = None,
    limit: int = 50,
    status: models.FindingStatus | None = None,
    severity: models.Severity | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    stmt = select(models.Finding)
    if status:
        stmt = stmt.where(models.Finding.status == status)
    if severity:
        stmt = stmt.where(models.Finding.severity == severity)
    stmt = apply_cursor(stmt, models.Finding, cursor, limit)
    rows = list(db.execute(stmt).scalars())
    next_cursor = None
    if len(rows) > limit:
        last = rows[limit - 1]
        next_cursor = encode_cursor(last.created_at, last.id)
        rows = rows[:limit]
    return schemas.CursorPage(items=[schemas.FindingOut.model_validate(row).model_dump(mode="json") for row in rows], next_cursor=next_cursor)

