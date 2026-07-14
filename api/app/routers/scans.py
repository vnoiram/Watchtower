from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.database import get_db
from api.app.deps import Principal, get_principal, require_role
from api.app.pagination import apply_cursor, encode_cursor
from api.app.services.audit import audit

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("", response_model=schemas.ScanOut)
def create_scan(
    payload: schemas.ScanCreate,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_role("operator")),
):
    scan = models.Scan(**payload.model_dump())
    db.add(scan)
    db.flush()
    audit(db, principal.actor, principal.role, "scan.create", "scan", str(scan.id))
    db.commit()
    db.refresh(scan)
    return scan


@router.get("", response_model=schemas.CursorPage)
def list_scans(
    cursor: str | None = None,
    limit: int = 50,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    stmt = apply_cursor(select(models.Scan), models.Scan, cursor, limit)
    rows = list(db.execute(stmt).scalars())
    next_cursor = None
    if len(rows) > limit:
        last = rows[limit - 1]
        next_cursor = encode_cursor(last.created_at, last.id)
        rows = rows[:limit]
    return schemas.CursorPage(items=[schemas.ScanOut.model_validate(row).model_dump(mode="json") for row in rows], next_cursor=next_cursor)

