from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.database import get_db
from api.app.deps import Principal, require_role
from api.app.services.audit import audit

router = APIRouter(prefix="/vex", tags=["vex"])


@router.post("", response_model=schemas.VexOut)
def create_vex_statement(
    payload: schemas.VexCreate,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_role("operator")),
):
    vex = models.VexStatement(**payload.model_dump())
    db.add(vex)
    db.flush()
    audit(db, principal.actor, principal.role, "vex.create", "vex", str(vex.id), finding_id=str(vex.finding_id))
    db.commit()
    db.refresh(vex)
    return vex

