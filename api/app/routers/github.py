from fastapi import APIRouter, Depends, Header, Request
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.config import Settings, get_settings
from api.app.database import get_db
from api.app.deps import Principal, require_role
from api.app.errors import problem
from api.app.services.github import verify_webhook_signature
from api.app.services.jobs import enqueue_job

router = APIRouter(prefix="/github", tags=["github"])


@router.post("/webhook", response_model=schemas.JobOut)
async def github_webhook(
    request: Request,
    x_hub_signature_256: str | None = Header(default=None),
    x_github_event: str | None = Header(default=None),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    body = await request.body()
    if not settings.github_webhook_secret:
        raise problem(500, "GitHub webhook secret is not configured")
    if not verify_webhook_signature(settings.github_webhook_secret, body, x_hub_signature_256):
        raise problem(401, "Invalid webhook signature")
    job = enqueue_job(db, models.JobType.repository_sync, payload={"event": x_github_event, "body": body.decode("utf-8")})
    db.commit()
    db.refresh(job)
    return job


@router.post("/sync", response_model=schemas.JobOut)
def enqueue_github_sync(
    owner: str,
    db: Session = Depends(get_db),
    _: Principal = Depends(require_role("operator")),
):
    job = enqueue_job(db, models.JobType.repository_sync, payload={"owner": owner})
    db.commit()
    db.refresh(job)
    return job

