from datetime import timedelta

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from api.app.database import Base
from api.app.models import (
    Application,
    ApplicationType,
    Job,
    JobStatus,
    JobType,
    Repository,
    RepositoryProvider,
    Scan,
    ScanStatus,
    SourceClassification,
    TriggerType,
    now_utc,
)
from api.app.services.scheduler import enqueue_stale_repository_scans


def session_factory() -> sessionmaker[Session]:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def create_repository(
    db: Session,
    name: str,
    *,
    archived: bool = False,
    url: str | None = "https://github.com/local/demo",
    local_path: str | None = None,
) -> Repository:
    repo = Repository(
        provider=RepositoryProvider.github,
        provider_repository_id=name,
        owner="local",
        name=name,
        url=url,
        local_path=local_path,
        source_classification=SourceClassification.private,
        archived=archived,
        fork=False,
        topics=[],
    )
    db.add(repo)
    db.flush()
    return repo


def create_application(db: Session, repo: Repository) -> Application:
    app = Application(
        repository_id=repo.id,
        name=repo.name,
        path=".",
        application_type=ApplicationType.api,
    )
    db.add(app)
    db.flush()
    return app


def create_scan(db: Session, app: Application, *, age_hours: int) -> Scan:
    scan = Scan(
        application_id=app.id,
        trigger_type=TriggerType.manual,
        status=ScanStatus.succeeded,
        created_at=now_utc() - timedelta(hours=age_hours),
    )
    db.add(scan)
    db.flush()
    return scan


def test_enqueue_stale_repository_scans_enqueues_repository_without_scans() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db, "unscanned")
        create_application(db, repo)

        result = enqueue_stale_repository_scans(db)
        db.flush()

        assert result.enqueued_count == 1
        job = db.scalar(select(Job).where(Job.job_type == JobType.scan))
        assert job.repository_id == repo.id
        assert job.payload == {"repository_id": str(repo.id), "trigger_type": "schedule"}


def test_enqueue_stale_repository_scans_skips_recent_scan() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db, "fresh")
        app = create_application(db, repo)
        create_scan(db, app, age_hours=1)

        result = enqueue_stale_repository_scans(db, stale_after_hours=24)

        assert result.enqueued_count == 0
        assert result.fresh_count == 1
        assert db.scalar(select(Job)) is None


def test_enqueue_stale_repository_scans_enqueues_old_scan() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db, "stale")
        app = create_application(db, repo)
        create_scan(db, app, age_hours=25)

        result = enqueue_stale_repository_scans(db, stale_after_hours=24)

        assert result.enqueued_count == 1
        assert result.jobs[0].repository_id == repo.id


def test_enqueue_stale_repository_scans_skips_existing_active_scan_jobs() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        queued_repo = create_repository(db, "queued")
        running_repo = create_repository(db, "running")
        create_application(db, queued_repo)
        create_application(db, running_repo)
        db.add(
            Job(
                job_type=JobType.scan,
                status=JobStatus.queued,
                payload={"repository_id": str(queued_repo.id)},
            )
        )
        db.add(
            Job(
                job_type=JobType.scan,
                status=JobStatus.running,
                repository_id=running_repo.id,
                payload={},
            )
        )
        db.flush()

        result = enqueue_stale_repository_scans(db)

        assert result.enqueued_count == 0
        assert result.already_queued_count == 2


def test_enqueue_stale_repository_scans_allows_completed_scan_jobs() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db, "completed-job")
        create_application(db, repo)
        db.add(
            Job(
                job_type=JobType.scan,
                status=JobStatus.succeeded,
                repository_id=repo.id,
                payload={"repository_id": str(repo.id)},
            )
        )
        db.flush()

        result = enqueue_stale_repository_scans(db)

        assert result.enqueued_count == 1


def test_enqueue_stale_repository_scans_skips_archived_and_missing_source() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        archived = create_repository(db, "archived", archived=True)
        missing_source = create_repository(db, "missing-source", url=None, local_path=None)
        create_application(db, archived)
        create_application(db, missing_source)

        result = enqueue_stale_repository_scans(db)

        assert result.enqueued_count == 0
        assert result.archived_count == 1
        assert result.missing_source_count == 1


def test_enqueue_stale_repository_scans_treats_repository_without_applications_as_stale() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db, "no-apps")

        result = enqueue_stale_repository_scans(db)

        assert result.enqueued_count == 1
        assert result.jobs[0].repository_id == repo.id


def test_enqueue_stale_repository_scans_respects_limit() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        first = create_repository(db, "first")
        second = create_repository(db, "second")
        create_application(db, first)
        create_application(db, second)

        result = enqueue_stale_repository_scans(db, limit=1)

        assert result.enqueued_count == 1
        assert result.jobs[0].repository_id == first.id
