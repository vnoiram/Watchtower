import json
from pathlib import Path

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from api.app.database import Base
from api.app.models import (
    Application,
    ApplicationType,
    Component,
    Repository,
    RepositoryProvider,
    Scan,
    ScanStatus,
    SourceClassification,
)
from worker import runner


class FakeArtifactStore:
    def __init__(self) -> None:
        self.keys: list[str] = []

    def put_file(self, key: str, path: Path) -> str:
        assert path.exists()
        self.keys.append(key)
        return "sha256-digest"


def session_factory() -> sessionmaker[Session]:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def create_repo_and_app(db: Session, tmp_path: Path) -> tuple[Repository, Application]:
    repo = Repository(
        provider=RepositoryProvider.local,
        provider_repository_id="repo-1",
        owner="local",
        name="demo",
        local_path=str(tmp_path),
        source_classification=SourceClassification.private,
        archived=False,
        fork=False,
        topics=[],
    )
    db.add(repo)
    db.flush()
    app = Application(
        repository_id=repo.id,
        name="demo",
        path=".",
        application_type=ApplicationType.api,
    )
    db.add(app)
    db.flush()
    return repo, app


def test_scan_application_persists_successful_syft_sbom(monkeypatch, tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo, app = create_repo_and_app(db, tmp_path)
        store = FakeArtifactStore()

        def fake_run_syft(_: Path, output_path: Path) -> dict:
            payload = {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [{"type": "library", "name": "fastapi", "version": "0.111.0"}],
            }
            output_path.write_text(json.dumps(payload), encoding="utf-8")
            return payload

        monkeypatch.setattr(runner, "run_syft", fake_run_syft)

        assert runner.scan_application(db, repo, app, tmp_path, store, tmp_path)
        db.flush()

        scan = db.scalar(select(Scan))
        assert scan.status == ScanStatus.succeeded
        assert scan.result_summary["component_count"] == 1
        assert store.keys == [f"repositories/{repo.id}/applications/{app.id}/scans/{scan.id}/source-sbom.cdx.json"]
        assert db.scalar(select(Component).where(Component.purl == "pkg:generic/fastapi@0.111.0"))


def test_scan_application_records_failure_without_raising(monkeypatch, tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo, app = create_repo_and_app(db, tmp_path)

        def fake_run_syft(_: Path, __: Path) -> dict:
            raise RuntimeError("syft missing")

        monkeypatch.setattr(runner, "run_syft", fake_run_syft)

        assert not runner.scan_application(db, repo, app, tmp_path, FakeArtifactStore(), tmp_path)
        db.flush()

        scan = db.scalar(select(Scan))
        assert scan.status == ScanStatus.failed
        assert scan.result_summary == {"scanner_failure": True, "sbom_stored": False}
        assert scan.error_message == "syft missing"
