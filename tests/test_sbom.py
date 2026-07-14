from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from api.app.database import Base
from api.app.models import (
    Application,
    ApplicationType,
    Component,
    Repository,
    RepositoryProvider,
    Sbom,
    SbomComponent,
    Scan,
    SourceClassification,
)
from api.app.services.sbom import component_records_from_cyclonedx, upsert_source_sbom


def session_factory() -> sessionmaker[Session]:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def sample_sbom() -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {
                "type": "library",
                "name": "fastapi",
                "version": "0.111.0",
                "purl": "pkg:pypi/fastapi@0.111.0",
                "licenses": [{"license": {"id": "MIT"}}],
                "supplier": {"name": "FastAPI"},
                "hashes": [{"alg": "SHA-256", "content": "abc"}],
            },
            {
                "type": "library",
                "name": "local-package",
                "version": "1.0.0",
                "licenses": [{"expression": "Apache-2.0 OR MIT"}],
            },
        ],
    }


def create_app(db: Session) -> Application:
    repo = Repository(
        provider=RepositoryProvider.manual,
        provider_repository_id="repo-1",
        owner="local",
        name="demo",
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
    return app


def test_component_records_from_cyclonedx_extracts_purl_and_fallback() -> None:
    records = component_records_from_cyclonedx(sample_sbom())

    assert records[0].purl == "pkg:pypi/fastapi@0.111.0"
    assert records[0].namespace is None
    assert records[0].license == "MIT"
    assert records[0].supplier == "FastAPI"
    assert records[0].hash == "abc"
    assert records[1].purl == "pkg:generic/local-package@1.0.0"
    assert records[1].license == "Apache-2.0 OR MIT"


def test_component_records_require_components_array() -> None:
    try:
        component_records_from_cyclonedx({"bomFormat": "CycloneDX"})
    except ValueError as exc:
        assert "components array" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_upsert_source_sbom_creates_components_and_deactivates_old_sbom() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        app = create_app(db)
        first_scan = Scan(application_id=app.id)
        db.add(first_scan)
        db.flush()

        first_sbom, first_count = upsert_source_sbom(
            db,
            app,
            first_scan,
            sample_sbom(),
            storage_key="first/source-sbom.cdx.json",
            sbom_digest="digest-1",
        )

        second_scan = Scan(application_id=app.id)
        db.add(second_scan)
        db.flush()
        second_sbom, second_count = upsert_source_sbom(
            db,
            app,
            second_scan,
            sample_sbom(),
            storage_key="second/source-sbom.cdx.json",
            sbom_digest="digest-2",
        )

        db.flush()

        assert first_count == 2
        assert second_count == 2
        assert not db.get(Sbom, first_sbom.id).active
        assert db.get(Sbom, second_sbom.id).active
        assert db.scalar(select(Component).where(Component.purl == "pkg:pypi/fastapi@0.111.0"))
        assert len(db.scalars(select(SbomComponent).where(SbomComponent.sbom_id == second_sbom.id)).all()) == 2
