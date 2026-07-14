from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.models import Application, Component, Sbom, SbomComponent, Scan
from api.app.services.scanner import normalize_purl


@dataclass(frozen=True)
class ComponentRecord:
    purl: str
    ecosystem: str | None
    namespace: str | None
    name: str
    version: str | None
    supplier: str | None
    license: str | None
    cpe: str | None
    hash: str | None


def first_license(licenses: list[dict[str, Any]] | None) -> str | None:
    for item in licenses or []:
        expression = item.get("expression")
        if expression:
            return str(expression)
        license_data = item.get("license") or {}
        for key in ("id", "name"):
            value = license_data.get(key)
            if value:
                return str(value)
    return None


def first_hash(hashes: list[dict[str, Any]] | None) -> str | None:
    for item in hashes or []:
        value = item.get("content")
        if value:
            return str(value)
    return None


def supplier_name(supplier: dict[str, Any] | str | None) -> str | None:
    if isinstance(supplier, str):
        return supplier
    if isinstance(supplier, dict):
        value = supplier.get("name")
        return str(value) if value else None
    return None


def split_purl_namespace(purl: str) -> str | None:
    if not purl.startswith("pkg:"):
        return None
    without_type = purl.split("/", 1)[1] if "/" in purl else ""
    name_part = without_type.split("@", 1)[0]
    if "/" not in name_part:
        return None
    return name_part.rsplit("/", 1)[0]


def component_records_from_cyclonedx(payload: dict[str, Any]) -> list[ComponentRecord]:
    components = payload.get("components")
    if not isinstance(components, list):
        raise ValueError("CycloneDX SBOM must contain a components array")

    records: list[ComponentRecord] = []
    for component in components:
        if not isinstance(component, dict):
            continue
        name = component.get("name")
        if not name:
            continue
        version = component.get("version")
        purl = component.get("purl") or normalize_purl("generic", str(name), str(version) if version else None)
        ecosystem = component.get("type")
        records.append(
            ComponentRecord(
                purl=str(purl),
                ecosystem=str(ecosystem) if ecosystem else None,
                namespace=split_purl_namespace(str(purl)),
                name=str(name),
                version=str(version) if version else None,
                supplier=supplier_name(component.get("supplier")),
                license=first_license(component.get("licenses")),
                cpe=str(component.get("cpe")) if component.get("cpe") else None,
                hash=first_hash(component.get("hashes")),
            )
        )
    return records


def upsert_source_sbom(
    db: Session,
    application: Application,
    scan: Scan,
    payload: dict[str, Any],
    *,
    storage_key: str,
    sbom_digest: str,
    commit_sha: str | None = None,
) -> tuple[Sbom, int]:
    records = component_records_from_cyclonedx(payload)

    active_sboms = db.scalars(
        select(Sbom).where(
            Sbom.application_id == application.id,
            Sbom.sbom_kind == "source",
            Sbom.active.is_(True),
        )
    )
    for active_sbom in active_sboms:
        active_sbom.active = False

    sbom = Sbom(
        application_id=application.id,
        scan_id=scan.id,
        sbom_kind="source",
        format="cyclonedx-json",
        specification_version=payload.get("specVersion"),
        commit_sha=commit_sha,
        sbom_digest=sbom_digest,
        storage_key=storage_key,
        active=True,
    )
    db.add(sbom)
    db.flush()

    seen_purls: set[str] = set()
    for record in records:
        if record.purl in seen_purls:
            continue
        seen_purls.add(record.purl)
        component = db.query(Component).filter(Component.purl == record.purl).one_or_none()
        if not component:
            component = Component(
                purl=record.purl,
                ecosystem=record.ecosystem,
                namespace=record.namespace,
                name=record.name,
                version=record.version,
                supplier=record.supplier,
                license=record.license,
                cpe=record.cpe,
                hash=record.hash,
            )
            db.add(component)
            db.flush()
        db.add(SbomComponent(sbom_id=sbom.id, component_id=component.id))

    return sbom, len(seen_purls)
