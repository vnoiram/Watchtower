from pathlib import Path

from api.app.services.registry import detect_applications


def test_detect_applications_from_manifests(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    service = tmp_path / "service"
    service.mkdir()
    (service / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")

    apps = sorted(detect_applications(tmp_path), key=lambda item: item["path"])

    assert [app["path"] for app in apps] == [".", "service"]
    assert apps[0]["application_type"] == "web"


def test_detect_applications_returns_unknown_for_unclassified_repo(tmp_path: Path) -> None:
    apps = detect_applications(tmp_path)
    assert apps == [
        {
            "path": ".",
            "name": tmp_path.name,
            "application_type": "unknown",
            "technology": "unknown",
            "detection_source": "none",
        }
    ]

