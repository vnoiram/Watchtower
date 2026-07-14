from pathlib import Path

from api.app.models import ApplicationType


MANIFEST_RULES = {
    "package.json": ("javascript", ApplicationType.web),
    "pnpm-lock.yaml": ("javascript", ApplicationType.web),
    "package-lock.json": ("javascript", ApplicationType.web),
    "yarn.lock": ("javascript", ApplicationType.web),
    "pyproject.toml": ("python", ApplicationType.api),
    "requirements.txt": ("python", ApplicationType.api),
    "go.mod": ("go", ApplicationType.cli),
    "Cargo.toml": ("rust", ApplicationType.cli),
    "pom.xml": ("java", ApplicationType.api),
    "build.gradle": ("java", ApplicationType.api),
    "Dockerfile": ("container", ApplicationType.container),
    "manifest.json": ("browser-extension", ApplicationType.browser_extension),
}


def detect_applications(root: Path) -> list[dict[str, str]]:
    detected: dict[str, dict[str, str]] = {}
    for path in root.rglob("*"):
        if not path.is_file() or path.name not in MANIFEST_RULES:
            continue
        technology, app_type = MANIFEST_RULES[path.name]
        rel_parent = path.parent.relative_to(root).as_posix() or "."
        current = detected.setdefault(
            rel_parent,
            {
                "path": rel_parent,
                "name": root.name if rel_parent == "." else path.parent.name,
                "application_type": app_type.value,
                "technology": technology,
                "detection_source": path.name,
            },
        )
        if current["application_type"] == ApplicationType.unknown.value:
            current["application_type"] = app_type.value
    if not detected:
        detected["."] = {
            "path": ".",
            "name": root.name,
            "application_type": ApplicationType.unknown.value,
            "technology": "unknown",
            "detection_source": "none",
        }
    return list(detected.values())

