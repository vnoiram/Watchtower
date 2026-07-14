import importlib

MODULES = [
    "api.app.main",
    "api.app.models",
    "api.app.services.scanner",
    "api.app.services.sbom",
    "api.app.services.github",
    "api.app.services.scheduler",
    "worker.runner",
]


def main() -> None:
    for module in MODULES:
        importlib.import_module(module)
        print(f"ok {module}")


if __name__ == "__main__":
    main()
