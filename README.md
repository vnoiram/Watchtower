# Watchtower Maintenance Platform

Centralized maintenance platform for GitHub repositories, local folders, and isolated source targets. It tracks repository inventory, applications, jobs, scans, SBOM metadata, components, vulnerabilities, findings, VEX statements, notifications, and remediation actions.

## Quick Start

```bash
cp .env.example .env
docker compose up --build
```

Services:

- API: http://localhost:8000
- Frontend: http://localhost:3000
- MinIO: http://localhost:9001

The API is namespaced under `/v1`. Set `API_TOKEN` in `.env` and send it as `Authorization: Bearer <token>`.

## Local Checks

```bash
python -m compileall api worker scripts tests
python -m pytest
```

