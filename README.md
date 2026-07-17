# Watchtower Maintenance Platform

日本語版はこちら: [README.ja.md](README.ja.md)

Centralized maintenance platform for GitHub repositories, local folders, and isolated source targets. It tracks repository inventory, applications, jobs, scans, SBOM metadata, components, vulnerabilities, findings, VEX statements, notifications, and remediation actions.

Watchtower is intended for teams that maintain many repositories and need one place to answer questions such as:

- Which repositories and applications are currently in scope?
- Which applications have stale or failed scans?
- Which components, vulnerabilities, and findings affect each application?
- Which vulnerabilities need notification, GitHub issue creation, validation, or closure?
- Which findings were accepted as VEX exceptions, and when should they be reviewed again?

## Features

- **Repository and application inventory**: register GitHub repositories, local folders, and isolated source targets, then detect applications and technology metadata from the source tree.
- **Scheduled and manual scans**: enqueue scans directly or through the scheduler for stale repositories.
- **SBOM and artifact storage**: generate CycloneDX source SBOMs with Syft and store SBOMs, scanner JSON, and logs in MinIO-compatible object storage.
- **Vulnerability and security scanning**: normalize results from OSV-Scanner, Trivy, Grype, Gitleaks, and Semgrep into central findings.
- **Finding lifecycle management**: track open, resolved, stale, duplicated, false-positive, and evidence-gap states across applications.
- **VEX and exception handling**: record non-affected, accepted-risk, and review-needed decisions with expiry and invalidation checks.
- **Remediation workflow**: prepare GitHub issue actions, issue closure actions, remediation validations, dependency update queues, AI fix candidates, and auto-merge eligibility checks.
- **Notifications**: enqueue and deliver finding notifications through configured Slack, Discord, or SMTP channels.
- **Governance and operations dashboards**: expose KPIs, SLA status, scan health, scanner coverage, storage pressure, RBAC review, rollout readiness, and daily/weekly/monthly operational checks.
- **Isolated lane support**: keep GitHub-managed repositories and sensitive local or isolated code paths visible through the same inventory and scan model.
- **Audit logging and token roles**: protect API operations with bearer tokens and record auditable actions.

## Architecture

The local stack is composed of:

- **API**: FastAPI service under `/v1`.
- **Worker**: job runner that clones or copies repositories, detects applications, runs scanners, stores artifacts, and updates findings.
- **Scheduler**: periodic stale-scan enqueuer.
- **PostgreSQL**: system of record for repositories, applications, jobs, scans, SBOM metadata, findings, VEX, and remediation records.
- **MinIO**: object storage for SBOMs and scanner artifacts.
- **Frontend**: static dashboard for inventory, vulnerability, remediation, governance, and operations views.

## Quick Start

```bash
cp .env.example .env
docker compose up --build
```

Apply database migrations before using the API:

```bash
docker compose run --rm api alembic upgrade head
```

Services:

- API: http://localhost:8000
- Frontend: http://localhost:3000
- MinIO: http://localhost:9001

The API is namespaced under `/v1`. Set `API_TOKEN` in `.env` and send it as `Authorization: Bearer <token>`.

## Typical Workflow

1. Start the stack and run migrations.
2. Register repositories with `POST /v1/repositories`, or enqueue a GitHub sync job with `POST /v1/github/sync`.
3. Enqueue a repository scan with `POST /v1/repositories/{repository_id}/scan`.
4. Let the worker detect applications, generate SBOMs, run scanners, store artifacts, and update findings.
5. Review the dashboard, finding lists, remediation queues, VEX reviews, and operational health endpoints.

## Notable API Areas

- `/v1/repositories`, `/v1/applications`, `/v1/technologies`: inventory and detected application metadata.
- `/v1/jobs`, `/v1/scans`, `/v1/scan-health`: job execution, scan history, evidence quality, and freshness.
- `/v1/sboms`, `/v1/components`, `/v1/artifacts`: SBOM, component, dependency, license, and artifact tracking.
- `/v1/vulnerabilities`, `/v1/findings`, `/v1/security`: vulnerability impact, finding lifecycle, secret scan, SAST, and exploit-intelligence views.
- `/v1/vex`, `/v1/exceptions`: exception and VEX review workflows.
- `/v1/remediation`, `/v1/remediation-actions`, `/v1/ai-fix`, `/v1/auto-merge`: issue creation, validation, dependency updates, AI fix candidates, and automation guardrails.
- `/v1/dashboard`, `/v1/kpis`, `/v1/operations`, `/v1/governance`, `/v1/rollout`: dashboard metrics, operating checks, ownership, rollout readiness, and MVP target tracking.
- `/v1/github`, `/v1/integrations`, `/v1/repository-sync`: GitHub sync, webhooks, permissions, and provider health.

## Configuration

Copy `.env.example` to `.env` and adjust values for your environment. Important settings include:

- `DATABASE_URL`: PostgreSQL connection string.
- `API_TOKEN` or `API_TOKENS`: bearer token authentication. `API_TOKENS` supports comma-separated `label:token:role` entries.
- `MINIO_ENDPOINT`, `MINIO_ACCESS_KEY`, `MINIO_SECRET_KEY`, `MINIO_BUCKET`: object storage configuration.
- `GITHUB_APP_ID`, `GITHUB_PRIVATE_KEY`, `GITHUB_WEBHOOK_SECRET`: optional GitHub App integration.
- `SLACK_WEBHOOK_URL`, `DISCORD_WEBHOOK_URL`, `SMTP_*`: optional notification delivery channels.
- `WORKER_*` and `SCAN_SCHEDULER_*`: worker timeout, polling, hardening, and scheduler behavior.

## Local Checks

```bash
python -m compileall api worker scripts tests
python -m pytest
```
