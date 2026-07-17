# Watchtower Maintenance Platform

GitHub リポジトリ、ローカルフォルダー、隔離されたソース対象を一元管理するメンテナンスプラットフォームです。リポジトリ台帳、アプリケーション、ジョブ、スキャン、SBOM メタデータ、コンポーネント、脆弱性、finding、VEX statement、通知、修復アクションを追跡します。

Watchtower は、多数のリポジトリを保守するチームが次のような問いに答えるための単一の場所を提供することを意図しています。

- 現在スコープ内にあるリポジトリとアプリケーションはどれか。
- 古い、または失敗したスキャンを持つアプリケーションはどれか。
- 各アプリケーションに影響するコンポーネント、脆弱性、finding は何か。
- 通知、GitHub issue 作成、検証、クローズが必要な脆弱性はどれか。
- VEX 例外として受け入れられた finding はどれで、いつ再レビューすべきか。

## 機能

- **リポジトリとアプリケーション台帳**: GitHub リポジトリ、ローカルフォルダー、隔離ソース対象を登録し、ソースツリーからアプリケーションと技術メタデータを検出します。
- **定期/手動スキャン**: stale なリポジトリに対して直接、または scheduler 経由でスキャンを enqueue します。
- **SBOM と artifact 保存**: Syft で CycloneDX source SBOM を生成し、SBOM、scanner JSON、ログを MinIO 互換 object storage に保存します。
- **脆弱性/セキュリティスキャン**: OSV-Scanner, Trivy, Grype, Gitleaks, Semgrep の結果を中央 finding に正規化します。
- **Finding ライフサイクル管理**: open, resolved, stale, duplicated, false-positive, evidence-gap をアプリケーション横断で追跡します。
- **VEX と例外処理**: non-affected, accepted-risk, review-needed の判断を期限と invalidation check 付きで記録します。
- **修復ワークフロー**: GitHub issue 作成、issue close、修復検証、依存更新キュー、AI fix 候補、auto-merge eligibility check を準備します。
- **通知**: 設定済みの Slack, Discord, SMTP チャンネルへ finding 通知を enqueue して配信します。
- **ガバナンス/運用ダッシュボード**: KPI、SLA 状態、スキャン健全性、scanner coverage、storage pressure、RBAC review、rollout readiness、日次/週次/月次運用チェックを公開します。
- **隔離レーン対応**: GitHub 管理リポジトリと機密性の高いローカル/隔離コードパスを、同じ台帳とスキャンモデルで可視化します。
- **監査ログと token role**: bearer token で API 操作を保護し、監査可能なアクションを記録します。

## アーキテクチャ

ローカルスタックは次で構成されます。

- **API**: `/v1` 配下の FastAPI サービス。
- **Worker**: リポジトリの clone/copy、アプリケーション検出、scanner 実行、artifact 保存、finding 更新を行うジョブランナー。
- **Scheduler**: stale scan を定期的に enqueue します。
- **PostgreSQL**: リポジトリ、アプリケーション、ジョブ、スキャン、SBOM メタデータ、finding、VEX、修復レコードの system of record。
- **MinIO**: SBOM と scanner artifact 用 object storage。
- **Frontend**: 台帳、脆弱性、修復、ガバナンス、運用ビュー用の静的ダッシュボード。

## クイックスタート

```bash
cp .env.example .env
docker compose up --build
```

API を使う前にデータベース migration を適用します。

```bash
docker compose run --rm api alembic upgrade head
```

サービス:

- API: http://localhost:8000
- Frontend: http://localhost:3000
- MinIO: http://localhost:9001

API は `/v1` 配下に namespaced されています。`.env` に `API_TOKEN` を設定し、`Authorization: Bearer <token>` として送信してください。

## 典型的なワークフロー

1. スタックを起動し、migration を実行します。
2. `POST /v1/repositories` でリポジトリを登録するか、`POST /v1/github/sync` で GitHub sync job を enqueue します。
3. `POST /v1/repositories/{repository_id}/scan` でリポジトリスキャンを enqueue します。
4. Worker がアプリケーション検出、SBOM 生成、scanner 実行、artifact 保存、finding 更新を行います。
5. ダッシュボード、finding list、修復キュー、VEX review、運用 health endpoint を確認します。

## 主な API 領域

- `/v1/repositories`, `/v1/applications`, `/v1/technologies`: 台帳と検出済みアプリケーションメタデータ。
- `/v1/jobs`, `/v1/scans`, `/v1/scan-health`: ジョブ実行、スキャン履歴、証跡品質、鮮度。
- `/v1/sboms`, `/v1/components`, `/v1/artifacts`: SBOM、コンポーネント、依存、ライセンス、artifact 追跡。
- `/v1/vulnerabilities`, `/v1/findings`, `/v1/security`: 脆弱性影響、finding lifecycle、secret scan、SAST、exploit intelligence。
- `/v1/vex`, `/v1/exceptions`: 例外と VEX review workflow。
- `/v1/remediation`, `/v1/remediation-actions`, `/v1/ai-fix`, `/v1/auto-merge`: issue 作成、検証、依存更新、AI fix 候補、自動化 guardrail。
- `/v1/dashboard`, `/v1/kpis`, `/v1/operations`, `/v1/governance`, `/v1/rollout`: ダッシュボード指標、運用チェック、owner、rollout readiness、MVP target tracking。
- `/v1/github`, `/v1/integrations`, `/v1/repository-sync`: GitHub sync、webhook、権限、provider health。

## 設定

`.env.example` を `.env` にコピーし、環境に合わせて調整します。重要な設定は次の通りです。

- `DATABASE_URL`: PostgreSQL 接続文字列。
- `API_TOKEN` または `API_TOKENS`: bearer token 認証。`API_TOKENS` はカンマ区切りの `label:token:role` エントリをサポートします。
- `MINIO_ENDPOINT`, `MINIO_ACCESS_KEY`, `MINIO_SECRET_KEY`, `MINIO_BUCKET`: object storage 設定。
- `GITHUB_APP_ID`, `GITHUB_PRIVATE_KEY`, `GITHUB_WEBHOOK_SECRET`: 任意の GitHub App integration。
- `SLACK_WEBHOOK_URL`, `DISCORD_WEBHOOK_URL`, `SMTP_*`: 任意の通知配信チャンネル。
- `WORKER_*` と `SCAN_SCHEDULER_*`: worker timeout、polling、hardening、scheduler behavior。

## ローカルチェック

```bash
python -m compileall api worker scripts tests
python -m pytest
```
