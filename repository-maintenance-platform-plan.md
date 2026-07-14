# 多数リポジトリ向け自動保守・脆弱性管理基盤
# 詳細実装計画書

## 1. 文書概要

### 1.1 文書目的

本計画書は、GitHub public/private repositoryおよびGitHub外の隔離リポジトリを対象として、外部ライブラリ、SBOM、脆弱性、修正対応を一元管理する保守基盤の構築計画を定義する。

現在約54リポジトリが存在し、今後もClaude、CodexなどのAI開発支援によってアプリケーション数が増加することを前提とする。

本基盤では、以下を実現する。

- 全リポジトリの自動棚卸し
- アプリケーションと技術スタックの一元管理
- Source SBOMおよびArtifact SBOMの生成
- 外部ライブラリとOSパッケージの一覧化
- 最新脆弱性情報との定期照合
- 新規脆弱性検出時の自動発火
- GitHub Issue、修正PR、通知の自動作成
- 修正後のテスト、再スキャン、自動クローズ
- VEXおよび例外判断の期限付き管理
- GitHub外の研究用コードへの対応
- 将来的なAI修正エージェントとの連携

---

## 2. 背景

### 2.1 現状

- 約54のリポジトリが存在する
- 多くはGitHub上で管理されている
- public repositoryとprivate repositoryが混在する
- 将来的にGitHubへ保存できないセキュリティ研究コードが発生する可能性がある
- 多数の言語、フレームワーク、アプリ種別が存在する
- サーバーアプリ、Webアプリ、CLI、ブラウザ拡張機能などが混在する
- AI開発支援により、新規アプリ作成の速度が高まっている
- 一方で、依存関係更新、脆弱性対応、バグ修正、廃止判断の負荷が増加する

### 2.2 課題

現状のままでは、以下の問題が発生する。

- どのリポジトリが保守対象か分からない
- どのライブラリがどのアプリで使われているか逆引きできない
- 新規CVE公開時に影響範囲を迅速に特定できない
- Dependabotや各リポジトリのSecurity画面を個別に確認する必要がある
- private repositoryと隔離環境で管理方法が分断される
- 脆弱性の未対応、対応中、修正済みが追跡できない
- 脆弱性が非該当である理由が記録されない
- 修正PR作成後に本当に脆弱性が解消したか自動確認できない
- リポジトリ増加に比例して手作業が増える
- AIによる自動修正を安全に判定する基盤がない

---

## 3. プロジェクト目標

### 3.1 最終目標

以下の問いに対して、中央システムから即座に回答できる状態を作る。

- 現在管理対象となっているリポジトリはいくつあるか
- 最終スキャンが古いリポジトリはどれか
- CriticalまたはHigh脆弱性を持つアプリはどれか
- 特定ライブラリを使用しているアプリはどれか
- 特定CVEの影響を受けるアプリはどれか
- 修正版が存在するがPR未作成の脆弱性はどれか
- 修正PR作成済みだがCI失敗中のものはどれか
- VEXで非該当と判断された脆弱性はどれか
- VEXの再確認期限が切れているものはどれか
- GitHub外の隔離アプリのスキャン状態はどうか
- 長期間更新されていない廃止候補アプリはどれか

### 3.2 定量目標

| 指標 | 目標 |
|---|---:|
| リポジトリ台帳登録率 | 100% |
| SBOM生成率 | 90%以上 |
| 日次スキャン成功率 | 95%以上 |
| Critical検出から通知まで | 1時間以内 |
| High検出からIssue作成まで | 24時間以内 |
| 修正可能な脆弱性の自動PR作成率 | 70%以上 |
| 修正後の自動再スキャン率 | 100% |
| 期限なし例外 | 0件 |
| 30日以上未スキャンのActiveアプリ | 0件 |
| 手作業による定期棚卸し | 原則不要 |

---

## 4. スコープ

### 4.1 対象範囲

#### ソース管理

- GitHub public repository
- GitHub private repository
- GitHub Organization配下のrepository
- 将来的なForgejo、Gitea、GitLab Self-Managed
- ローカルGit
- 暗号化された隔離環境

#### アプリ種別

- Webアプリケーション
- APIサーバー
- バッチ
- CLI
- ブラウザ拡張
- コンテナアプリ
- サーバーレス
- デスクトップアプリ
- ライブラリ
- セキュリティ研究用PoC

#### スキャン対象

- 外部ライブラリ
- 推移的依存
- OSパッケージ
- コンテナイメージ
- lockfile
- manifest
- 配布成果物
- Secret
- SAST
- ライセンス
- SBOM

### 4.2 初期スコープ外

MVPでは以下を対象外とする。

- 完全なSIEM機能
- 本番ログの長期分析
- 高度なランタイム脆弱性検知
- Kubernetes全体のCSPM
- 自動ペネトレーションテスト
- AIによる無条件自動修正
- AIによるmainブランチへの直接変更
- 複雑なマイクロサービス構成
- Kafkaなどの大規模イベント基盤
- 全脆弱性フィードの独自集約
- 独自SBOM標準の策定

---

## 5. 設計原則

1. PostgreSQLを管理情報の正本とする
2. SBOMやスキャン生データはオブジェクトストレージへ保存する
3. GitHubを標準レーン、機密研究コードを隔離レーンとする
4. 保存場所にかかわらず、スキャン結果の形式を統一する
5. SBOM生成と脆弱性再評価を分離する
6. コード変更がなくても、脆弱性情報更新により再評価する
7. 修正PR作成後に必ず再スキャンする
8. 自動マージは低リスク変更のみに限定する
9. 例外はVEXとして理由、承認者、期限を保持する
10. 各リポジトリに複雑なロジックを持たせず、中央基盤へ集約する
11. GitHub Actionsと隔離Runnerで同じスキャンスクリプトを使用する
12. スキャナの出力形式はJSON、SARIF、CycloneDXを基本とする
13. スキャナ障害と脆弱性検出を区別する
14. 再実行可能かつ冪等な処理とする
15. 最初から54リポジトリすべてを完全自動化せず、段階的に展開する

---

## 6. 全体アーキテクチャ

```text
┌──────────────────────────────────────────────┐
│             GitHub public/private            │
│                                              │
│  Repository / Actions / Issues / Pull Request│
└───────────────────┬──────────────────────────┘
                    │ API / Webhook / Scan Result
                    │
┌───────────────────▼──────────────────────────┐
│              Maintenance API                 │
│                                              │
│ ・リポジトリ同期                              │
│ ・アプリ台帳                                  │
│ ・スキャン受付                                │
│ ・SBOMメタデータ管理                          │
│ ・脆弱性判定                                  │
│ ・Issue/PR連携                                │
│ ・VEX管理                                     │
│ ・認証・監査                                  │
└───────────┬───────────────────┬──────────────┘
            │                   │
            │                   │ Job
┌───────────▼──────────┐  ┌────▼──────────────────┐
│ PostgreSQL           │  │ Maintenance Worker    │
│                      │  │                       │
│ ・Repositories       │  │ ・Repository clone    │
│ ・Applications       │  │ ・Syft                │
│ ・Components         │  │ ・OSV-Scanner         │
│ ・Vulnerabilities    │  │ ・Trivy               │
│ ・Findings           │  │ ・Grype               │
│ ・Remediations       │  │ ・Gitleaks            │
│ ・VEX                │  │ ・Semgrep             │
│ ・Scan history       │  │ ・Result normalization│
└──────────────────────┘  └──────────┬────────────┘
                                     │
                           ┌─────────▼───────────┐
                           │ Object Storage     │
                           │                    │
                           │ ・SBOM             │
                           │ ・SARIF            │
                           │ ・Scanner JSON      │
                           │ ・Logs              │
                           └────────────────────┘

┌──────────────────────────────────────────────┐
│              Isolated Environment            │
│                                              │
│ Local Git / Forgejo / Dedicated Runner       │
│ 同一スキャナ、同一結果形式                    │
│ 必要に応じて概要のみMaintenance APIへ送信     │
└──────────────────────────────────────────────┘
```

---

## 7. システム構成

### 7.1 Maintenance API

#### 役割

- GitHubからのリポジトリ情報同期
- アプリケーション台帳管理
- スキャンジョブ登録
- スキャン結果受付
- SBOM登録
- コンポーネント正規化
- 脆弱性Finding管理
- GitHub IssueおよびPR情報管理
- VEX登録
- ダッシュボードAPI
- 監査ログ
- Webhook受付

#### 技術候補

第一候補:

- Python
- FastAPI
- SQLAlchemy
- Alembic
- Pydantic
- PostgreSQL

代替:

- Go
- EchoまたはChi
- sqlc
- PostgreSQL

#### 選定方針

MVPでは開発速度とデータ処理の容易さを優先し、FastAPIを推奨する。

### 7.2 Maintenance Worker

#### 役割

- リポジトリの一時clone
- 言語、フレームワーク、パッケージマネージャーの検出
- Source SBOM生成
- Artifact SBOM生成
- 脆弱性スキャン
- Secretスキャン
- SAST
- 結果形式の正規化
- オブジェクトストレージへのアップロード
- APIへの結果登録
- 一時作業ディレクトリの破棄

#### 実行方式

MVP:

- Dockerコンテナ
- cronまたはDBベースジョブキュー
- 最大同時実行数を制限

将来:

- Temporal
- Celery
- Redis Queue
- Kubernetes Job

#### セキュリティ要件

- リポジトリごとに作業ディレクトリを分離
- ジョブ終了後に作業ディレクトリ削除
- ホスト上のSecretを直接マウントしない
- 必要最小限のGitHub権限を使用
- private repo用Credentialは短時間化
- 攻撃コードと通常コードでWorkerを分離
- 隔離コードは専用Runnerで実行
- 外向き通信を制限可能にする

### 7.3 PostgreSQL

#### 保存対象

- リポジトリ情報
- アプリケーション情報
- 技術スタック
- スキャン履歴
- SBOMメタデータ
- コンポーネント
- 脆弱性情報
- Findings
- 対応履歴
- VEX
- 通知履歴
- ジョブ状態
- 監査ログ

#### 保存しないもの

以下の全文は原則としてDBへ保存しない。

- SBOM全文
- Trivy JSON全文
- OSV JSON全文
- SARIF全文
- Semgrep JSON全文
- 大容量ログ
- コンテナイメージ
- ビルド成果物

### 7.4 オブジェクトストレージ

#### 候補

- MinIO
- AWS S3
- Cloudflare R2
- 暗号化されたローカルストレージ

#### 保存構造例

```text
maintenance-artifacts/
├── repositories/
│   └── {repository_id}/
│       └── applications/
│           └── {application_id}/
│               └── scans/
│                   └── {scan_id}/
│                       ├── source-sbom.cdx.json
│                       ├── artifact-sbom.cdx.json
│                       ├── trivy.json
│                       ├── osv.json
│                       ├── grype.json
│                       ├── semgrep.sarif
│                       ├── gitleaks.sarif
│                       └── scan.log
```

#### 保持条件

- リリースSBOMは保持
- 定期スキャンの生データは一定期間後に削除可能
- Critical/Highに関連する証跡は長期保持
- ファイルにはSHA-256を付与
- 暗号化を有効化
- 隔離コードのSBOMは別ストレージとする

---

## 8. データモデル

### 8.1 repositories

- provider
- provider上のrepository ID
- repository名
- ownerまたはorganization
- URL
- visibility
- default branch
- archived
- fork
- source classification
- 最終同期日時
- 最終push日時
- 作成日時
- 更新日時

source classification:

- `public`
- `private`
- `restricted`
- `isolated`

### 8.2 applications

- application ID
- repository ID
- application名
- repository内path
- application type
- lifecycle
- criticality
- internet exposed
- production
- auto fix
- auto merge
- owner
- support status

application type:

- web
- api
- batch
- cli
- browser-extension
- desktop
- library
- container
- serverless
- security-research
- unknown

lifecycle:

- experimental
- active
- maintenance
- deprecated
- archived
- research

### 8.3 technologies

- category
- name
- version
- detection source
- confidence
- detected time

### 8.4 scans

- scan ID
- application ID
- scan type
- trigger type
- status
- commit SHA
- branch
- tool
- tool version
- start time
- completion time
- result summary
- error message
- retry count

scan status:

- queued
- running
- succeeded
- partially_succeeded
- failed
- cancelled
- timed_out

trigger type:

- initial-import
- pull-request
- push
- release
- schedule
- advisory-update
- manual
- remediation-validation

### 8.5 sboms

- SBOM ID
- application ID
- scan ID
- source/artifact区分
- format
- specification version
- commit SHA
- artifact digest
- SBOM digest
- storage location
- generated time
- active flag

### 8.6 components

- purl
- ecosystem
- namespace
- name
- version
- supplier
- license
- CPE
- hash

### 8.7 sbom_components

- SBOM ID
- component ID
- direct dependency
- dependency scope
- dependency path
- optional flag
- development dependency flag

### 8.8 vulnerabilities

- CVE
- GHSA
- OSV ID
- source
- summary
- description
- severity
- CVSS
- EPSS
- CISA KEV
- exploit availability
- published time
- modified time
- references
- raw data location

### 8.9 findings

- application ID
- component ID
- vulnerability ID
- current SBOM ID
- first detected
- last detected
- status
- risk score
- fix available
- fixed version
- affected range
- resolved time
- suppression reason
- assigned owner

finding status:

- open
- triaging
- remediation_planned
- fix_pr_created
- fixing
- mitigated
- resolved
- not_affected
- risk_accepted
- false_positive
- deferred

### 8.10 remediation_actions

- action type
- provider
- GitHub Issue番号
- PR番号
- branch
- target version
- status
- created time
- merged time
- validation scan ID
- metadata

### 8.11 vex_statements

- finding ID
- status
- justification
- impact statement
- approved by
- approved time
- review date
- invalidation conditions
- active flag

### 8.12 jobs

- job type
- target ID
- priority
- status
- scheduled time
- started time
- completed time
- retry count
- maximum retries
- locked by
- error

---

## 9. 実装フェーズ

### Phase 0: 事前調査・設計確定

期間目安: 1週間

主な作業:

- 54リポジトリ一覧取得
- public/private/archived分類
- 技術スタック確認
- モノレポ候補確認
- MVP対象10リポジトリ選定
- 隔離対象候補抽出
- ホスティング先決定
- GitHub App権限設計

完了条件:

- 54リポジトリが一覧化されている
- visibilityが判明している
- MVP対象10件が選定されている
- 基盤配置先が決定している

### Phase 1: DB・API基盤

期間目安: 2週間

主な作業:

- PostgreSQL構築
- Alembic導入
- 初期DBスキーマ
- CRUD API
- API認証
- 監査ログ
- OpenAPI
- 単体テスト

完了条件:

- Docker ComposeでAPI、DB、ストレージが起動
- migrationが再現可能
- RepositoryとApplicationを登録可能
- Scanジョブを登録可能

### Phase 2: GitHub同期

期間目安: 1週間

主な作業:

- GitHub App
- Installation token
- Repository一覧取得
- visibility、default branch、language、topics取得
- DBへのupsert
- 日次同期
- Webhook署名検証

完了条件:

- 54リポジトリがDBへ登録される
- 再同期で重複しない
- archive変更が反映される

### Phase 3: アプリ・技術検出

期間目安: 1週間

主な作業:

- clone Worker
- manifest検出
- lockfile検出
- Dockerfile検出
- モノレポ候補検出
- application自動登録
- technology自動登録

完了条件:

- MVP対象10リポジトリのアプリを検出
- 主要言語とpackage managerを登録
- 不明構成はunknownとして保持

### Phase 4: SBOM生成・保存

期間目安: 2週間

主な作業:

- Syft統合
- Source SBOM生成
- CycloneDX保存
- MinIOアップロード
- SHA-256計算
- component正規化
- purl正規化
- Artifact SBOM基本対応

完了条件:

- MVP対象10件でSBOM生成率90%以上
- componentをDB登録可能
- SBOM全文をストレージへ保存

### Phase 5: 脆弱性スキャン

期間目安: 2週間

主な作業:

- OSV-Scanner統合
- Trivy統合
- Grype統合
- 出力正規化
- vulnerability/finding upsert
- fixed version取得
- severity統合
- 日次再スキャン
- 週次完全スキャン

完了条件:

- 同一Findingが重複しない
- スキャン失敗と脆弱性なしを区別
- 新規脆弱性をFinding登録
- 解消Findingを検出

### Phase 6: リスク評価・通知

期間目安: 1週間

主な作業:

- Risk Score
- Criticality、Exposure、KEV、EPSS対応
- SLA算出
- EmailまたはSlack通知
- 日次サマリー
- 即時通知

完了条件:

- Criticalが即時通知
- Medium以下は集約通知
- 同一Findingの通知重複を抑止

### Phase 7: GitHub Issue・PR連携

期間目安: 2週間

主な作業:

- Issue自動作成
- 重複防止
- 自動更新・クローズ
- Renovate導入
- PR情報同期
- Workflow結果同期
- PRマージ後再スキャン

完了条件:

- FindingからIssue生成
- Renovate PRとFindingを紐付け
- PRマージ後に再スキャン
- 解消時にFindingとIssueをクローズ

### Phase 8: VEX・例外管理

期間目安: 1週間

主な作業:

- VEX登録API
- 承認者
- review date
- invalidation condition
- 期限切れジョブ
- component変更時失効
- 監査履歴

完了条件:

- 期限なし例外を禁止
- 期限切れVEXを自動検出
- バージョン変更時に再評価
- 履歴保持

### Phase 9: 全54リポジトリ展開

期間目安: 2〜4週間

展開単位:

- Wave 1: 10リポジトリ
- Wave 2: 15リポジトリ
- Wave 3: 15リポジトリ
- Wave 4: 14リポジトリ

完了条件:

- 54リポジトリが台帳登録済み
- Active対象の90%以上がSBOM生成済み
- Tier、owner設定済み
- Critical/High初期棚卸し完了

### Phase 10: 隔離環境

期間目安: 2週間

主な作業:

- ForgejoまたはLocal Git
- 専用Runner
- ネットワーク分離
- ローカルSBOM
- ローカル脆弱性スキャン
- 概要送信形式
- 暗号化バックアップ

完了条件:

- 隔離コードがGitHubへ送信されない
- 通常Runnerと共有されない
- 許可された概要のみ中央送信

### Phase 11: 条件付き自動マージ

期間目安: 1週間

主な作業:

- Auto Merge Policy
- Tier別ルール
- Patch/Minor判定
- CI、再スキャン確認
- 禁止領域判定
- Dry Run
- Pilot適用

完了条件:

- Policy外PRは自動マージされない
- 脆弱性解消後のみマージ
- 監査履歴とロールバック手順が存在

### Phase 12: AI修正支援

将来フェーズ

対象:

- 非推奨API置換
- 単純な依存更新対応
- 型エラー
- Lint
- 明確なテスト失敗
- 小規模な互換修正

対象外:

- 認証
- 暗号
- 課金
- DB migration
- Secret
- 未公開脆弱性
- マルウェア
- 高重要度システム

---

## 10. 想定スケジュール

| 週 | フェーズ |
|---:|---|
| 1 | 事前調査・設計確定 |
| 2〜3 | DB・API基盤 |
| 4 | GitHub同期 |
| 5 | アプリ・技術検出 |
| 6〜7 | SBOM生成 |
| 8〜9 | 脆弱性スキャン |
| 10 | リスク評価・通知 |
| 11〜12 | Issue・PR連携 |
| 13 | VEX管理 |
| 14〜17 | 全54リポジトリ展開 |
| 18〜19 | 隔離環境 |
| 20 | 条件付き自動マージ |

目安:

- MVP: 約8〜10週間
- 基本運用開始: 約12〜13週間
- 54リポジトリ全体展開: 約16〜17週間
- 隔離環境・自動マージ込み: 約20週間

---

## 11. MVP定義

対象:

- GitHub上の10リポジトリ
- 複数言語
- public/private双方
- コンテナアプリを1件以上
- ブラウザ拡張を1件以上

MVP機能:

- GitHubからrepository同期
- application自動検出
- Source SBOM生成
- component DB登録
- OSVおよびTrivyスキャン
- Finding登録
- Critical/High一覧
- 日次スキャン
- GitHub Issue作成
- 最終スキャン日時表示

MVPでは未実装でもよいもの:

- AI修正
- 自動マージ
- 高度なVEX
- 全スキャナ統合
- 隔離環境
- 高度なUI
- 全54リポジトリ対応

---

## 12. テスト計画

### 単体テスト

- purl正規化
- severity統合
- Finding重複排除
- Risk Score
- VEX期限判定
- Auto Merge Policy
- GitHub payload検証

### 結合テスト

- GitHub同期からrepository登録
- cloneからSBOM生成
- SBOMからcomponent登録
- スキャナからFinding登録
- FindingからIssue作成
- PRマージから再スキャン
- Finding解決からIssueクローズ

### E2Eテスト

1. 脆弱な依存を追加
2. PRスキャンで検出
3. mainへ反映
4. Finding作成
5. Issue作成
6. Renovate PR作成
7. 修正後CI成功
8. 再スキャンで解消
9. Finding resolved
10. Issue close

### 障害テスト

- GitHub API rate limit
- GitHub API timeout
- clone失敗
- private repository認証失敗
- Syft失敗
- Trivy DB更新失敗
- MinIO停止
- PostgreSQL一時停止
- Worker異常終了
- 重複Webhook
- 同一ジョブ多重実行

---

## 13. セキュリティ要件

### 認証・認可

- 管理UIに認証必須
- API tokenを暗号化保存
- RBAC導入
- Viewer、Operator、Adminを分離
- VEX承認権限を限定
- Auto Merge設定変更権限を限定

### Secret管理

- SecretをDBへ平文保存しない
- Secret Managerを利用
- GitHub App private keyを保護
- Workerへ必要時のみCredentialを渡す
- 長期PATを避ける

### Worker

- root実行を避ける
- read-only filesystemを検討
- ジョブ単位で一時領域を作成
- ジョブ後に削除
- タイムアウト設定
- CPU、メモリ制限
- ネットワーク制限
- 通常コードとRestrictedコードを分離

### データ

- DB暗号化
- オブジェクトストレージ暗号化
- バックアップ暗号化
- TLS
- SBOMの機密分類
- 監査ログ
- 保存期間ポリシー

---

## 14. 運用設計

### 日次

- GitHub repository同期
- 最新SBOMの脆弱性再評価
- 失敗ジョブ再試行
- Critical/High通知
- 期限超過確認
- VEX期限確認

### 週次

- 全リポジトリ完全スキャン
- PR停滞確認
- Medium脆弱性レビュー
- 未スキャンアプリ確認
- scanner version確認
- false positive確認
- auto fix失敗確認

### 月次

- VEX再評価
- Risk Accepted再評価
- ツール更新
- ランタイムEOL確認
- スキャン成功率確認
- MTTR確認
- ストレージ整理
- バックアップ復元確認

### 四半期

- 廃止候補抽出
- Tier見直し
- owner見直し
- 外部公開状態見直し
- GitHub App権限見直し
- 隔離分類見直し
- 自動マージ範囲見直し

---

## 15. KPI

### カバレッジ

- Repository登録率
- Application検出率
- SBOM生成率
- 日次スキャン率
- Artifact SBOM生成率

### 対応効率

- Mean Time to Detect
- Mean Time to Notify
- Mean Time to Remediate
- 自動PR作成率
- 自動解決率
- 再オープン率

### 品質

- スキャン失敗率
- false positive率
- VEX期限切れ率
- 自動マージ失敗率
- 修正PRのCI成功率
- AI修正成功率

### 運用負荷

- 月間手動確認件数
- 手動Issue作成件数
- 手動依存更新件数
- 未対応Finding件数
- 長期滞留PR件数

---

## 16. リスクと対策

| リスク | 影響 | 対策 |
|---|---|---|
| 誤検知が多い | 通知疲れ | VEX、集約通知、複数情報源統合 |
| スキャン時間増大 | CI遅延 | PR差分と定期完全スキャンを分離 |
| GitHub API制限 | 同期失敗 | キャッシュ、差分同期、再試行 |
| スキャナDB更新失敗 | 判定漏れ | 更新状態監視、複数スキャナ |
| モノレポ誤検出 | アプリ分類不正 | 手動補正、path管理 |
| SBOM不完全 | 影響範囲漏れ | SourceとArtifactの両方を生成 |
| 自動PR過多 | 運用負荷 | Group化、優先度、同時PR制限 |
| 自動マージ事故 | 障害 | Tier制限、再スキャン、rollback |
| Worker侵害 | 横展開 | 一時環境、Credential分離 |
| 機密情報漏えい | 重大 | 隔離Runner、送信制限 |
| DB肥大化 | 性能低下 | 生データをObject Storageへ分離 |
| 管理基盤自体の保守負荷 | 逆効果 | モノリス構成、OSS活用 |
| owner不明 | 対応停滞 | owner必須、未設定アラート |
| 例外放置 | リスク残存 | review date必須、自動失効 |

---

## 17. 初期技術選定案

```yaml
backend:
  language: Python
  framework: FastAPI
  orm: SQLAlchemy
  migration: Alembic

database:
  engine: PostgreSQL

object_storage:
  engine: MinIO

worker:
  runtime: Docker
  queue: PostgreSQL
  scheduler: APScheduler または cron

scanners:
  sbom:
    - Syft
  vulnerability:
    - OSV-Scanner
    - Trivy
    - Grype
  secret:
    - Gitleaks
  sast:
    - Semgrep

dependency_updates:
  primary: Renovate
  secondary: Dependabot

frontend:
  initial: Metabase または簡易React
  future: Next.js

deployment:
  initial: Docker Compose
  future: VMまたはKubernetes

authentication:
  initial: Reverse Proxy認証
  future: OIDC

observability:
  logs: JSON structured logs
  metrics: Prometheus
  dashboard: Grafana
```

---

## 18. プロジェクト完了条件

- 54リポジトリがDBに登録されている
- public/private/isolated分類が設定されている
- Activeアプリにownerが設定されている
- Activeアプリの90%以上でSBOMが生成されている
- 日次脆弱性再スキャンが稼働している
- Critical/High Findingが中央一覧で確認できる
- 修正版ありのFindingでIssueまたはPRが作成できる
- 修正後に自動再スキャンされる
- 解消したFindingが自動でresolvedになる
- VEXに期限を設定できる
- 期限切れVEXを検出できる
- スキャン失敗を監視できる
- 隔離コードの運用ルールが定義されている
- バックアップと復旧手順が存在する
- 運用担当者が日次・週次作業を実施できる

---

## 19. 最初に着手する作業

1. GitHub APIから54リポジトリ一覧を取得する
2. public、private、archived、forkを分類する
3. 主要言語と最終更新日を集計する
4. MVP対象10リポジトリを選定する
5. PostgreSQLの初期スキーマを作成する
6. GitHub Appを作成する
7. Repository同期処理を実装する
8. SyftによるSBOM生成のPoCを行う
9. OSV-ScannerおよびTrivyの出力を比較する
10. Findingの正規化モデルを確定する

最初の技術的な成功条件:

```text
GitHub repository取得
  ↓
DBへ登録
  ↓
clone
  ↓
SBOM生成
  ↓
component登録
  ↓
脆弱性スキャン
  ↓
Finding登録
  ↓
管理画面またはAPIで確認
```

この縦方向の処理を1件で完成させた後、10件、54件へ水平展開する。
