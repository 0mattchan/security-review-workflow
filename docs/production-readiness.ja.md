# 本番運用チェックリスト

## 完了済み

| 項目 | 状態 |
|---|---|
| Cloud Run稼働 | 完了 |
| GitHub Webhook | 完了 |
| Slack通知 | 完了 |
| Slack Slash Commands | 完了 |
| 修正PR作成 | 完了 |
| 重複PR防止 | 完了 |
| Cloud Storage履歴保存 | 完了 |
| Dashboard | 完了 |
| README / Demo / Architecture | 完了 |

## 本番化で追加する項目

### 1. Cloud Run設定診断

- Ingress設定
- 認証有無
- allow unauthenticated
- Service Account権限
- CPU / Memory設定
- 環境変数のSecret化

### 2. CI/CD設定診断

- cloudbuild.yaml の権限確認
- GitHub Actionsの権限確認
- Secretの平文露出確認
- Artifact Registry push権限確認

### 3. Slack Block Kit対応

- Open PRボタン
- Re-run Analysisボタン
- Fix PRボタン
- Dashboardボタン
- エラー通知UI

### 4. Cloud Logging構造化ログ

- event_type
- owner
- repo
- pr_number
- severity
- action
- status
- remediation_pr_url

### 5. AIレベル制御

| Level | 内容 |
|---|---|
| L1 | 診断のみ |
| L2 | 修正PR作成まで |
| L3 | 承認後に自動適用 |

## 本番L2運用・拡張検出の達成状況

現在の本番運用モードは L2 です。

- L1: 診断、GitHub PRコメント、Slack通知、履歴保存
- L2: Slack承認後の修正PR作成、既存修正PRの重複防止
- L3: 自動適用は無効化。安全上、現時点では運用対象外

確認済みのレビュー対象:

- Kubernetes manifest
- GitHub Actions / CI/CD workflow
- Cloud Run / Cloud Build deploy設定
- Dockerfile / Container設定
- Terraform / IAM設定

確認済みデモPR:

- PR #2: Kubernetes脆弱manifestレビュー
  - Total Issues: 8
  - High: 1
  - Medium: 3
  - Low: 4
  - Decision: BLOCK

- PR #6: 拡張セキュリティレビュー
  - Total Issues: 17
  - High: 12
  - Medium: 4
  - Low: 1
  - Decision: BLOCK
  - Labels: demo, do-not-merge

安全設計:

- 自動mergeなし
- 自動適用なし
- 修正PR作成はL2承認後のみ
- 危険なデモPRは do-not-merge ラベルで保護
