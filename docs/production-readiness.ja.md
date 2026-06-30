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
