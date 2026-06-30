# Security Review Workflow 日本語版

Security Review Workflow は、GitHub Pull Request のセキュリティレビューを自動化する Cloud Run ベースのシステムです。

Kubernetes、Cloud Run、CI/CD、Dockerfile、IAM関連の変更内容を解析し、GitHub PRコメント、Slack通知、Slack承認、修正PR作成、履歴保存、Webダッシュボード表示までを一連のワークフローとして実行します。

## 主な機能

- GitHub Pull Request の差分取得
- Kubernetes manifest のセキュリティ検出
- GitHub PRコメントの作成・更新
- Slack通知
- Slack Slash Command による操作
- 承認後の修正PR作成
- 重複修正PRの防止
- Cloud Storageへの履歴保存
- /api/history による履歴取得
- /dashboard による可視化

## Slack Commands

| コマンド | 説明 |
|---|---|
| /agent-status | サービス状態を表示 |
| /agent-diagnose owner/repo#pr_number | 指定PRを再診断 |
| /agent-approve owner/repo#pr_number | 修正PR作成、または既存修正PRを表示 |

## デモ例

/agent-diagnose 0mattchan/security-review-workflow#6

期待結果:

Security review completed.
Repository: 0mattchan/security-review-workflow
Pull Request: #2
Total Issues: 8
High: 1 / Medium: 3 / Low: 4

## 関連ドキュメント

- English README: README.en.md
- 日本語 README: README.ja.md
- Demo Guide English: docs/demo.en.md
- Architecture English: docs/architecture.en.md
- 本番運用チェックリスト: docs/production-readiness.ja.md
- Production Readiness Checklist: docs/production-readiness.en.md


## 本番初期運用モード

初期本番運用では `action_level: L1` を使用します。

- PRコメント: 有効
- Slack通知: 有効
- 修正PR作成: 無効
- 自動適用: 無効

現在の本番標準モードはL2です。L3自動適用は安全上、現時点では無効化しています。

- 要件達成チェックリスト: docs/requirements-checklist.ja.md
