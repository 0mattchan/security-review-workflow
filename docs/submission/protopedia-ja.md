# ProtoPedia 登録用テキスト

## 作品タイトル

Security Review Workflow

## 概要

Security Review Workflow は、GitHub Pull Request の変更内容を解析し、Kubernetes、Cloud Run、CI/CD、Dockerfile、IAM に関するセキュリティリスクを検出する AI 支援型の DevSecOps ワークフローです。

検出結果は GitHub のレビューコメントとして投稿され、Slack に通知されます。さらに、Slack 上で承認された場合のみ修正 Pull Request を作成します。Cloud Run 上の Web ダッシュボードでは、重要度別件数、運用モード、最近のレビュー履歴を確認できます。

本番反映は自動で行わず、L2の承認型ワークフローを標準運用とすることで、安全性と自動化のバランスを取っています。

## ストーリー

### 1. 解決したい課題と背景

クラウドネイティブ開発では、Kubernetes manifest、Cloud Run 設定、Cloud Build、GitHub Actions、Dockerfile、IAM など、多くの設定変更が Pull Request に含まれます。

しかし、これらの変更に含まれるセキュリティリスクを人手で毎回確認するには、専門知識と時間が必要です。レビュー担当者に負担が集中し、確認漏れや品質のばらつきも発生しやすくなります。

Security Review Workflow は、Pull Request の段階でリスクを検出し、GitHub、Slack、Cloud Run Dashboard を通じてレビュー・承認・履歴確認まで行えるようにすることで、DevSecOps のレビュー負担を減らします。

### 2. 想定ユーザー

- Kubernetes や Cloud Run を使う開発チーム
- GitHub Pull Request ベースで開発しているチーム
- セキュリティレビューを標準化したい DevOps / SRE / Platform Engineering チーム
- インフラや CI/CD の設定ミスをマージ前に検出したいチーム

### 3. プロダクトの特徴

- GitHub Pull Request の差分をレビュー
- Kubernetes / Cloud Run / CI/CD / Dockerfile / IAM のリスクを検出
- GitHub review comment を自動投稿
- Slack 通知と slash command に対応
- Slack 承認後に修正 Pull Request を作成
- 重複する修正 Pull Request を防止
- Cloud Storage にレビュー・承認履歴を保存
- Cloud Run ダッシュボードで重要度別件数と履歴を可視化
- 本番反映は自動化せず、人が判断する L2 安全運用を採用

## システム構成の説明

GitHub Pull Request を起点に、GitHub Webhook が Cloud Run 上の Review Service を呼び出します。Review Service は Pull Request の差分を解析し、policy.yaml と Gemini / AI 支援ロジックを組み合わせてセキュリティリスクを判定します。

結果は GitHub review comment と Slack 通知に反映され、レビュー履歴は Cloud Storage に保存されます。ユーザーは Cloud Run ダッシュボードから履歴や重要度別件数を確認できます。

Slack で承認された場合のみ、修正 Pull Request が作成されます。

## 開発素材

- Google Cloud Run
- Google Cloud Build
- Google Cloud Storage
- Secret Manager
- Gemini API / AI-assisted review logic
- GitHub App
- GitHub Webhooks
- GitHub REST API
- Slack App
- Slack Slash Commands
- Python
- FastAPI
- Docker

## タグ候補

- findy_hackathon
- GoogleCloud
- CloudRun
- Gemini
- DevOps
- DevSecOps
- Security
- GitHub
- Slack
- Kubernetes
- AI-Agent

## 関連URL

- GitHub: https://github.com/0mattchan/security-review-workflow
- Dashboard: https://devsecops-agent-35u6z2s5dq-an.a.run.app/dashboard?lang=ja
- README: https://github.com/0mattchan/security-review-workflow/blob/main/README.md
- 要件達成チェックリスト: https://github.com/0mattchan/security-review-workflow/blob/main/docs/requirements-checklist.ja.md
