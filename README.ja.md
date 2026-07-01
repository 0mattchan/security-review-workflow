# Security Review Workflow 日本語版

Security Review Workflow は、GitHub Pull Request のセキュリティレビューを支援する Cloud Run ベースのワークフローです。

Kubernetes、Cloud Run、CI/CD、Dockerfile、IAM に関連する Pull Request の変更をレビューし、GitHub にレビュー結果を投稿します。さらに Slack 通知、Slack 承認、修正 Pull Request 作成、履歴保存、Web ダッシュボード表示まで対応しています。

## 解決する課題

インフラや CI/CD の変更は、マージ前にセキュリティリスクを持ち込む可能性があります。

例として、特権コンテナ、安全でない Kubernetes 設定、平文の機密情報、危険な Cloud Run 設定、広すぎる IAM 権限、安全でない Dockerfile 記述、危険なワークフロー変更などがあります。

このプロジェクトは、Pull Request レビューの段階でそれらのリスクを検出し、承認ベースで修正 Pull Request を作成できる運用フローを提供します。

## 主な機能

- GitHub Pull Request Webhook レビュー
- Kubernetes manifest セキュリティチェック
- Cloud Run / Cloud Build 設定チェック
- GitHub Actions / CI/CD リスク検出
- Dockerfile リスク検出
- Terraform / IAM リスク検出
- GitHub review comment 更新
- Slack 通知
- Slack slash command
- Slack 承認フロー
- 修正 Pull Request 作成
- 重複修正 Pull Request 防止
- レビュー履歴・承認履歴の保存
- Web ダッシュボードでの履歴・重要度表示

## 現在の達成状況

| 項目 | 状態 |
|---|---|
| Cloud Run デプロイ | 完了 |
| GitHub App 連携 | 完了 |
| GitHub Webhook | 完了 |
| Pull Request diff レビュー | 完了 |
| GitHub review comment 更新 | 完了 |
| Slack 通知 | 完了 |
| `/agent-status` | 完了 |
| `/agent-diagnose` | 完了 |
| `/agent-approve` | 完了 |
| 修正 Pull Request 作成 | 完了 |
| 重複修正 Pull Request 防止 | 完了 |
| レビュー履歴・承認履歴保存 | 完了 |
| 拡張セキュリティ検出ルール | 完了 |
| Web ダッシュボード | 完了 |

## 安全運用モデル

本番初期運用の標準モードは L2 です。

| レベル | 動作 |
|---|---|
| L1 | レビューのみ。GitHub コメントと Slack 通知を行う。 |
| L2 | 承認後に修正 Pull Request を作成する。 |
| L3 | 承認なしの本番反映は無効。 |

このリポジトリは、本番反映を人が判断する前提で設計しています。修正内容は Pull Request として提案され、直接本番環境へ反映されません。

## アーキテクチャ

GitHub、Cloud Run、Slack、Cloud Storage を中心に構成しています。

    GitHub Pull Request
            |
            v
    GitHub Webhook
            |
            v
    Cloud Run Review Service
            |
            +--> GitHub review comment
            +--> Slack notification
            +--> Cloud Storage history
            +--> Web dashboard
            |
            v
    Slack approval
            |
            v
    Remediation pull request

詳細は [docs/architecture.md](docs/architecture.md) を参照してください。

## デモガイド

デモ手順は [docs/demo.md](docs/demo.md) を参照してください。

デモ用 Pull Request:

    PR #6: test: extended security review samples

## Slack Commands

| Command | 説明 |
|---|---|
| `/agent-status` | サービス状態を表示 |
| `/agent-diagnose owner/repo#pr_number` | 指定した Pull Request のセキュリティレビューを実行 |
| `/agent-approve owner/repo#pr_number` | 修正フローを開始、または既存の修正 Pull Request を返す |

## API Endpoints

| Endpoint | Method | 説明 |
|---|---|---|
| `/` | GET | ヘルスチェック |
| `/diagnose` | GET | 基本診断 |
| `/github/webhook` | POST | GitHub Webhook 受信 |
| `/github/test-pr-review` | POST | 手動 Pull Request レビューテスト |
| `/slack/commands` | POST | Slack slash command 共通エンドポイント |
| `/slack/action` | POST | Slack interactive action エンドポイント |
| `/api/diagnose` | POST | Manifest 診断 API |
| `/api/history` | GET | レビュー履歴・承認履歴 API |
| `/api/policy` | GET | 実行時ポリシー確認 API |
| `/dashboard?lang=ja` | GET | 日本語 Web ダッシュボード |
| `/dashboard?lang=en` | GET | 英語 Web ダッシュボード |

## 検出ルール

現在の diff ベースレビューでは、主に以下を検出します。

- privileged container
- privilege escalation
- root user 実行
- host namespace
- 危険な Linux capability
- `hostPath` volume
- `latest` image tag
- resource requests / limits の不足
- readiness / liveness probe の不足
- `imagePullPolicy` の不足
- 平文の機密情報を含む environment variable
- NetworkPolicy の注意喚起
- 危険な Cloud Run 設定
- 危険な Cloud Build 設定
- 危険な GitHub Actions 設定
- Dockerfile リスク
- Terraform / IAM リスク

## 履歴保存

ワークフロー履歴は Cloud Storage に JSON ファイルとして保存されます。

    gs://<PROJECT_ID>-security-review-history/events/YYYY/MM/DD/<timestamp>-<event_type>-<uuid>.json

履歴は API からも確認できます。

    GET /api/history?limit=20

## Web ダッシュボード

    https://devsecops-agent-35u6z2s5dq-an.a.run.app/dashboard?lang=ja

ダッシュボードでは、重要度別件数、現在の運用モード、最近のレビュー履歴を確認できます。

## デプロイ

    gcloud builds submit --config deployment/cloudbuild.yaml .

## Service URL

    https://devsecops-agent-35u6z2s5dq-an.a.run.app

## 要件・本番運用チェック

- [要件達成チェックリスト](docs/requirements-checklist.ja.md)
- [本番運用チェックリスト 日本語版](docs/production-readiness.ja.md)
- [Production readiness English](docs/production-readiness.en.md)

## 技術スタック

- Google Cloud Run
- Google Cloud Build
- Google Cloud Storage
- GitHub App
- GitHub Webhooks
- Slack App / Slash Commands
- Python
- FastAPI

## 補足

既存のデプロイ設定と Webhook URL との互換性維持のため、Cloud Run service 名は `devsecops-agent` のままにしています。

公開プロジェクト名は Security Review Workflow です。
