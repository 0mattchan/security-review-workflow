# デモ動画台本

想定時間: 3分〜4分

## 0. オープニング 15秒

こんにちは。Security Review Workflow を紹介します。

この作品は、GitHub Pull Request の変更内容から Kubernetes、Cloud Run、CI/CD、Dockerfile、IAM に関するセキュリティリスクを検出し、GitHub、Slack、Cloud Run Dashboard でレビューと承認を行う AI 支援型 DevSecOps ワークフローです。

## 1. 課題説明 30秒

クラウドネイティブ開発では、Kubernetes manifest や Cloud Run 設定、CI/CD 設定の変更が日常的に Pull Request に含まれます。

しかし、これらのセキュリティレビューには専門知識が必要で、確認漏れや属人化が起きやすいです。

この作品では、Pull Request の段階でリスクを検出し、レビュー、通知、承認、修正 PR 作成までを一つの流れにしました。

## 2. GitHub PR デモ 45秒

こちらがデモ用 Pull Request です。

PR には、privileged container、hostPath volume、latest image tag、危険な CI/CD 設定など、複数のリスクを含むサンプル変更が入っています。

Security Review Workflow は PR の差分を解析し、検出結果を GitHub review comment として投稿します。

## 3. Slack デモ 45秒

Slack では `/agent-status` でサービス状態を確認できます。

`/agent-diagnose owner/repo#pr_number` を実行すると、Pull Request のセキュリティレビューを手動で実行できます。

修正が必要な場合、Slack 上で承認した後に `/agent-approve owner/repo#pr_number` を実行すると、修正 Pull Request を作成します。

本番反映は自動で行わず、Pull Request として提案することで安全性を確保しています。

## 4. Web Dashboard デモ 45秒

Cloud Run 上の Web Dashboard では、重要度別の件数、現在の運用モード、最近のレビュー履歴を確認できます。

現在の標準運用は L2 です。L2 では、承認後に修正 Pull Request を作成し、本番反映は人が判断します。

## 5. 技術構成 30秒

構成は、GitHub Webhook、Cloud Run、Slack App、Cloud Storage、Cloud Build、GitHub App を中心にしています。

Pull Request を起点に Cloud Run の Review Service が動き、セキュリティ判定、GitHub コメント、Slack 通知、履歴保存、Dashboard 表示まで行います。

## 6. クロージング 15秒

Security Review Workflow は、DevSecOps のレビュー負担を減らし、Pull Request の段階で安全性を高めるためのワークフローです。

「つくる・まわす・とどける」を意識し、実際に Cloud Run 上で動作する形まで実装しました。
