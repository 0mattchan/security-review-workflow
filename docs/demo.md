# Demo Guide

## Demo Goal

Show the end-to-end workflow:

1. Review a vulnerable Kubernetes pull request.
2. Post a GitHub security review comment.
3. Notify Slack.
4. Approve remediation from Slack.
5. Create or reuse a remediation pull request.
6. Store review and approval history.

## Service URL

```text
https://devsecops-agent-35u6z2s5dq-an.a.run.app
```

Slack slash commands should use this endpoint:

```text
https://devsecops-agent-35u6z2s5dq-an.a.run.app/slack/commands
```

## Demo 1: Service Status

```text
/agent-status
```

Expected response:

```text
Security Review Workflow is running.
Cloud Run: active
GitHub Webhook: configured
Slack Notifications: configured
Review target: Kubernetes manifest diffs
```

## Demo 2: Pull Request Security Review

```text
/agent-diagnose 0mattchan/devsecops-agent#2
```

Expected completion message:

```text
Security review completed.
Repository: 0mattchan/devsecops-agent
Pull Request: #2
Total Issues: 8
High: 1 / Medium: 3 / Low: 4
```

## Demo 3: Remediation Approval

```text
/agent-approve 0mattchan/devsecops-agent#2
```

Expected response when remediation already exists:

```text
Remediation pull request already exists.
Repository: 0mattchan/devsecops-agent
Source Pull Request: #2
Status: merged
Pull Request: https://github.com/0mattchan/devsecops-agent/pull/5
```

## Demo 4: Review History

```bash
curl -s "https://devsecops-agent-35u6z2s5dq-an.a.run.app/api/history?limit=5" | python -m json.tool
```

## Demo 5: Cloud Storage History Files

```bash
PROJECT_ID=$(gcloud config get-value project)
BUCKET="${PROJECT_ID}-security-review-history"
gcloud storage ls "gs://${BUCKET}/events/**" | tail -20
```
