# Security Review Workflow

Security Review Workflow is a Cloud Run based automation system for GitHub pull request security review.

It reviews Kubernetes manifest changes, posts a security review report to GitHub, sends Slack notifications, and creates remediation pull requests after Slack approval.

## Current Status

| Area | Status |
|---|---|
| Cloud Run deployment | Completed |
| GitHub App integration | Completed |
| GitHub Webhook | Completed |
| Pull request diff review | Completed |
| GitHub review comment update | Completed |
| Slack notification | Completed |
| /agent-status | Completed |
| /agent-diagnose | Completed |
| /agent-approve | Completed |
| Remediation pull request creation | Completed |
| Duplicate remediation PR prevention | Completed |
| Review and approval history storage | Completed |
| Expanded Kubernetes detection rules | Completed |
| Web dashboard | Planned |

## Architecture

See [docs/architecture.md](docs/architecture.md).

## Demo Guide

See [docs/demo.md](docs/demo.md).

## Slack Commands

| Command | Description |
|---|---|
| `/agent-status` | Shows service status |
| `/agent-diagnose owner/repo#pr_number` | Runs security review for a pull request |
| `/agent-approve owner/repo#pr_number` | Starts remediation workflow or returns an existing remediation PR |

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Health check |
| `/diagnose` | GET | Basic diagnosis |
| `/github/webhook` | POST | GitHub Webhook receiver |
| `/github/test-pr-review` | POST | Manual PR review test endpoint |
| `/slack/commands` | POST | Unified Slack slash command endpoint |
| `/api/diagnose` | POST | Manifest diagnosis API |
| `/api/history` | GET | Review and approval history API |

## Detection Rules

The current diff-based Kubernetes review includes checks for privileged containers, privilege escalation, root user execution, host namespaces, dangerous capabilities, hostPath volumes, latest image tags, empty resource settings, missing probes, missing imagePullPolicy, plaintext sensitive environment variables, and NetworkPolicy advisories.

## History Storage

Workflow history is stored as JSON files in Cloud Storage.

```text
gs://<PROJECT_ID>-security-review-history/events/YYYY/MM/DD/<timestamp>-<event_type>-<uuid>.json
```

History can also be read through:

```text
GET /api/history?limit=20
```

## Deployment

```bash
gcloud builds submit --config deployment/cloudbuild.yaml .
```

## Service URL

```text
https://devsecops-agent-35u6z2s5dq-an.a.run.app
```
