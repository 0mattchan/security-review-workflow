# Security Review Workflow

Security Review Workflow is a Cloud Run based workflow for GitHub pull request security review.

It reviews Kubernetes, Cloud Run, CI/CD, Dockerfile, and IAM-related pull request changes, posts security review results to GitHub, sends Slack notifications, and creates remediation pull requests after Slack approval.

## Problem

Infrastructure and CI/CD changes can introduce security risks before they reach production.

Examples include privileged containers, unsafe Kubernetes settings, plaintext secrets, risky Cloud Run configuration, overly broad IAM permissions, unsafe Dockerfile instructions, and dangerous workflow changes.

This project provides an approval-based review workflow that helps detect those risks during pull request review.

## Key Features

- GitHub pull request webhook review
- Kubernetes manifest security checks
- Cloud Run and Cloud Build configuration checks
- GitHub Actions / CI/CD risk detection
- Dockerfile risk detection
- Terraform / IAM risk detection
- GitHub review comment updates
- Slack notifications
- Slack slash commands
- Slack approval flow
- Remediation pull request creation
- Duplicate remediation PR prevention
- Review and approval history storage
- Web dashboard for review history and severity counts

## Current Status

| Area | Status |
|---|---|
| Cloud Run deployment | Completed |
| GitHub App integration | Completed |
| GitHub Webhook | Completed |
| Pull request diff review | Completed |
| GitHub review comment update | Completed |
| Slack notification | Completed |
| `/agent-status` | Completed |
| `/agent-diagnose` | Completed |
| `/agent-approve` | Completed |
| Remediation pull request creation | Completed |
| Duplicate remediation PR prevention | Completed |
| Review and approval history storage | Completed |
| Expanded security detection rules | Completed |
| Web dashboard | Completed |

## Safety Model

The default production operation mode is L2.

| Level | Behavior |
|---|---|
| L1 | Review only. Post findings and notify Slack. |
| L2 | Create remediation pull requests after approval. |
| L3 | Approval-free production changes are disabled. |

This repository is designed to keep production changes human-controlled. Remediation changes are proposed as pull requests and are not directly applied to production.

## Architecture

The workflow is built around GitHub, Cloud Run, Slack, and Cloud Storage.

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

See [docs/architecture.md](docs/architecture.md).

## Demo Guide

See [docs/demo.md](docs/demo.md).

Demo pull request:

    PR #6: test: extended security review samples

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
| `/slack/action` | POST | Slack interactive action endpoint |
| `/api/diagnose` | POST | Manifest diagnosis API |
| `/api/history` | GET | Review and approval history API |
| `/api/policy` | GET | Runtime policy API |
| `/dashboard?lang=ja` | GET | Japanese web dashboard |
| `/dashboard?lang=en` | GET | English web dashboard |

## Detection Rules

The current diff-based review includes checks for:

- Privileged containers
- Privilege escalation
- Root user execution
- Host namespaces
- Dangerous Linux capabilities
- `hostPath` volumes
- `latest` image tags
- Missing resource requests or limits
- Missing readiness or liveness probes
- Missing `imagePullPolicy`
- Plaintext sensitive environment variables
- NetworkPolicy advisories
- Risky Cloud Run settings
- Risky Cloud Build settings
- Risky GitHub Actions settings
- Dockerfile risks
- Terraform / IAM risks

## History Storage

Workflow history is stored as JSON files in Cloud Storage.

    gs://<PROJECT_ID>-security-review-history/events/YYYY/MM/DD/<timestamp>-<event_type>-<uuid>.json

History can also be read through:

    GET /api/history?limit=20

## Web Dashboard

    https://devsecops-agent-35u6z2s5dq-an.a.run.app/dashboard?lang=ja

The dashboard shows severity counts, current operation mode, and recent review history.

## Deployment

    gcloud builds submit --config deployment/cloudbuild.yaml .

## Service URL

    https://devsecops-agent-35u6z2s5dq-an.a.run.app

## Requirements and Readiness

- [Requirements checklist Japanese](docs/requirements-checklist.ja.md)
- [Production readiness Japanese](docs/production-readiness.ja.md)
- [Production readiness English](docs/production-readiness.en.md)

## Tech Stack

- Google Cloud Run
- Google Cloud Build
- Google Cloud Storage
- GitHub App
- GitHub Webhooks
- Slack App / Slash Commands
- Python
- FastAPI

## Notes

The Cloud Run service name currently remains `devsecops-agent` for compatibility with the existing deployment and webhook URL.

The public project name is Security Review Workflow.
