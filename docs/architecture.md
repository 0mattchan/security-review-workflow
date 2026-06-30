# Architecture

## System Context

```mermaid
flowchart LR
    User[Reviewer / Developer]
    GitHub[GitHub Repository]
    Slack[Slack Workspace]
    CloudRun[Cloud Run Service]
    SecretManager[Secret Manager]
    GCS[Cloud Storage]
    User -->|Open Pull Request| GitHub
    GitHub -->|Webhook pull_request| CloudRun
    CloudRun -->|Read PR diff| GitHub
    CloudRun -->|Create or update PR comment| GitHub
    CloudRun -->|Send notification| Slack
    Slack -->|Slash command| CloudRun
    CloudRun -->|Read tokens and signing secrets| SecretManager
    CloudRun -->|Write history JSON| GCS
```

## Review Flow

```mermaid
sequenceDiagram
    participant Dev as Developer
    participant GH as GitHub
    participant CR as Cloud Run
    participant SL as Slack
    participant CS as Cloud Storage
    Dev->>GH: Open or update pull request
    GH->>CR: POST /github/webhook
    CR->>GH: Fetch pull request diff
    CR->>CR: Analyze Kubernetes manifest changes
    CR->>GH: Create or update review comment
    CR->>SL: Send review notification
    CR->>CS: Store review history
```

## Slack Approval Flow

```mermaid
sequenceDiagram
    participant Reviewer as Reviewer
    participant Slack as Slack
    participant CR as Cloud Run
    participant GH as GitHub
    participant CS as Cloud Storage
    Reviewer->>Slack: /agent-approve owner/repo#pr
    Slack->>CR: POST /slack/commands
    CR->>GH: Check existing remediation PR
    alt Existing remediation PR found
        CR->>CS: Store duplicate prevention event
        CR-->>Slack: Return existing PR URL
    else No existing remediation PR
        CR->>GH: Create remediation branch
        CR->>GH: Update supported Kubernetes files
        CR->>GH: Create remediation pull request
        CR->>CS: Store approval history
        CR->>Slack: Post remediation PR URL
    end
```

## Data Stores

| Store | Purpose |
|---|---|
| GitHub Pull Request comments | Human-readable review report |
| GitHub Pull Requests | Remediation changes |
| Cloud Storage | Review and approval history JSON |
| Secret Manager | GitHub and Slack credentials |
