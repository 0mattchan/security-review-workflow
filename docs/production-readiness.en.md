# Production Readiness Checklist

## Completed

| Area | Status |
|---|---|
| Cloud Run service | Completed |
| GitHub Webhook | Completed |
| Slack notifications | Completed |
| Slack slash commands | Completed |
| Remediation PR creation | Completed |
| Duplicate remediation PR prevention | Completed |
| Cloud Storage history | Completed |
| Dashboard | Completed |
| README / Demo / Architecture | Completed |

## Required for Production

### 1. Cloud Run configuration checks

- Ingress settings
- Authentication settings
- Allow unauthenticated access
- Service account permissions
- CPU and memory settings
- Secret-based environment variables

### 2. CI/CD configuration checks

- cloudbuild.yaml permissions
- GitHub Actions permissions
- Plaintext secret exposure
- Artifact Registry push permissions

### 3. Slack Block Kit actions

- Open PR button
- Re-run Analysis button
- Fix PR button
- Dashboard button
- Error notification UI

### 4. Structured Cloud Logging

- event_type
- owner
- repo
- pr_number
- severity
- action
- status
- remediation_pr_url

### 5. Action level controls

| Level | Behavior |
|---|---|
| L1 | Diagnosis only |
| L2 | Create remediation PR |
| L3 | Apply after approval |
