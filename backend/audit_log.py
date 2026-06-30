import json
import sys
from datetime import datetime, timezone


def _normalize_repository(payload: dict) -> str:
    if payload.get("repository"):
        return str(payload.get("repository"))

    owner = payload.get("owner")
    repo = payload.get("repo")

    if owner and repo:
        return f"{owner}/{repo}"

    return ""


def _normalize_pr_number(payload: dict):
    return (
        payload.get("pr_number")
        or payload.get("source_pr_number")
        or payload.get("pull_request_number")
        or ""
    )


def log_audit_event(event_type: str, payload: dict | None = None, status: str = "ok"):
    """
    Write structured JSON logs to stdout.
    Cloud Run automatically sends stdout to Cloud Logging.
    """
    payload = payload or {}

    record = {
        "severity": "INFO" if status == "ok" else "ERROR",
        "event_type": event_type,
        "status": status,
        "created_at": datetime.now(timezone.utc).isoformat(),

        # Search-friendly top-level fields for Cloud Logging.
        "repository": _normalize_repository(payload),
        "owner": payload.get("owner", ""),
        "repo": payload.get("repo", ""),
        "pr_number": _normalize_pr_number(payload),
        "event_id": payload.get("event_id", ""),
        "review_url": payload.get("review_url", ""),
        "existing_pr_url": payload.get("existing_pr_url", ""),
        "remediation_pr_url": payload.get("remediation_pr_url", ""),

        # Full original payload.
        "payload": payload,
    }

    print(json.dumps(record, ensure_ascii=False), flush=True, file=sys.stdout)
