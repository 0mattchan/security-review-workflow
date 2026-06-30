import json
import sys
from datetime import datetime, timezone


def log_audit_event(event_type: str, payload: dict | None = None, status: str = "ok"):
    """
    Write structured JSON logs to stdout.
    Cloud Run automatically sends stdout to Cloud Logging.
    """
    record = {
        "severity": "INFO" if status == "ok" else "ERROR",
        "event_type": event_type,
        "status": status,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "payload": payload or {},
    }

    print(json.dumps(record, ensure_ascii=False), flush=True, file=sys.stdout)
