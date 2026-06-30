import json
import os
import uuid
from backend.audit_log import log_audit_event
from datetime import datetime, timezone

from google.cloud import storage

PROJECT_ID = os.getenv("GOOGLE_CLOUD_PROJECT", "project-cf538dc4-c334-46fa-aac")
HISTORY_BUCKET = os.getenv("HISTORY_BUCKET", f"{PROJECT_ID}-security-review-history")


def utc_now():
    return datetime.now(timezone.utc)


def record_history(event_type: str, payload: dict):
    """
    Store a workflow history event in Cloud Storage.
    This function must not break the main workflow.
    """

    now = utc_now()
    event_id = str(uuid.uuid4())

    document = {
        "event_id": event_id,
        "event_type": event_type,
        "created_at": now.isoformat(),
        "payload": payload or {},
    }

    path = (
        f"events/{now:%Y/%m/%d}/"
        f"{now:%H%M%S}-{event_type}-{event_id}.json"
    )

    client = storage.Client(project=PROJECT_ID)
    bucket = client.bucket(HISTORY_BUCKET)
    blob = bucket.blob(path)

    blob.upload_from_string(
        json.dumps(document, ensure_ascii=False, indent=2),
        content_type="application/json",
    )

    print(f"History recorded: gs://{HISTORY_BUCKET}/{path}", flush=True)

    return {
        "bucket": HISTORY_BUCKET,
        "path": path,
        "event_id": event_id,
    }


def safe_record_history(event_type: str, payload: dict):
    try:
        return record_history(event_type, payload)
    except Exception as e:
        print(f"History record failed: {e}", flush=True)
        return None


def list_history(limit: int = 20):
    client = storage.Client(project=PROJECT_ID)
    bucket = client.bucket(HISTORY_BUCKET)

    blobs = list(client.list_blobs(bucket, prefix="events/"))
    blobs = sorted(blobs, key=lambda item: item.updated or utc_now(), reverse=True)

    records = []

    for blob in blobs[: max(1, min(limit, 100))]:
        try:
            records.append(json.loads(blob.download_as_text()))
        except Exception as e:
            records.append({
                "event_type": "history_read_error",
                "path": blob.name,
                "error": str(e),
            })

    return records
