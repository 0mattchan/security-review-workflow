import json
import os
import uuid
from datetime import datetime, timezone

from backend.audit_log import log_audit_event

PROJECT_ID = os.getenv("GOOGLE_CLOUD_PROJECT", "project-cf538dc4-c334-46fa-aac")
HISTORY_BUCKET = os.getenv("HISTORY_BUCKET", f"{PROJECT_ID}-security-review-history")


def utc_now():
    return datetime.now(timezone.utc)


def get_storage_client():
    """
    Import Cloud Storage lazily so storage dependency issues do not prevent
    the FastAPI application from starting.
    """
    try:
        import google.cloud.storage as storage
        return storage.Client(project=PROJECT_ID)
    except Exception as e:
        log_audit_event(
            "storage_client_error",
            {"error": str(e), "project_id": PROJECT_ID},
            status="error",
        )
        raise


def record_history(event_type: str, payload: dict):
    """
    Store a workflow history event in Cloud Storage.
    This function must not break the main workflow when called via safe_record_history.
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

    client = get_storage_client()
    bucket = client.bucket(HISTORY_BUCKET)
    blob = bucket.blob(path)

    blob.upload_from_string(
        json.dumps(document, ensure_ascii=False, indent=2),
        content_type="application/json",
    )

    log_audit_event(
        event_type,
        {
            "bucket": HISTORY_BUCKET,
            "path": path,
            "event_id": event_id,
            **(payload or {}),
        },
        status="ok",
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
        log_audit_event(
            "history_record_failed",
            {"event_type": event_type, "error": str(e), "payload": payload or {}},
            status="error",
        )
        print(f"History record failed: {e}", flush=True)
        return None


def list_history(limit: int = 20):
    try:
        client = get_storage_client()
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

    except Exception as e:
        log_audit_event(
            "history_list_failed",
            {"error": str(e), "bucket": HISTORY_BUCKET},
            status="error",
        )
        return [{
            "event_type": "history_unavailable",
            "created_at": utc_now().isoformat(),
            "payload": {
                "error": str(e),
                "bucket": HISTORY_BUCKET,
            },
        }]
