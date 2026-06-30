import os
import requests
from google.cloud import secretmanager

PROJECT_ID = os.getenv("GOOGLE_CLOUD_PROJECT", "project-cf538dc4-c334-46fa-aac")


def get_secret(secret_id: str) -> str:
    client = secretmanager.SecretManagerServiceClient()
    name = f"projects/{PROJECT_ID}/secrets/{secret_id}/versions/latest"
    response = client.access_secret_version(request={"name": name})
    return response.payload.data.decode("utf-8").strip()


def get_slack_signing_secret():
    return get_secret("slack-signing-secret")


def normalize_slack_text(value):
    if isinstance(value, str):
        return value.replace("\\n", "\n")
    if isinstance(value, list):
        return [normalize_slack_text(item) for item in value]
    if isinstance(value, dict):
        return {
            key: normalize_slack_text(item)
            for key, item in value.items()
        }
    return value


def send_slack_message(text: str, blocks=None):
    token = get_secret("slack-bot-token")
    channel = get_secret("slack-channel-id")

    payload = {
        "channel": channel,
        "text": normalize_slack_text(text),
    }

    if blocks:
        payload["blocks"] = normalize_slack_text(blocks)

    res = requests.post(
        "https://slack.com/api/chat.postMessage",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json; charset=utf-8",
        },
        json=payload,
        timeout=10,
    )

    data = res.json()

    if not data.get("ok"):
        raise RuntimeError(f"Slack API error: {data}")

    print(f"Slack notification sent: channel={channel}, ts={data.get('ts')}")
    return data
