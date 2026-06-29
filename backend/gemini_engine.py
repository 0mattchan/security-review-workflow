from google import genai
from google.cloud import secretmanager

PROJECT_ID = "project-cf538dc4-c334-46fa-aac"

def get_secret(secret_id):
    client = secretmanager.SecretManagerServiceClient()
    name = f"projects/{PROJECT_ID}/secrets/{secret_id}/versions/latest"

    response = client.access_secret_version(
        request={"name": name}
    )

    return response.payload.data.decode("UTF-8")


def analyze_with_gemini(manifest_text, scan_result):
    api_key = get_secret("gemini-api-key")
    model_name = get_secret("gemini-model")

    client = genai.Client(api_key=api_key)

    prompt = f"""
あなたは企業向けDevSecOpsセキュリティレビュー担当者です。
以下の Kubernetes Manifest とルールベース診断結果をもとに、
運用者向けに短く実用的な分析コメントを日本語で作成してください。

出力形式は必ず以下にしてください。

summary:
risk:
recommended_action:

Kubernetes Manifest:
{manifest_text}

Rule Based Scan Result:
{scan_result}
"""

    response = client.models.generate_content(
        model=model_name,
        contents=prompt
    )

    return response.text
