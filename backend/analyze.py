from google.cloud import secretmanager
from google import genai
import yaml
import json

PROJECT_ID = "project-cf538dc4-c334-46fa-aac"
LOCATION = "global"

def get_secret(secret_id):
    client_sm = secretmanager.SecretManagerServiceClient()
    name = f"projects/{PROJECT_ID}/secrets/{secret_id}/versions/latest"
    response = client_sm.access_secret_version(request={"name": name})
    return response.payload.data.decode("UTF-8")

MODEL = get_secret("gemini-model")

client = genai.Client(
    vertexai=True,
    project=PROJECT_ID,
    location=LOCATION,
)

def load_yaml(path):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

manifest = load_yaml("samples/manifest.yaml")
policy = load_yaml("backend/policy.yaml")

def get_containers(manifest):
    return (
        manifest.get("spec", {})
        .get("template", {})
        .get("spec", {})
        .get("containers", [])
    )

def detect_policy_violations(manifest, policy):
    findings = []
    containers = get_containers(manifest)

    for rule in policy.get("rules", []):
        if rule.get("target") != "k8s.deployment":
            continue
        rule_id = rule.get("id")
        condition = rule.get("condition", "")

        for container in containers:
            security_context = container.get("securityContext", {})
            image = container.get("image", "")
            resources = container.get("resources", {})

            matched = False

            if "privileged" in condition:
                matched = security_context.get("privileged") is True

            elif "image" in condition and "latest" in condition:
                matched = image.endswith(":latest")

            elif "resources.limits" in condition:
                matched = resources.get("limits") is None

            elif "runAsNonRoot" in condition:
                matched = security_context.get("runAsNonRoot") is not True

            elif "allowPrivilegeEscalation" in condition:
                matched = security_context.get("allowPrivilegeEscalation") is True

            if matched:
                findings.append({
                    "rule_id": rule_id,
                    "target": rule.get("target"),
                    "severity": rule.get("severity"),
                    "description": rule.get("description"),
                    "recommendation": rule.get("recommendation"),
                    "container": container.get("name"),
                    "image": image
                })

    return findings

violations = detect_policy_violations(manifest, policy)

if not violations:
    print(json.dumps({
        "status": "PASS",
        "message": "policy.yaml に違反する項目はありません。"
    }, ensure_ascii=False, indent=2))
    exit()

prompt = f"""
あなたはDevSecOpsのセキュリティエンジニアです。

以下は policy.yaml によって検出された違反です。
新しい違反を勝手に追加しないでください。
検出済みの違反だけをもとに、説明・理由・修正例をJSONで作成してください。

必ずJSONのみで返してください。

出力形式:
{{
  "report": {{
    "manifest_type": "...",
    "manifest_name": "...",
    "findings": [
      {{
        "rule_id": "...",
        "severity": "...",
        "title": "...",
        "description": "...",
        "reasoning": "...",
        "recommendation": "...",
        "remediation_example": {{}}
      }}
    ]
  }}
}}

manifest:
{manifest}

policy_violations:
{violations}
"""

response = client.models.generate_content(
    model=MODEL,
    contents=prompt,
)

print(response.text)
