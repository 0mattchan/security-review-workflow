from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse
import yaml
import json

app = FastAPI()

def scan_manifest(manifest):
    findings = []

    containers = (
        manifest.get("spec", {})
        .get("template", {})
        .get("spec", {})
        .get("containers", [])
    )

    for container in containers:
        image = container.get("image", "")
        security_context = container.get("securityContext", {})
        resources = container.get("resources", {})

        if security_context.get("privileged") is True:
            findings.append({
                "severity": "HIGH",
                "issue": "privileged: true",
                "recommendation": "privileged: false"
            })

        if image.endswith(":latest"):
            findings.append({
                "severity": "MEDIUM",
                "issue": "latest tag",
                "recommendation": "固定バージョンタグを使用"
            })

        if resources.get("limits") is None:
            findings.append({
                "severity": "MEDIUM",
                "issue": "resources.limits missing",
                "recommendation": "CPU/Memory limits設定"
            })

    return findings

@app.get("/", response_class=HTMLResponse)
async def home():
    return """
    <html>
    <head>
        <title>DevSecOps AI Agent</title>
    </head>
    <body>
        <h1>DevSecOps AI Agent</h1>

        <form action="/diagnose" method="post">
            <textarea
                name="manifest"
                rows="20"
                cols="100"
            ></textarea>

            <br><br>

            <button type="submit">
                Diagnose
            </button>
        </form>
    </body>
    </html>
    """

@app.post("/diagnose", response_class=HTMLResponse)
async def diagnose(manifest: str = Form(...)):
    try:
        manifest_yaml = yaml.safe_load(manifest)

        findings = scan_manifest(manifest_yaml)

        result = json.dumps(
            findings,
            indent=2,
            ensure_ascii=False
        )

        return f"""
        <html>
        <body>
            <h2>診断結果</h2>

            <pre>{result}</pre>

            <a href="/">戻る</a>
        </body>
        </html>
        """

    except Exception as e:
        return f"""
        <html>
        <body>
            <h2>エラー</h2>

            <pre>{str(e)}</pre>

            <a href="/">戻る</a>
        </body>
        </html>
        """

