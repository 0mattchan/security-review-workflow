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
    <!doctype html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Security Review Workflow</title>
        <style>
            body {
                margin: 0;
                font-family: Arial, sans-serif;
                background: #f3f4f6;
                color: #111827;
            }

            .container {
                max-width: 960px;
                margin: 0 auto;
                padding: 32px;
            }

            .hero {
                background: linear-gradient(135deg, #111827, #1f2937);
                color: white;
                border-radius: 20px;
                padding: 28px;
                margin-bottom: 20px;
            }

            h1 {
                margin: 0 0 8px 0;
            }

            .subtitle {
                color: #d1d5db;
                line-height: 1.6;
            }

            .panel {
                background: white;
                border: 1px solid #e5e7eb;
                border-radius: 16px;
                padding: 20px;
                box-shadow: 0 1px 2px rgba(0,0,0,0.04);
            }

            textarea {
                width: 100%;
                min-height: 360px;
                box-sizing: border-box;
                border: 1px solid #d1d5db;
                border-radius: 12px;
                padding: 14px;
                font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
                font-size: 13px;
            }

            button {
                margin-top: 14px;
                background: #2563eb;
                color: white;
                border: none;
                border-radius: 999px;
                padding: 10px 18px;
                font-weight: 700;
                cursor: pointer;
            }

            .links {
                margin-top: 14px;
                display: flex;
                gap: 10px;
                flex-wrap: wrap;
            }

            a {
                color: #2563eb;
                text-decoration: none;
                font-weight: 700;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="hero">
                <h1>Security Review Workflow</h1>
                <div class="subtitle">
                    Review Kubernetes manifests and pull request security findings.
                    For production operations, use the dashboard and Slack approval workflow.
                </div>
            </div>

            <div class="panel">
                <form action="/diagnose" method="post">
                    <textarea
                        name="manifest"
                        placeholder="Paste a Kubernetes manifest here..."
                    ></textarea>

                    <br>

                    <button type="submit">Run Review</button>
                </form>

                <div class="links">
                    <a href="/dashboard?lang=ja">Dashboard JA</a>
                    <a href="/dashboard?lang=en">Dashboard EN</a>
                    <a href="/api/policy">Policy API</a>
                    <a href="/api/history?limit=5">History API</a>
                </div>
            </div>
        </div>
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

