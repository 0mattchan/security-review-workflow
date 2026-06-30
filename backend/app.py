import urllib.parse
import time
import hmac
import json
from google.cloud import secretmanager
import os
from backend.slack_notify import send_slack_message, get_slack_signing_secret
from backend.gemini_engine import analyze_with_gemini
from backend.vuln_scan import scan_k8s_deployment
from fastapi import Request, BackgroundTasks
from fastapi.responses import JSONResponse
from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse
import yaml
import json
import time
import hmac
import hashlib
import re



PROJECT_ID = os.getenv("GOOGLE_CLOUD_PROJECT", "project-cf538dc4-c334-46fa-aac")

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
        <title>DevSecOps Security Review</title>
    </head>
    <body>
        <h1>DevSecOps Security Review</h1>

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


from fastapi import Request
from fastapi.responses import JSONResponse

@app.post("/github/webhook")
async def github_webhook(request: Request):
    body = await request.body()

    if not verify_github_signature(request, body):
        return JSONResponse({
            "status": "error",
            "message": "invalid github signature"
        }, status_code=401)

    payload = json.loads(body.decode("utf-8"))

    event = request.headers.get("X-GitHub-Event", "")
    print(f"GitHub Webhook received: {event}")

    if event != "pull_request":
        return JSONResponse({
            "status": "ignored",
            "reason": f"unsupported event: {event}"
        })

    action = payload.get("action")
    if action not in ["opened", "synchronize", "reopened"]:
        return JSONResponse({
            "status": "ignored",
            "reason": f"unsupported action: {action}"
        })

    try:
        pr = payload["pull_request"]
        repo_info = payload["repository"]

        owner = repo_info["owner"]["login"]
        repo = repo_info["name"]
        pr_number = pr["number"]

        diff_text = get_pr_diff(owner, repo, pr_number)
        parsed = parse_diff(diff_text)
        findings = detect_risks(parsed)

        markdown = build_markdown_report_with_assessment(
            owner,
            repo,
            pr_number,
            findings,
            diff_text
        )

        comment = post_pr_comment(
            owner,
            repo,
            pr_number,
            markdown
        )

        high = len([f for f in findings if f.get("severity") == "HIGH"])
        medium = len([f for f in findings if f.get("severity") == "MEDIUM"])
        low = len([f for f in findings if f.get("severity") == "LOW"])

        try:
            slack_text = (
                f"DevSecOps Security Review completed for {owner}/{repo} PR #{pr_number}: "
                f"HIGH={high}, MEDIUM={medium}, LOW={low}"
            )

            send_slack_message(
                slack_text,
                blocks=build_slack_review_blocks(
                    owner,
                    repo,
                    pr_number,
                    findings,
                    comment.get("html_url")
                )
            )
        except Exception as slack_error:
            print(f"Slack notification failed: {slack_error}")

        return JSONResponse({
            "status": "ok",
            "repository": f"{owner}/{repo}",
            "pr_number": pr_number,
            "findings": findings,
            "comment_url": comment.get("html_url")
        })

    except Exception as e:
        print(f"GitHub webhook failed: {e}")

        try:
            send_slack_message(
                "Security Review Failed\n"
                f"Error: {str(e)}"
            )
        except Exception as slack_error:
            print(f"Slack error notification failed: {slack_error}")

        return JSONResponse({
            "status": "error",
            "message": str(e)
        }, status_code=500)

@app.post("/create-pr")
async def create_pr_api():
    return JSONResponse({
        "status": "ok",
        "message": "PR create API placeholder"
    })

@app.post("/slack/events")
async def slack_events(request: Request):
    payload = await request.json()
    print("Slack event received")
    print(payload)

    if payload.get("type") == "url_verification":
        return JSONResponse({
            "challenge": payload.get("challenge")
        })

    return JSONResponse({
        "status": "ok",
        "message": "Slack event received"
    })

@app.post("/slack/command")
async def slack_command(request: Request):
    form = await request.form()
    text = form.get("text", "")

    return JSONResponse({
        "response_type": "in_channel",
        "text": f"DevSecOps scan received: {text}"
    })






@app.get("/dashboard")
async def dashboard(lang: str = "en"):
    from html import escape
    from fastapi.responses import HTMLResponse

    is_ja = str(lang).lower().startswith("ja")

    t = {
        "title": "セキュリティレビュー ダッシュボード" if is_ja else "Security Review Workflow Dashboard",
        "subtitle": "GitHub PRレビュー、Slack承認、修正PR、履歴を確認できます。" if is_ja else "GitHub PR security review, Slack approval, remediation PR, and history overview.",
        "cloud_run": "Cloud Run",
        "github_webhook": "GitHub Webhook",
        "slack_commands": "Slack Commands",
        "history_records": "履歴件数" if is_ja else "History Records",
        "recent_history": "最近の履歴" if is_ja else "Recent History",
        "created_at": "作成日時" if is_ja else "Created At",
        "event_type": "イベント種別" if is_ja else "Event Type",
        "repository": "リポジトリ" if is_ja else "Repository",
        "pr": "PR",
        "total_issues": "検出件数" if is_ja else "Total Issues",
        "url": "URL",
        "active": "稼働中" if is_ja else "Active",
        "enabled": "有効" if is_ja else "Enabled",
        "no_history": "履歴が見つかりません。" if is_ja else "No history records found.",
        "api": "API",
        "switch": "English" if is_ja else "日本語",
        "switch_url": "/dashboard?lang=en" if is_ja else "/dashboard?lang=ja",
    }

    try:
        from backend.history_store import list_history
        history = list_history(30)
        history_error = ""
    except Exception as e:
        history = []
        history_error = str(e)

    rows = []

    for item in history:
        payload = item.get("payload") or {}
        url = (
            payload.get("review_url")
            or payload.get("existing_pr_url")
            or payload.get("remediation_pr_url")
            or payload.get("comment_url")
            or ""
        )

        url_html = f"<a href='{escape(str(url))}' target='_blank'>{escape(str(url))}</a>" if url else ""

        rows.append(
            "<tr>"
            f"<td>{escape(str(item.get('created_at', '')))}</td>"
            f"<td>{escape(str(item.get('event_type', '')))}</td>"
            f"<td>{escape(str(payload.get('owner', '')))}/{escape(str(payload.get('repo', '')))}</td>"
            f"<td>{escape(str(payload.get('pr_number') or payload.get('source_pr_number') or ''))}</td>"
            f"<td>{escape(str(payload.get('total_issues', '')))}</td>"
            f"<td>{url_html}</td>"
            "</tr>"
        )

    rows_html = "\n".join(rows) if rows else f"<tr><td colspan='6'>{t['no_history']}</td></tr>"
    error_html = f"<div class='error'>History load error: {escape(history_error)}</div>" if history_error else ""

    html = f"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>{t['title']}</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 32px; color: #1f2937; background: #f9fafb; }}
    h1 {{ margin-bottom: 8px; }}
    .top {{ display: flex; justify-content: space-between; align-items: center; gap: 16px; }}
    .subtitle {{ color: #6b7280; margin-bottom: 24px; }}
    .lang {{ background: white; border: 1px solid #d1d5db; border-radius: 999px; padding: 8px 14px; text-decoration: none; color: #111827; font-size: 14px; }}
    .cards {{ display: grid; grid-template-columns: repeat(4, minmax(160px, 1fr)); gap: 16px; margin-bottom: 28px; }}
    .card {{ background: white; border: 1px solid #e5e7eb; border-radius: 12px; padding: 18px; box-shadow: 0 1px 2px rgba(0,0,0,0.04); }}
    .label {{ color: #6b7280; font-size: 13px; margin-bottom: 8px; }}
    .value {{ font-size: 22px; font-weight: bold; }}
    table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 12px; overflow: hidden; border: 1px solid #e5e7eb; }}
    th, td {{ text-align: left; padding: 12px; border-bottom: 1px solid #e5e7eb; font-size: 14px; vertical-align: top; }}
    th {{ background: #f3f4f6; color: #374151; }}
    tr:last-child td {{ border-bottom: none; }}
    a {{ color: #2563eb; word-break: break-all; }}
    .error {{ background: #fef2f2; border: 1px solid #fecaca; color: #991b1b; padding: 12px; border-radius: 8px; margin-bottom: 16px; }}
    .footer {{ margin-top: 24px; color: #6b7280; font-size: 13px; }}
  </style>
</head>
<body>
  <div class="top">
    <div>
      <h1>{t['title']}</h1>
      <div class="subtitle">{t['subtitle']}</div>
    </div>
    <a class="lang" href="{t['switch_url']}">{t['switch']}</a>
  </div>

  {error_html}

  <div class="cards">
    <div class="card"><div class="label">{t['cloud_run']}</div><div class="value">{t['active']}</div></div>
    <div class="card"><div class="label">{t['github_webhook']}</div><div class="value">{t['enabled']}</div></div>
    <div class="card"><div class="label">{t['slack_commands']}</div><div class="value">3</div></div>
    <div class="card"><div class="label">{t['history_records']}</div><div class="value">{len(history)}</div></div>
  </div>

  <h2>{t['recent_history']}</h2>
  <table>
    <thead>
      <tr>
        <th>{t['created_at']}</th>
        <th>{t['event_type']}</th>
        <th>{t['repository']}</th>
        <th>{t['pr']}</th>
        <th>{t['total_issues']}</th>
        <th>{t['url']}</th>
      </tr>
    </thead>
    <tbody>
      {rows_html}
    </tbody>
  </table>

  <div class="footer">{t['api']}: /api/history?limit=20</div>
</body>
</html>
"""

    return HTMLResponse(html)

@app.get("/api/history")
async def api_history(limit: int = 20):
    try:
        from backend.history_store import list_history

        return JSONResponse({
            "status": "ok",
            "history": list_history(limit),
        })
    except Exception as e:
        print(f"History API failed: {e}", flush=True)
        return JSONResponse({
            "status": "error",
            "message": str(e),
            "history": [],
        }, status_code=500)

@app.post("/api/diagnose")
async def api_diagnose(request: Request):
    try:
        data = await request.json()
        manifest_text = data.get("manifest", "")

        if not manifest_text.strip():
            return JSONResponse({
                "status": "error",
                "message": "manifest is empty",
                "findings": []
            }, status_code=400)

        result = scan_manifest_text(manifest_text)

        try:
            findings = result.get("findings", [])
            high = len([f for f in findings if f.get("severity") == "HIGH"])
            medium = len([f for f in findings if f.get("severity") == "MEDIUM"])

            send_slack_message(
                "Security scan completed\n"
                f"Target: {result.get('manifest_name')}\n"
                f"HIGH: {high}, MEDIUM: {medium}"
            )

        except Exception as e:
            print(f"Slack notification failed: {e}")

        return JSONResponse({
            "status": "ok",
            **result
        })

    except Exception as e:
        return JSONResponse({
            "status": "error",
            "message": str(e),
            "findings": []
        }, status_code=500)

def scan_manifest_text(manifest_text):
    manifest = yaml.safe_load(manifest_text)
    findings = []

    containers = (
        manifest
        .get("spec", {})
        .get("template", {})
        .get("spec", {})
        .get("containers", [])
    )

    for container in containers:
        name = container.get("name", "unknown")
        image = container.get("image", "")
        security_context = container.get("securityContext", {})
        resources = container.get("resources", {})

        if security_context.get("privileged") is True:
            findings.append({
                "rule_id": "k8s_privileged_container",
                "severity": "HIGH",
                "container": name,
                "issue": "privileged: true が設定されています",
                "recommendation": "privileged: false にしてください"
            })

        if image.endswith(":latest"):
            findings.append({
                "rule_id": "k8s_image_latest_tag",
                "severity": "MEDIUM",
                "container": name,
                "issue": "latest タグが使用されています",
                "recommendation": "固定バージョンタグを使用してください"
            })

        if "limits" not in resources:
            findings.append({
                "rule_id": "k8s_resource_limits_missing",
                "severity": "MEDIUM",
                "container": name,
                "issue": "resources.limits が未設定です",
                "recommendation": "CPU/Memory limits を設定してください"
            })

        if security_context.get("runAsNonRoot") is not True:
            findings.append({
                "rule_id": "k8s_run_as_non_root_missing",
                "severity": "HIGH",
                "container": name,
                "issue": "runAsNonRoot: true が未設定です",
                "recommendation": "runAsNonRoot: true を設定してください"
            })

    return {
        "manifest_type": manifest.get("kind", "unknown"),
        "manifest_name": manifest.get("metadata", {}).get("name", "unknown"),
        "findings": findings
    }

@app.post("/slack/status")
async def slack_status(request: Request):
    body = await request.body()
    timestamp = request.headers.get("X-Slack-Request-Timestamp", "")
    signature = request.headers.get("X-Slack-Signature", "")

    if not verify_slack_signature(body, timestamp, signature):
        return JSONResponse({
            "response_type": "ephemeral",
            "text": "Invalid Slack signature"
        }, status_code=401)

    return JSONResponse({
        "response_type": "ephemeral",
        "text": (
            "DevSecOps Agent Status\n"
            "Cloud Run: Active\n"
            "GitHub: Connected\n"
            "Slack: Connected\n"
            "Gemini: Available\n"
            "Scan API: Ready"
        )
    })

@app.post("/slack/diagnose")
async def slack_diagnose(request: Request):
    body = await request.body()
    timestamp = request.headers.get("X-Slack-Request-Timestamp", "")
    signature = request.headers.get("X-Slack-Signature", "")

    if not verify_slack_signature(body, timestamp, signature):
        return JSONResponse({
            "response_type": "ephemeral",
            "text": "Invalid Slack signature"
        }, status_code=401)

    form = await request.form()
    text = form.get("text", "")

    if not text.strip():
        return JSONResponse({
            "response_type": "ephemeral",
            "text": "診断対象の Kubernetes manifest を入力してください。"
        })

    try:
        manifest = yaml.safe_load(text)
        scan_result = scan_k8s_deployment(manifest)

        findings = scan_result.get("findings", [])
        high = len([f for f in findings if f.get("severity") == "HIGH"])
        medium = len([f for f in findings if f.get("severity") == "MEDIUM"])

        decision = "BLOCK" if high > 0 else "WARN" if medium > 0 else "PASS"

        return JSONResponse({
            "response_type": "in_channel",
            "text": (
                "Security Scan Result\n"
                f"Target: {scan_result.get('manifest_name')}\n"
                f"Decision: {decision}\n"
                f"HIGH: {high}\n"
                f"MEDIUM: {medium}"
            )
        })

    except Exception as e:
        return JSONResponse({
            "response_type": "ephemeral",
            "text": f"診断に失敗しました: {str(e)}"
        })


@app.post("/slack/approve")
async def slack_approve(request: Request):
    body = await request.body()
    timestamp = request.headers.get("X-Slack-Request-Timestamp", "")
    signature = request.headers.get("X-Slack-Signature", "")

    if not verify_slack_signature(body, timestamp, signature):
        return JSONResponse({
            "response_type": "ephemeral",
            "text": "Invalid Slack signature"
        }, status_code=401)

    try:
        return JSONResponse({
            "response_type": "in_channel",
            "text": (
                "Remediation approved.\n"
                "PR automation request accepted.\n"
                "Status: Ready to create pull request."
            )
        })

    except Exception as e:
        return JSONResponse({
            "response_type": "ephemeral",
            "text": f"承認処理に失敗しました: {str(e)}"
        })


def verify_slack_signature(request_body, timestamp, signature):
    if not timestamp or not signature:
        return False

    try:
        if abs(time.time() - int(timestamp)) > 60 * 5:
            return False
    except ValueError:
        return False

    signing_secret = get_slack_signing_secret()

    base_string = f"v0:{timestamp}:{request_body.decode('utf-8')}"
    expected = "v0=" + hmac.new(
        signing_secret.encode("utf-8"),
        base_string.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(expected, signature.strip())

from backend.github_pr import get_pr_diff, post_pr_comment
from backend.diff_analyze import parse_diff, detect_risks

def build_markdown_report(owner, repo, pr_number, findings):
    high = len([f for f in findings if f.get("severity") == "HIGH"])
    medium = len([f for f in findings if f.get("severity") == "MEDIUM"])
    low = len([f for f in findings if f.get("severity") == "LOW"])

    lines = []
    lines.append("# Security Review Report")
    lines.append("")
    lines.append("## Summary")
    lines.append(f"- Repository: `{owner}/{repo}`")
    lines.append(f"- Pull Request: `#{pr_number}`")
    lines.append(f"- Total Issues: {len(findings)}")
    lines.append(f"- High: {high} / Medium: {medium} / Low: {low}")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Detected Issues")
    lines.append("")

    if not findings:
        lines.append("No security issues detected.")
    else:
        for i, finding in enumerate(findings, start=1):
            lines.append(f"### Issue {i} — {finding.get('rule_id', 'unknown')}")
            lines.append(f"**Severity:** {finding.get('severity', 'UNKNOWN')}")
            lines.append("")
            lines.append(f"**File:** `{finding.get('file', 'unknown')}`")
            lines.append("")
            lines.append(f"**Issue:** {finding.get('issue', '')}")
            lines.append("")
            lines.append(f"**Recommendation:** {finding.get('recommendation', '')}")
            lines.append("")
            lines.append("---")
            lines.append("")

    lines.append("## Notes")
    lines.append("- This comment was generated automatically by the security review workflow.")
    lines.append("- Findings are based on changed diff lines only.")

    return "\n".join(lines)

@app.post("/github/test-pr-review")
async def github_test_pr_review(request: Request):
    try:
        data = await request.json()

        owner = data.get("owner")
        repo = data.get("repo")
        pr_number = data.get("pr_number")

        if not owner or not repo or not pr_number:
            return JSONResponse({
                "status": "error",
                "message": "owner, repo, pr_number are required"
            }, status_code=400)

        diff_text = get_pr_diff(owner, repo, pr_number)
        parsed = parse_diff(diff_text)
        findings = detect_risks(parsed)

        markdown = build_markdown_report_with_assessment(
            owner,
            repo,
            pr_number,
            findings,
            diff_text
        )

        comment = post_pr_comment(
            owner,
            repo,
            pr_number,
            markdown
        )

        return JSONResponse({
            "status": "ok",
            "findings": findings,
            "comment_url": comment.get("html_url")
        })

    except Exception as e:
        return JSONResponse({
            "status": "error",
            "message": str(e)
        }, status_code=500)


# --- GitHub webhook signature verification ---

def get_github_webhook_secret():
    client = secretmanager.SecretManagerServiceClient()
    name = f"projects/{PROJECT_ID}/secrets/github-webhook-secret/versions/latest"
    response = client.access_secret_version(request={"name": name})
    return response.payload.data.decode("utf-8").strip()


def verify_github_signature(request: Request, body: bytes) -> bool:
    signature = request.headers.get("X-Hub-Signature-256")

    if not signature:
        print("GitHub signature missing")
        return False

    try:
        secret = get_github_webhook_secret()
        expected = "sha256=" + hmac.new(
            secret.encode("utf-8"),
            body,
            hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(expected, signature.strip())

    except Exception as e:
        print(f"GitHub signature verification error: {e}")
        return False



# --- Risk assessment integration for PR comments ---

def _normalize_assessment_text(value):
    text = str(value or "").strip()

    cleanup = {
        "Gemini": "the review workflow",
        "AI": "automated review",
        "summary:": "### Summary\n",
        "risk:": "### Risk\n",
        "recommended_action:": "### Recommended Action\n",
        "recommendation:": "### Recommended Action\n",
    }

    for old, new in cleanup.items():
        text = text.replace(old, new)

    return text


def build_markdown_report_with_assessment(owner, repo, pr_number, findings, diff_text):
    base_markdown = build_markdown_report(owner, repo, pr_number, findings)

    if not findings:
        return base_markdown

    try:
        from backend.gemini_engine import analyze_with_gemini

        result = analyze_with_gemini(
            diff_text,
            {
                "type": "pull_request_diff",
                "repository": f"{owner}/{repo}",
                "pr_number": pr_number,
                "findings": findings,
            },
        )

        if isinstance(result, dict):
            summary = result.get("summary") or result.get("analysis") or ""
            risk = result.get("risk") or ""
            recommended_action = (
                result.get("recommended_action")
                or result.get("recommendation")
                or ""
            )

            assessment_parts = []

            if summary:
                assessment_parts.extend(["### Summary", "", str(summary), ""])

            if risk:
                assessment_parts.extend(["### Risk", "", str(risk), ""])

            if recommended_action:
                assessment_parts.extend([
                    "### Recommended Action",
                    "",
                    str(recommended_action),
                    "",
                ])

            assessment_text = "\n".join(assessment_parts).strip()
        else:
            assessment_text = _normalize_assessment_text(result)

        if not assessment_text:
            assessment_text = "No additional risk assessment was generated for this review."

    except Exception as e:
        print(f"Risk assessment failed: {e}")
        assessment_text = (
            "Additional risk assessment was unavailable for this run.\n\n"
            "Please review the rule-based findings above."
        )

    section_text = "\n".join([
        "## Risk Assessment",
        "",
        assessment_text,
        "",
        "---",
        "",
    ])

    marker = "## Notes"
    if marker in base_markdown:
        return base_markdown.replace(marker, section_text + marker)

    return base_markdown + "\n\n" + section_text


# --- Slack Block Kit formatting for PR review ---

def build_slack_review_blocks(owner, repo, pr_number, findings, comment_url=None):
    high = len([f for f in findings if f.get("severity") == "HIGH"])
    medium = len([f for f in findings if f.get("severity") == "MEDIUM"])
    low = len([f for f in findings if f.get("severity") == "LOW"])

    issue_lines = []

    for f in findings[:8]:
        severity = f.get("severity", "INFO")
        rule_id = f.get("rule_id", "unknown_rule")
        file_name = f.get("file", "unknown_file")

        icon = "[HIGH]" if severity == "HIGH" else "[MEDIUM]" if severity == "MEDIUM" else "[INFO]"

        issue_lines.append(
            f"{icon} *{severity}* `{rule_id}`\\n"
            f"• `{file_name}`\\n"
            f"• {f.get('issue', '')}"
        )

    if not issue_lines:
        issue_text = "No security issues were detected in the PR diff."
    else:
        issue_text = "\\n\\n".join(issue_lines)

    pr_url = f"https://github.com/{owner}/{repo}/pull/{pr_number}"
    dashboard_base_url = (
        os.getenv("DASHBOARD_URL")
        or os.getenv("SERVICE_URL")
        or "https://devsecops-agent-35u6z2s5dq-an.a.run.app"
    ).rstrip("/")
    dashboard_url = f"{dashboard_base_url}/dashboard?lang=en"

    buttons = []

    if comment_url:
        buttons.append({
            "type": "button",
            "text": {
                "type": "plain_text",
                "text": "Open Review"
            },
            "url": comment_url
        })

    action_value = f"{owner}/{repo}#{pr_number}"

    buttons.extend([
        {
            "type": "button",
            "text": {
                "type": "plain_text",
                "text": "Open PR"
            },
            "url": pr_url
        },
        {
            "type": "button",
            "text": {
                "type": "plain_text",
                "text": "Re-run Analysis"
            },
            "action_id": "rerun_analysis",
            "value": action_value
        },
        {
            "type": "button",
            "text": {
                "type": "plain_text",
                "text": "Fix PR"
            },
            "style": "primary",
            "action_id": "fix_pr",
            "value": action_value
        },
        {
            "type": "button",
            "text": {
                "type": "plain_text",
                "text": "Dashboard"
            },
            "url": dashboard_url
        }
    ])

    return [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "DevSecOps Security Review"
            }
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Repository:*\\n`{owner}/{repo}`"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Pull Request:*\\n`#{pr_number}`"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*High:*\\n{high}"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Medium:*\\n{medium}"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Low:*\\n{low}"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Total:*\\n{len(findings)}"
                }
            ]
        },
        {
            "type": "divider"
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Detected Issues*\\n\\n{issue_text}"
            }
        },
        {
            "type": "actions",
            "elements": buttons
        }
    ]


# --- Slack slash command unified endpoint ---

@app.post("/slack/commands")
async def slack_commands(request: Request, background_tasks: BackgroundTasks):
    import time
    import hmac
    import hashlib
    from urllib.parse import parse_qs
    from fastapi.responses import JSONResponse
    from backend.slack_notify import get_slack_signing_secret

    body = await request.body()
    timestamp = request.headers.get("X-Slack-Request-Timestamp", "")
    signature = request.headers.get("X-Slack-Signature", "")

    if not timestamp or not signature:
        return JSONResponse(
            {"response_type": "ephemeral", "text": "Missing Slack signature headers"},
            status_code=401,
        )

    try:
        timestamp_int = int(timestamp)
    except ValueError:
        return JSONResponse(
            {"response_type": "ephemeral", "text": "Invalid Slack timestamp"},
            status_code=401,
        )

    if abs(time.time() - timestamp_int) > 60 * 5:
        return JSONResponse(
            {"response_type": "ephemeral", "text": "Slack request timestamp is too old"},
            status_code=401,
        )

    signing_secret = get_slack_signing_secret().strip()
    base_string = f"v0:{timestamp}:{body.decode('utf-8')}".encode("utf-8")

    expected = "v0=" + hmac.new(
        signing_secret.encode("utf-8"),
        base_string,
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected, signature):
        return JSONResponse(
            {"response_type": "ephemeral", "text": "Invalid Slack signature"},
            status_code=401,
        )

    form = parse_qs(body.decode("utf-8"))
    command = form.get("command", [""])[0]
    text = form.get("text", [""])[0].strip()

    if command == "/agent-status":
        status_lang = text.strip().lower()
        if status_lang in ["ja", "jp", "japanese", "日本語"]:
            status_text = (
                "Security Review Workflow は稼働中です。\n"
                "Cloud Run: 稼働中\n"
                "GitHub Webhook: 設定済み\n"
                "Slack通知: 設定済み\n"
                "レビュー対象: Kubernetes manifest の差分"
            )
        else:
            status_text = (
                "Security Review Workflow is running.\n"
                "Cloud Run: active\n"
                "GitHub Webhook: configured\n"
                "Slack Notifications: configured\n"
                "Review target: Kubernetes manifest diffs"
            )

        return JSONResponse({
            "response_type": "ephemeral",
            "text": status_text,
        })

    if command == "/agent-diagnose":
        diagnose_lang = "ja" if any(word in text.lower().split() for word in ["ja", "jp", "japanese", "日本語"]) else "en"
        diagnose_target = " ".join([
            word for word in text.split()
            if word.lower() not in ["ja", "jp", "japanese", "日本語", "en", "english", "英語"]
        ]).strip()

        if diagnose_lang == "ja":
            usage = (
                "使い方:\n"
                "/agent-diagnose owner/repo#pr_number ja\n"
                "例:\n"
                "/agent-diagnose 0mattchan/devsecops-agent#2 ja"
            )
        else:
            usage = (
                "Usage:\n"
                "/agent-diagnose owner/repo#pr_number en\n"
                "Example:\n"
                "/agent-diagnose 0mattchan/devsecops-agent#2 en"
            )

        if not diagnose_target:
            return JSONResponse({
                "response_type": "ephemeral",
                "text": usage,
            })

        try:
            import re

            match = re.search(r"([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)#(\d+)", diagnose_target)

            if not match:
                return JSONResponse({
                    "response_type": "ephemeral",
                    "text": usage,
                })

            owner = match.group(1)
            repo = match.group(2)
            pr_number = int(match.group(3))
            response_url = form.get("response_url", [""])[0]

            print(f"Slash diagnose accepted: {owner}/{repo}#{pr_number}", flush=True)

            background_tasks.add_task(
                run_slack_diagnose_v2,
                owner,
                repo,
                pr_number,
                response_url,
            )

            if diagnose_lang == "ja":
                started_text = (
                    "セキュリティレビューを開始しました。\n"
                    f"Repository: {owner}/{repo}\n"
                    f"Pull Request: #{pr_number}\n"
                    "結果はまもなく投稿されます。"
                )
            else:
                started_text = (
                    "Security review started.\n"
                    f"Repository: {owner}/{repo}\n"
                    f"Pull Request: #{pr_number}\n"
                    "The result will be posted shortly."
                )

            return JSONResponse({
                "response_type": "ephemeral",
                "text": started_text,
            }, background=background_tasks)

        except Exception as e:
            print(f"Slash diagnose request failed: {e}", flush=True)
            return JSONResponse({
                "response_type": "ephemeral",
                "text": "セキュリティレビューのリクエストに失敗しました。Cloud Run logs を確認してください。" if diagnose_lang == "ja" else "Security review request failed. Please check Cloud Run logs.",
            })

    if command == "/agent-approve":
        approve_lang = "ja" if any(word in text.lower().split() for word in ["ja", "jp", "japanese", "日本語"]) else "en"
        approve_target = " ".join([
            word for word in text.split()
            if word.lower() not in ["ja", "jp", "japanese", "日本語", "en", "english", "英語"]
        ]).strip()

        if approve_lang == "ja":
            usage = (
                "使い方:\n"
                "/agent-approve owner/repo#pr_number ja\n"
                "例:\n"
                "/agent-approve 0mattchan/devsecops-agent#2 ja"
            )
        else:
            usage = (
                "Usage:\n"
                "/agent-approve owner/repo#pr_number en\n"
                "Example:\n"
                "/agent-approve 0mattchan/devsecops-agent#2 en"
            )

        if not approve_target:
            return JSONResponse({
                "response_type": "ephemeral",
                "text": usage,
            })

        try:
            import re
            from backend.github_pr import find_existing_remediation_pr

            match = re.search(r"([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)#(\d+)", approve_target)

            if not match:
                return JSONResponse({
                    "response_type": "ephemeral",
                    "text": usage,
                })

            owner = match.group(1)
            repo = match.group(2)
            pr_number = int(match.group(3))
            response_url = form.get("response_url", [""])[0]

            print(f"Slash approve accepted: {owner}/{repo}#{pr_number}", flush=True)

            existing_pr = find_existing_remediation_pr(owner, repo, pr_number)

            if existing_pr:
                pr_url = existing_pr.get("html_url", "")
                pr_state = existing_pr.get("state", "unknown")
                merged_at = existing_pr.get("merged_at")
                head_ref = (existing_pr.get("head") or {}).get("ref")
                display_state = "merged" if merged_at else pr_state

                try:
                    from backend.history_store import safe_record_history
                    safe_record_history("approval_duplicate_prevented", {
                        "owner": owner,
                        "repo": repo,
                        "source_pr_number": pr_number,
                        "existing_pr_url": pr_url,
                        "existing_pr_state": display_state,
                        "existing_branch": head_ref,
                    })
                except Exception as history_error:
                    print(f"Approval history record failed: {history_error}", flush=True)

                if approve_lang == "ja":
                    existing_text = (
                        "修正PRは既に存在します。\n"
                        f"Repository: {owner}/{repo}\n"
                        f"Source Pull Request: #{pr_number}\n"
                        f"Status: {display_state}\n"
                        f"Branch: {head_ref}\n"
                        f"Pull Request: {pr_url}"
                    )
                else:
                    existing_text = (
                        "Remediation pull request already exists.\n"
                        f"Repository: {owner}/{repo}\n"
                        f"Source Pull Request: #{pr_number}\n"
                        f"Status: {display_state}\n"
                        f"Branch: {head_ref}\n"
                        f"Pull Request: {pr_url}"
                    )

                return JSONResponse({
                    "response_type": "ephemeral",
                    "text": existing_text,
                })

            background_tasks.add_task(
                run_slack_approve,
                owner,
                repo,
                pr_number,
                response_url,
            )

            if approve_lang == "ja":
                started_text = (
                    "修正ワークフローを開始しました。\n"
                    f"Repository: {owner}/{repo}\n"
                    f"Pull Request: #{pr_number}\n"
                    "対応可能な修正がある場合、修正PRを作成します。"
                )
            else:
                started_text = (
                    "Remediation workflow started.\n"
                    f"Repository: {owner}/{repo}\n"
                    f"Pull Request: #{pr_number}\n"
                    "A remediation pull request will be created if supported fixes are available."
                )

            return JSONResponse({
                "response_type": "ephemeral",
                "text": started_text,
            }, background=background_tasks)

        except Exception as e:
            print(f"Slash approve request failed: {e}", flush=True)
            return JSONResponse({
                "response_type": "ephemeral",
                "text": "修正ワークフローのリクエストに失敗しました。Cloud Run logs を確認してください。" if approve_lang == "ja" else "Remediation workflow request failed. Please check Cloud Run logs.",
            })

    return JSONResponse({
        "response_type": "ephemeral",
        "text": f"Unsupported command: {command}",
    })


# --- Slack delayed response worker for slash command diagnosis ---

def run_slack_diagnose(owner: str, repo: str, pr_number: int, response_url: str):
    import requests

    try:
        from backend.github_pr import get_pr_diff, post_pr_comment
        from backend.diff_analyze import parse_diff, detect_risks

        diff_text = get_pr_diff(owner, repo, pr_number)
        findings = detect_risks(parse_diff(diff_text))

        def build_fallback_markdown_report(reason: str = "") -> str:
            high_count = len([f for f in findings if f.get("severity") == "HIGH"])
            medium_count = len([f for f in findings if f.get("severity") == "MEDIUM"])
            low_count = len([f for f in findings if f.get("severity") == "LOW"])

            lines = [
                "<!-- devsecops-agent:security-review -->",
                f"# Security Review for {owner}/{repo} PR #{pr_number}",
                "",
                "AI assessment did not finish in time, so this report was generated from deterministic security rules.",
                "",
                "## Summary",
                f"- Total Issues: {len(findings)}",
                f"- High: {high_count}",
                f"- Medium: {medium_count}",
                f"- Low: {low_count}",
                "",
            ]

            if reason:
                lines.extend([
                    "## Fallback Reason",
                    f"- {reason}",
                    "",
                ])

            lines.append("## Findings")

            if not findings:
                lines.append("- No security findings detected by deterministic rules.")
            else:
                for index, finding in enumerate(findings, start=1):
                    if not isinstance(finding, dict):
                        lines.append(f"### {index}. Security finding")
                        lines.append(f"- Detail: {finding}")
                        lines.append("")
                        continue

                    severity = finding.get("severity", "UNKNOWN")
                    title = (
                        finding.get("title")
                        or finding.get("rule_id")
                        or finding.get("id")
                        or finding.get("message")
                        or "Security finding"
                    )
                    file_path = (
                        finding.get("file")
                        or finding.get("path")
                        or finding.get("file_path")
                        or finding.get("filename")
                        or ""
                    )
                    recommendation = (
                        finding.get("recommendation")
                        or finding.get("remediation")
                        or finding.get("fix")
                        or finding.get("suggestion")
                        or ""
                    )

                    lines.append(f"### {index}. [{severity}] {title}")

                    if file_path:
                        lines.append(f"- File: `{file_path}`")

                    if recommendation:
                        lines.append(f"- Recommendation: {recommendation}")

                    lines.append("")

            lines.extend([
                "---",
                "_Generated by DevSecOps Agent fallback report builder._",
            ])

            return "\n".join(lines)

        def build_markdown_report_with_timeout() -> str:
            import concurrent.futures
            import os

            timeout_seconds = int(os.environ.get("DIAGNOSE_REPORT_TIMEOUT_SECONDS", "45"))

            executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
            future = executor.submit(
                build_markdown_report_with_assessment,
                owner,
                repo,
                pr_number,
                findings,
                diff_text,
            )

            try:
                return future.result(timeout=timeout_seconds)

            except concurrent.futures.TimeoutError:
                try:
                    from backend.audit_log import log_audit_event
                    log_audit_event("diagnose_report_build_timeout", {
                        "owner": owner,
                        "repo": repo,
                        "pr_number": pr_number,
                        "total_issues": len(findings),
                        "timeout_seconds": timeout_seconds,
                    }, status="warning")
                except Exception as audit_error:
                    print(f"Diagnose report timeout audit log failed: {audit_error}", flush=True)

                return build_fallback_markdown_report(
                    f"AI assessment timed out after {timeout_seconds} seconds."
                )

            except Exception as report_error:
                try:
                    from backend.audit_log import log_audit_event
                    log_audit_event("diagnose_report_build_failed", {
                        "owner": owner,
                        "repo": repo,
                        "pr_number": pr_number,
                        "total_issues": len(findings),
                        "error": str(report_error),
                    }, status="error")
                except Exception as audit_error:
                    print(f"Diagnose report failure audit log failed: {audit_error}", flush=True)

                return build_fallback_markdown_report(str(report_error))

            finally:
                executor.shutdown(wait=False, cancel_futures=True)

        markdown = build_markdown_report_with_timeout()

        comment = post_pr_comment(owner, repo, pr_number, markdown)

        high = len([f for f in findings if f.get("severity") == "HIGH"])
        medium = len([f for f in findings if f.get("severity") == "MEDIUM"])
        low = len([f for f in findings if f.get("severity") == "LOW"])

        message = (
            "Security review completed.\n"
            f"Repository: {owner}/{repo}\n"
            f"Pull Request: #{pr_number}\n"
            f"Total Issues: {len(findings)}\n"
            f"High: {high} / Medium: {medium} / Low: {low}\n"
            f"Review: {comment.get('html_url')}"
        )

        requests.post(
            response_url,
            json={
                "response_type": "ephemeral",
                "text": message,
            },
            timeout=10,
        )

    except Exception as e:
        print(f"Slash diagnose background task failed: {e}")

        try:
            requests.post(
                response_url,
                json={
                    "response_type": "ephemeral",
                    "text": "Security review failed. Please check Cloud Run logs.",
                },
                timeout=10,
            )
        except Exception as post_error:
            print(f"Failed to post Slack delayed response: {post_error}")



# --- Slack approve remediation worker ---

def run_slack_approve(owner: str, repo: str, pr_number: int, response_url: str = ""):
    import requests

    print(f"Slash approve started: {owner}/{repo}#{pr_number}")

    try:
        from backend.audit_log import log_audit_event
        log_audit_event("approval_worker_started", {
            "owner": owner,
            "repo": repo,
            "pr_number": pr_number,
        })
    except Exception as audit_error:
        print(f"Approval worker start audit log failed: {audit_error}", flush=True)

    try:
        from backend.github_pr import create_k8s_remediation_pr
        from backend.slack_notify import send_slack_message

        result = create_k8s_remediation_pr(owner, repo, pr_number)

        status = result.get("status")

        if status == "no_changes":
            message = (
                "Remediation review completed.\n"
                f"Repository: {owner}/{repo}\n"
                f"Pull Request: #{pr_number}\n"
                "No supported Kubernetes remediation changes were found."
            )
        elif status == "existing":
            pr_data = result.get("pull_request") or {}
            pr_url = pr_data.get("html_url", "")
            pr_state = pr_data.get("state", "unknown")
            merged_at = pr_data.get("merged_at")
            display_state = "merged" if merged_at else pr_state

            message = (
                "Remediation pull request already exists.\n"
                f"Repository: {owner}/{repo}\n"
                f"Source Pull Request: #{pr_number}\n"
                f"Status: {display_state}\n"
                f"Branch: {result.get('branch')}\n"
                f"Pull Request: {pr_url}"
            )
        else:
            pr_data = result.get("pull_request") or {}
            pr_url = pr_data.get("html_url", "")
            changed_files = result.get("changed_files", [])
            applied_changes = result.get("applied_changes", [])

            message = (
                "Remediation pull request created.\n"
                f"Repository: {owner}/{repo}\n"
                f"Source Pull Request: #{pr_number}\n"
                f"Branch: {result.get('branch')}\n"
                f"Files changed: {len(changed_files)}\n"
                f"Changes: {', '.join(applied_changes) if applied_changes else 'N/A'}\n"
                f"Pull Request: {pr_url}"
            )

        try:
            from backend.history_store import safe_record_history
            pr_data = result.get("pull_request") or {}
            completion_payload = {
                "owner": owner,
                "repo": repo,
                "source_pr_number": pr_number,
                "status": result.get("status"),
                "branch": result.get("branch"),
                "remediation_pr_url": pr_data.get("html_url"),
                "changed_files": result.get("changed_files", []),
                "applied_changes": result.get("applied_changes", []),
            }
            safe_record_history("approval_completed", completion_payload)

            try:
                from backend.audit_log import log_audit_event
                log_audit_event("approval_worker_completed", completion_payload)
            except Exception as audit_error:
                print(f"Approval worker completion audit log failed: {audit_error}", flush=True)
        except Exception as history_error:
            print(f"Approval history record failed: {history_error}", flush=True)

        try:
            send_slack_message(message)
            print("Slash approve channel notification posted")
        except Exception as notify_error:
            print(f"Failed to send Slack approve channel notification: {notify_error}")

        print(f"Slash approve completed: {owner}/{repo}#{pr_number}")

    except Exception as e:
        print(f"Slash approve failed: {e}")

        try:
            from backend.audit_log import log_audit_event
            log_audit_event("approval_worker_failed", {
                "owner": owner,
                "repo": repo,
                "pr_number": pr_number,
                "error": str(e),
            }, status="error")
        except Exception as audit_error:
            print(f"Approval worker failure audit log failed: {audit_error}", flush=True)

        error_message = (
            "Remediation workflow failed.\n"
            f"Repository: {owner}/{repo}\n"
            f"Pull Request: #{pr_number}\n"
            "Please check Cloud Run logs."
        )

        try:
            from backend.slack_notify import send_slack_message
            send_slack_message(error_message)
        except Exception as notify_error:
            print(f"Failed to send Slack approve error notification: {notify_error}")


# --- Slack diagnose worker v2 ---

def run_slack_diagnose_v2(owner: str, repo: str, pr_number: int, response_url: str = ""):
    import requests

    print(f"Slash diagnose started: {owner}/{repo}#{pr_number}", flush=True)

    try:
        from backend.audit_log import log_audit_event
        log_audit_event("diagnose_worker_started", {
            "owner": owner,
            "repo": repo,
            "pr_number": pr_number,
        })
    except Exception as audit_error:
        print(f"Diagnose worker start audit log failed: {audit_error}", flush=True)

    try:
        from backend.github_pr import get_pr_diff, post_pr_comment
        from backend.diff_analyze import parse_diff, detect_risks
        from backend.slack_notify import send_slack_message

        try:
            from backend.audit_log import log_audit_event
            log_audit_event("diagnose_get_diff_started", {
                "owner": owner,
                "repo": repo,
                "pr_number": pr_number,
            })
        except Exception as audit_error:
            print(f"Diagnose get diff start audit log failed: {audit_error}", flush=True)

        diff_text = get_pr_diff(owner, repo, pr_number)

        try:
            from backend.audit_log import log_audit_event
            log_audit_event("diagnose_get_diff_completed", {
                "owner": owner,
                "repo": repo,
                "pr_number": pr_number,
                "diff_chars": len(diff_text or ""),
            })
        except Exception as audit_error:
            print(f"Diagnose get diff completion audit log failed: {audit_error}", flush=True)

        findings = detect_risks(parse_diff(diff_text))

        try:
            from backend.audit_log import log_audit_event
            log_audit_event("diagnose_analysis_completed", {
                "owner": owner,
                "repo": repo,
                "pr_number": pr_number,
                "total_issues": len(findings),
            })
        except Exception as audit_error:
            print(f"Diagnose analysis audit log failed: {audit_error}", flush=True)

        try:
            from backend.audit_log import log_audit_event
            log_audit_event("diagnose_report_build_started", {
                "owner": owner,
                "repo": repo,
                "pr_number": pr_number,
                "total_issues": len(findings),
            })
        except Exception as audit_error:
            print(f"Diagnose report build start audit log failed: {audit_error}", flush=True)

        markdown = build_markdown_report_with_assessment(
            owner,
            repo,
            pr_number,
            findings,
            diff_text,
        )

        try:
            from backend.audit_log import log_audit_event
            log_audit_event("diagnose_report_build_completed", {
                "owner": owner,
                "repo": repo,
                "pr_number": pr_number,
                "total_issues": len(findings),
                "markdown_chars": len(markdown or ""),
            })
        except Exception as audit_error:
            print(f"Diagnose report build completion audit log failed: {audit_error}", flush=True)

        try:
            from backend.audit_log import log_audit_event
            log_audit_event("diagnose_post_comment_started", {
                "owner": owner,
                "repo": repo,
                "pr_number": pr_number,
            })
        except Exception as audit_error:
            print(f"Diagnose post comment start audit log failed: {audit_error}", flush=True)

        comment = post_pr_comment(owner, repo, pr_number, markdown)

        try:
            from backend.audit_log import log_audit_event
            log_audit_event("diagnose_post_comment_completed", {
                "owner": owner,
                "repo": repo,
                "pr_number": pr_number,
                "review_url": comment.get("html_url"),
            })
        except Exception as audit_error:
            print(f"Diagnose post comment completion audit log failed: {audit_error}", flush=True)

        high = len([f for f in findings if f.get("severity") == "HIGH"])
        medium = len([f for f in findings if f.get("severity") == "MEDIUM"])
        low = len([f for f in findings if f.get("severity") == "LOW"])

        message = (
            "Security review completed.\n"
            f"Repository: {owner}/{repo}\n"
            f"Pull Request: #{pr_number}\n"
            f"Total Issues: {len(findings)}\n"
            f"High: {high} / Medium: {medium} / Low: {low}\n"
            f"Review: {comment.get('html_url')}"
        )

        try:
            from backend.history_store import safe_record_history
            safe_record_history("diagnose_completed", {
                "owner": owner,
                "repo": repo,
                "pr_number": pr_number,
                "total_issues": len(findings),
                "high": high,
                "medium": medium,
                "low": low,
                "review_url": comment.get("html_url"),
            })
        except Exception as history_error:
            print(f"Diagnose history record failed: {history_error}", flush=True)

        if response_url and "example.com" not in response_url:
            try:
                requests.post(
                    response_url,
                    json={
                        "response_type": "ephemeral",
                        "text": message,
                    },
                    timeout=5,
                )
                print("Slash diagnose delayed response posted", flush=True)
            except Exception as response_error:
                print(f"Failed to post Slack diagnose delayed response: {response_error}", flush=True)

        try:
            from backend.audit_log import log_audit_event
            log_audit_event("diagnose_notification_started", {
                "owner": owner,
                "repo": repo,
                "pr_number": pr_number,
                "review_url": comment.get("html_url"),
            })
        except Exception as audit_error:
            print(f"Diagnose notification start audit log failed: {audit_error}", flush=True)

        try:
            send_slack_message(message)
            print("Slash diagnose channel notification posted", flush=True)

            try:
                from backend.audit_log import log_audit_event
                log_audit_event("diagnose_notification_completed", {
                    "owner": owner,
                    "repo": repo,
                    "pr_number": pr_number,
                    "review_url": comment.get("html_url"),
                })
            except Exception as audit_error:
                print(f"Diagnose notification completion audit log failed: {audit_error}", flush=True)

        except Exception as notify_error:
            print(f"Failed to send Slack diagnose channel notification: {notify_error}", flush=True)

            try:
                from backend.audit_log import log_audit_event
                log_audit_event("diagnose_notification_failed", {
                    "owner": owner,
                    "repo": repo,
                    "pr_number": pr_number,
                    "review_url": comment.get("html_url"),
                    "error": str(notify_error),
                }, status="error")
            except Exception as audit_error:
                print(f"Diagnose notification failure audit log failed: {audit_error}", flush=True)

        try:
            from backend.audit_log import log_audit_event
            log_audit_event("diagnose_worker_completed", {
                "owner": owner,
                "repo": repo,
                "pr_number": pr_number,
                "total_issues": len(findings),
                "high": high,
                "medium": medium,
                "low": low,
                "review_url": comment.get("html_url"),
            })
        except Exception as audit_error:
            print(f"Diagnose worker completion audit log failed: {audit_error}", flush=True)

        print(f"Slash diagnose completed: {owner}/{repo}#{pr_number}", flush=True)

    except Exception as e:
        print(f"Slash diagnose failed: {e}", flush=True)

        try:
            from backend.audit_log import log_audit_event
            log_audit_event("diagnose_worker_failed", {
                "owner": owner,
                "repo": repo,
                "pr_number": pr_number,
                "error": str(e),
            }, status="error")
        except Exception as audit_error:
            print(f"Diagnose worker failure audit log failed: {audit_error}", flush=True)

        error_message = (
            "Security review failed.\n"
            f"Repository: {owner}/{repo}\n"
            f"Pull Request: #{pr_number}\n"
            "Please check Cloud Run logs."
        )

        try:
            from backend.slack_notify import send_slack_message
            send_slack_message(error_message)
        except Exception as notify_error:
            print(f"Failed to send Slack diagnose error notification: {notify_error}", flush=True)


# --- Slack interactive button endpoint ---

def verify_slack_action_signature(headers, raw_body: bytes) -> bool:
    timestamp = headers.get("x-slack-request-timestamp")
    slack_signature = headers.get("x-slack-signature")

    if not timestamp or not slack_signature:
        return False

    try:
        if abs(time.time() - int(timestamp)) > 60 * 5:
            return False
    except Exception:
        return False

    secret = get_slack_signing_secret()
    base = f"v0:{timestamp}:{raw_body.decode('utf-8')}"
    expected = "v0=" + hmac.new(
        secret.encode("utf-8"),
        base.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(expected, slack_signature)


def parse_slack_action_target(value: str):
    match = re.search(r"([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)#(\d+)", value or "")
    if not match:
        return None

    owner, repo, pr_number = match.groups()
    return owner, repo, int(pr_number)


@app.post("/slack/action")
async def slack_action(request: Request, background_tasks: BackgroundTasks):
    raw_body = await request.body()

    if not verify_slack_action_signature(request.headers, raw_body):
        return JSONResponse(
            {"response_type": "ephemeral", "text": "Invalid Slack signature."},
            status_code=401,
        )

    params = urllib.parse.parse_qs(raw_body.decode("utf-8"))
    payload_text = params.get("payload", [""])[0]

    try:
        payload = json.loads(payload_text)
    except Exception:
        return JSONResponse(
            {"response_type": "ephemeral", "text": "Invalid Slack action payload."},
            status_code=400,
        )

    actions = payload.get("actions") or []
    if not actions:
        return JSONResponse({
            "response_type": "ephemeral",
            "text": "No Slack action was provided.",
        })

    action = actions[0]
    action_id = action.get("action_id", "")
    value = action.get("value", "")
    response_url = payload.get("response_url", "")

    target = parse_slack_action_target(value)
    if not target:
        return JSONResponse({
            "response_type": "ephemeral",
            "text": "Invalid PR target in Slack action.",
        })

    owner, repo, pr_number = target

    try:
        from backend.audit_log import log_audit_event
        log_audit_event("slack_action_received", {
            "owner": owner,
            "repo": repo,
            "pr_number": pr_number,
            "action_id": action_id,
        })
    except Exception as audit_error:
        print(f"Slack action audit log failed: {audit_error}", flush=True)

    if action_id == "rerun_analysis":
        background_tasks.add_task(
            run_slack_diagnose_v2,
            owner,
            repo,
            pr_number,
            response_url,
        )
        return JSONResponse({
            "response_type": "ephemeral",
            "replace_original": False,
            "text": (
                "Re-run analysis started.\n"
                f"Repository: {owner}/{repo}\n"
                f"Pull Request: #{pr_number}"
            ),
        }, background=background_tasks)

    if action_id == "fix_pr":
        background_tasks.add_task(
            run_slack_approve,
            owner,
            repo,
            pr_number,
            response_url,
        )
        return JSONResponse({
            "response_type": "ephemeral",
            "replace_original": False,
            "text": (
                "Fix PR workflow started.\n"
                f"Repository: {owner}/{repo}\n"
                f"Pull Request: #{pr_number}"
            ),
        }, background=background_tasks)

    return JSONResponse({
        "response_type": "ephemeral",
        "replace_original": False,
        "text": f"Unsupported Slack action: {action_id}",
    })
