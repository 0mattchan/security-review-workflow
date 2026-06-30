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

    buttons = [
        {
            "type": "button",
            "text": {
                "type": "plain_text",
                "text": "Open Pull Request"
            },
            "url": pr_url
        }
    ]

    if comment_url:
        buttons.insert(
            0,
            {
                "type": "button",
                "text": {
                    "type": "plain_text",
                    "text": "Open Review"
                },
                "url": comment_url
            }
        )

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
        return JSONResponse({
            "response_type": "ephemeral",
            "text": (
                "Security Review Workflow is running.\n"
                "Cloud Run: active\n"
                "GitHub Webhook: configured\n"
                "Slack Notifications: configured\n"
                "Review target: Kubernetes manifest diffs"
            ),
        })

    if command == "/agent-diagnose":
        usage = (
            "Usage:\n"
            "/agent-diagnose owner/repo#pr_number\n"
            "Example:\n"
            "/agent-diagnose 0mattchan/devsecops-agent#3"
        )

        if not text:
            return JSONResponse({
                "response_type": "ephemeral",
                "text": usage,
            })

        try:
            import re
            from backend.github_pr import get_pr_diff, post_pr_comment
            from backend.diff_analyze import parse_diff, detect_risks

            match = re.search(r"([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)#(\d+)", text)

            if not match:
                return JSONResponse({
                    "response_type": "ephemeral",
                    "text": usage,
                })

            owner = match.group(1)
            repo = match.group(2)
            pr_number = int(match.group(3))

            response_url = form.get("response_url", [""])[0]

            if not response_url:
                return JSONResponse({
                    "response_type": "ephemeral",
                    "text": "Missing Slack response URL.",
                })

            background_tasks.add_task(
                run_slack_diagnose,
                owner,
                repo,
                pr_number,
                response_url,
            )

            return JSONResponse({
                "response_type": "ephemeral",
                "text": (
                    "Security review started.\n"
                    f"Repository: {owner}/{repo}\n"
                    f"Pull Request: #{pr_number}\n"
                    "The result will be posted here shortly."
                ),
            })

        except Exception as e:
            print(f"Slash diagnose failed: {e}")
            return JSONResponse({
                "response_type": "ephemeral",
                "text": "Security review request failed. Please check Cloud Run logs.",
            })

    if command == "/agent-approve":
        usage = (
            "Usage:\n"
            "/agent-approve owner/repo#pr_number\n"
            "Example:\n"
            "/agent-approve 0mattchan/devsecops-agent#2"
        )

        if not text:
            return JSONResponse({
                "response_type": "ephemeral",
                "text": usage,
            })

        try:
            import re

            match = re.search(r"([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)#(\d+)", text)

            if not match:
                return JSONResponse({
                    "response_type": "ephemeral",
                    "text": usage,
                })

            owner = match.group(1)
            repo = match.group(2)
            pr_number = int(match.group(3))
            response_url = form.get("response_url", [""])[0]

            print(f"Slash approve accepted: {owner}/{repo}#{pr_number}")

            background_tasks.add_task(
                run_slack_approve,
                owner,
                repo,
                pr_number,
                response_url,
            )

            return JSONResponse({
                "response_type": "ephemeral",
                "text": (
                    "Remediation workflow started.\n"
                    f"Repository: {owner}/{repo}\n"
                    f"Pull Request: #{pr_number}\n"
                    "A remediation pull request will be created if supported fixes are available."
                ),
            })

        except Exception as e:
            print(f"Slash approve request failed: {e}")
            return JSONResponse({
                "response_type": "ephemeral",
                "text": "Remediation workflow request failed. Please check Cloud Run logs.",
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

        markdown = build_markdown_report_with_assessment(
            owner,
            repo,
            pr_number,
            findings,
            diff_text,
        )

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
        from backend.github_pr import create_k8s_remediation_pr
        from backend.slack_notify import send_slack_message

        result = create_k8s_remediation_pr(owner, repo, pr_number)

        if result.get("status") == "no_changes":
            message = (
                "Remediation review completed.\n"
                f"Repository: {owner}/{repo}\n"
                f"Pull Request: #{pr_number}\n"
                "No supported Kubernetes remediation changes were found."
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
            send_slack_message(message)
            print("Slash approve channel notification posted")
        except Exception as notify_error:
            print(f"Failed to send Slack approve channel notification: {notify_error}")

        print(f"Slash approve completed: {owner}/{repo}#{pr_number}")

    except Exception as e:
        print(f"Slash approve failed: {e}")

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
