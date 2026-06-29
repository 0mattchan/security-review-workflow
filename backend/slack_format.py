import json

def severity_icon(severity):
    if severity == "HIGH":
        return "🔴"
    elif severity == "MEDIUM":
        return "🟠"
    elif severity == "LOW":
        return "🟢"
    return "⚪"

def format_slack_message(report):
    manifest_name = report.get("manifest_name", "unknown")
    manifest_type = report.get("manifest_type", "unknown")
    findings = report.get("findings", [])

    lines = []

    lines.append("*Security Review Alert*")
    lines.append("")
    lines.append(f"*Manifest:* {manifest_name}")
    lines.append(f"*Type:* {manifest_type}")
    lines.append("")

    if not findings:
        lines.append("脆弱性は検出されませんでした")
    else:
        for finding in findings:
            severity = finding.get("severity", "UNKNOWN")
            issue = finding.get("issue", "unknown")
            recommendation = finding.get(
                "recommendation",
                "No recommendation"
            )

            icon = severity_icon(severity)

            lines.append(f"{icon} *{severity}*")
            lines.append(f"Issue: {issue}")
            lines.append(
                f"Recommendation: {recommendation}"
            )
            lines.append("")

    return "\n".join(lines)

if __name__ == "__main__":

    sample_report = {
        "manifest_name": "vulnerable-app",
        "manifest_type": "Deployment",
        "findings": [
            {
                "severity": "HIGH",
                "issue": "privileged: true",
                "recommendation": "privileged: false にしてください"
            },
            {
                "severity": "MEDIUM",
                "issue": "latest tag",
                "recommendation": "固定バージョンタグを使用してください"
            },
            {
                "severity": "MEDIUM",
                "issue": "resources.limits missing",
                "recommendation": "CPU/Memory limits を設定してください"
            }
        ]
    }

    message = format_slack_message(sample_report)

    print(message)
