import re
import json

def load_diff(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

def parse_diff(diff_text):
    files = []
    current_file = None

    for line in diff_text.splitlines():
        if line.startswith("diff --git"):
            match = re.search(r"b/(.+)$", line)
            if match:
                current_file = {
                    "file": match.group(1),
                    "added_lines": []
                }
                files.append(current_file)

        elif current_file and line.startswith("+") and not line.startswith("+++"):
            current_file["added_lines"].append(line[1:])

    return files

def detect_risks(parsed_files):
    findings = []

    for file in parsed_files:
        filename = file["file"]
        added_text = "\n".join(file["added_lines"])

        if "privileged: true" in added_text:
            findings.append({
                "file": filename,
                "severity": "HIGH",
                "rule_id": "diff_privileged_container",
                "issue": "privileged: true が追加されています",
                "recommendation": "privileged: false に変更してください"
            })

        if re.search(r"image:\s*.+:latest", added_text):
            findings.append({
                "file": filename,
                "severity": "MEDIUM",
                "rule_id": "diff_latest_tag",
                "issue": "latest タグのイメージが追加されています",
                "recommendation": "固定バージョンタグを使用してください"
            })

        if "resources: {}" in added_text:
            findings.append({
                "file": filename,
                "severity": "MEDIUM",
                "rule_id": "diff_empty_resources",
                "issue": "resources が空で追加されています",
                "recommendation": "CPU/Memory の requests と limits を設定してください"
            })

    return findings

if __name__ == "__main__":
    diff_text = load_diff("samples/diff_sample.txt")
    parsed = parse_diff(diff_text)
    findings = detect_risks(parsed)

    print(json.dumps({
        "changed_files": parsed,
        "findings": findings
    }, indent=2, ensure_ascii=False))
