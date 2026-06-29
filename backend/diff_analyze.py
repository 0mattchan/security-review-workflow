import re
from typing import Any, Dict, List


def parse_diff(diff_text: str) -> List[Dict[str, Any]]:
    changed_files = []
    current = None

    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            if current:
                changed_files.append(current)

            file_path = ""
            if " b/" in line:
                file_path = line.split(" b/", 1)[1].strip()
            else:
                parts = line.split()
                file_path = parts[-1].replace("b/", "") if parts else ""

            current = {
                "file": file_path,
                "added_lines": [],
            }
            continue

        if current is None:
            continue

        if line.startswith("+++") or line.startswith("---"):
            continue

        if line.startswith("+"):
            current["added_lines"].append(line[1:])

    if current:
        changed_files.append(current)

    return changed_files


def _is_review_target_file(file_path: str) -> bool:
    path = (file_path or "").lstrip("./")

    ignored_prefixes = (
        "backend/",
        "samples/",
        "tests/",
        "docs/",
        "frontend/",
        "deployment/",
        ".github/",
    )

    if path.startswith(ignored_prefixes):
        return False

    if not path.endswith((".yaml", ".yml")):
        return False

    review_prefixes = (
        "k8s/",
        "kubernetes/",
        "manifests/",
        "manifest/",
        "helm/",
        "charts/",
    )

    review_filenames = (
        "deployment.yaml",
        "deployment.yml",
        "manifest.yaml",
        "manifest.yml",
        "pod.yaml",
        "pod.yml",
        "statefulset.yaml",
        "statefulset.yml",
        "daemonset.yaml",
        "daemonset.yml",
    )

    return (
        path.startswith(review_prefixes)
        or path in review_filenames
        or path.endswith(tuple("/" + name for name in review_filenames))
    )


def detect_risks(changed_files: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    findings = []

    for changed_file in changed_files:
        file_path = changed_file.get("file") or changed_file.get("filename") or ""

        if not _is_review_target_file(file_path):
            continue

        added_lines = changed_file.get("added_lines") or changed_file.get("added") or []

        for line in added_lines:
            stripped = str(line).strip()

            if re.search(r"\bprivileged\s*:\s*true\b", stripped, re.IGNORECASE):
                findings.append({
                    "file": file_path,
                    "severity": "HIGH",
                    "rule_id": "diff_privileged_container",
                    "issue": "privileged: true が追加されています",
                    "recommendation": "privileged: false に変更してください",
                })

            if re.search(r"\bimage\s*:\s*[^\s#]+:latest\b", stripped, re.IGNORECASE):
                findings.append({
                    "file": file_path,
                    "severity": "MEDIUM",
                    "rule_id": "diff_latest_tag",
                    "issue": "latest タグのイメージが追加されています",
                    "recommendation": "固定バージョンタグを使用してください",
                })

            if re.search(r"\bresources\s*:\s*\{\s*\}\s*$", stripped, re.IGNORECASE):
                findings.append({
                    "file": file_path,
                    "severity": "MEDIUM",
                    "rule_id": "diff_empty_resources",
                    "issue": "resources が空で追加されています",
                    "recommendation": "CPU/Memory の requests と limits を設定してください",
                })

    return findings
