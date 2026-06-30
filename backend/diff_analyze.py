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
        "networkpolicy.yaml",
        "networkpolicy.yml",
        "service.yaml",
        "service.yml",
        "ingress.yaml",
        "ingress.yml",
        "role.yaml",
        "role.yml",
        "rolebinding.yaml",
        "rolebinding.yml",
        "clusterrole.yaml",
        "clusterrole.yml",
        "clusterrolebinding.yaml",
        "clusterrolebinding.yml",
    )

    return (
        path.startswith(review_prefixes)
        or path in review_filenames
        or path.endswith(tuple("/" + name for name in review_filenames))
    )


def _append_finding(
    findings: List[Dict[str, str]],
    seen: set,
    file_path: str,
    severity: str,
    rule_id: str,
    issue: str,
    recommendation: str,
):
    key = (file_path, rule_id)

    if key in seen:
        return

    seen.add(key)

    findings.append({
        "file": file_path,
        "severity": severity,
        "rule_id": rule_id,
        "issue": issue,
        "recommendation": recommendation,
    })


def _has_pattern(lines: List[str], pattern: str) -> bool:
    return any(re.search(pattern, str(line).strip(), re.IGNORECASE) for line in lines)


def _has_workload_addition(lines: List[str]) -> bool:
    return _has_pattern(
        lines,
        r"^\s*kind\s*:\s*(Deployment|StatefulSet|DaemonSet|Pod|Job|CronJob)\b",
    )


def _has_container_image_addition(lines: List[str]) -> bool:
    return _has_pattern(lines, r"^\s*image\s*:\s*\S+")


def _has_network_policy_addition(lines: List[str]) -> bool:
    return _has_pattern(lines, r"^\s*kind\s*:\s*NetworkPolicy\b")


def detect_risks(changed_files: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    seen = set()

    review_files = []

    for changed_file in changed_files:
        file_path = changed_file.get("file") or changed_file.get("filename") or ""

        if not _is_review_target_file(file_path):
            continue

        added_lines = changed_file.get("added_lines") or changed_file.get("added") or []
        added_lines = [str(line) for line in added_lines]

        review_files.append({
            "file": file_path,
            "added_lines": added_lines,
        })

    any_network_policy_added = any(
        _has_network_policy_addition(item["added_lines"])
        for item in review_files
    )

    for changed_file in review_files:
        file_path = changed_file["file"]
        added_lines = changed_file["added_lines"]
        joined = "\n".join(added_lines)

        has_workload = _has_workload_addition(added_lines)
        has_image = _has_container_image_addition(added_lines)

        if _has_pattern(added_lines, r"\bprivileged\s*:\s*true\b"):
            _append_finding(
                findings,
                seen,
                file_path,
                "HIGH",
                "diff_privileged_container",
                "privileged: true が追加されています",
                "privileged: false に変更してください",
            )

        if _has_pattern(added_lines, r"\ballowPrivilegeEscalation\s*:\s*true\b"):
            _append_finding(
                findings,
                seen,
                file_path,
                "HIGH",
                "diff_allow_privilege_escalation",
                "allowPrivilegeEscalation: true が追加されています",
                "allowPrivilegeEscalation: false を設定してください",
            )

        if _has_pattern(added_lines, r"\brunAsUser\s*:\s*0\b"):
            _append_finding(
                findings,
                seen,
                file_path,
                "HIGH",
                "diff_run_as_root",
                "runAsUser: 0 が追加されています",
                "非rootユーザーで実行する設定に変更してください",
            )

        if _has_pattern(added_lines, r"\bhostNetwork\s*:\s*true\b"):
            _append_finding(
                findings,
                seen,
                file_path,
                "HIGH",
                "diff_host_network",
                "hostNetwork: true が追加されています",
                "hostNetwork を使わない構成に変更してください",
            )

        if _has_pattern(added_lines, r"\bhostPID\s*:\s*true\b"):
            _append_finding(
                findings,
                seen,
                file_path,
                "HIGH",
                "diff_host_pid",
                "hostPID: true が追加されています",
                "hostPID: false を設定してください",
            )

        if _has_pattern(added_lines, r"\bhostIPC\s*:\s*true\b"):
            _append_finding(
                findings,
                seen,
                file_path,
                "HIGH",
                "diff_host_ipc",
                "hostIPC: true が追加されています",
                "hostIPC: false を設定してください",
            )

        if re.search(r"(?im)^\s*-\s*(NET_ADMIN|SYS_ADMIN)\s*$", joined):
            _append_finding(
                findings,
                seen,
                file_path,
                "HIGH",
                "diff_dangerous_capabilities",
                "危険なLinux capability が追加されています",
                "NET_ADMIN / SYS_ADMIN などの強いcapabilityを削除してください",
            )

        if _has_pattern(added_lines, r"\bimage\s*:\s*[^\s#]+:latest\b"):
            _append_finding(
                findings,
                seen,
                file_path,
                "MEDIUM",
                "diff_latest_tag",
                "latest タグのイメージが追加されています",
                "固定バージョンタグを使用してください",
            )

        if _has_pattern(added_lines, r"\bresources\s*:\s*\{\s*\}\s*$"):
            _append_finding(
                findings,
                seen,
                file_path,
                "MEDIUM",
                "diff_empty_resources",
                "resources が空で追加されています",
                "CPU/Memory の requests と limits を設定してください",
            )

        if _has_pattern(added_lines, r"\bhostPath\s*:"):
            _append_finding(
                findings,
                seen,
                file_path,
                "HIGH",
                "diff_hostpath_volume",
                "hostPath volume が追加されています",
                "hostPath を避け、必要な場合は厳密にパスと権限を制限してください",
            )

        if has_image and not _has_pattern(added_lines, r"\breadOnlyRootFilesystem\s*:\s*true\b"):
            _append_finding(
                findings,
                seen,
                file_path,
                "MEDIUM",
                "diff_read_only_root_filesystem_missing",
                "readOnlyRootFilesystem: true が追加されていません",
                "コンテナのroot filesystemを読み取り専用にしてください",
            )

        if has_image and not _has_pattern(added_lines, r"\bimagePullPolicy\s*:"):
            _append_finding(
                findings,
                seen,
                file_path,
                "LOW",
                "diff_image_pull_policy_missing",
                "imagePullPolicy が追加されていません",
                "imagePullPolicy を明示してください",
            )

        if has_image and not _has_pattern(added_lines, r"\blivenessProbe\s*:"):
            _append_finding(
                findings,
                seen,
                file_path,
                "LOW",
                "diff_liveness_probe_missing",
                "livenessProbe が追加されていません",
                "livenessProbe を設定してください",
            )

        if has_image and not _has_pattern(added_lines, r"\breadinessProbe\s*:"):
            _append_finding(
                findings,
                seen,
                file_path,
                "LOW",
                "diff_readiness_probe_missing",
                "readinessProbe が追加されていません",
                "readinessProbe を設定してください",
            )

        if has_workload and not any_network_policy_added:
            _append_finding(
                findings,
                seen,
                file_path,
                "LOW",
                "diff_network_policy_missing_advisory",
                "同じ変更内でNetworkPolicyが追加されていません",
                "公開範囲や通信要件に応じてNetworkPolicyを追加してください",
            )

        if re.search(r"(?im)^\s*name\s*:\s*(PASSWORD|PASS|TOKEN|SECRET|API_KEY)\b", joined) and re.search(
            r"(?im)^\s*value\s*:\s*['\"]?[^'\"]+['\"]?\s*$",
            joined,
        ):
            _append_finding(
                findings,
                seen,
                file_path,
                "HIGH",
                "diff_plaintext_sensitive_env",
                "機密情報らしき環境変数が平文で追加されています",
                "Secret または Secret Manager を参照してください",
            )

    return findings
