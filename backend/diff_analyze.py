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


def _detect_base_risks(changed_files: List[Dict[str, Any]]) -> List[Dict[str, str]]:
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


# --- Cloud Run / IAM / CI-CD policy-aware diff rules ---

def _flatten_added_diff_lines(parsed_diff):
    """Yield (file_path, added_line) pairs from several possible parsed diff shapes."""
    seen = set()

    def detect_file(obj, current_file):
        if not isinstance(obj, dict):
            return current_file

        for key in ("file", "path", "filename", "new_path", "new_file", "to_file"):
            value = obj.get(key)
            if value:
                return str(value)

        return current_file

    def extract_line(entry):
        if isinstance(entry, str):
            if entry.startswith("+++") or entry.startswith("---"):
                return None

            if entry.startswith("+"):
                return entry[1:]

            return entry

        if isinstance(entry, dict):
            line_type = str(entry.get("type") or entry.get("kind") or entry.get("change") or "").lower()
            raw = (
                entry.get("content")
                or entry.get("line")
                or entry.get("text")
                or entry.get("value")
                or ""
            )

            if line_type and line_type not in {"add", "added", "addition", "+"}:
                return None

            raw = str(raw)

            if raw.startswith("+++") or raw.startswith("---"):
                return None

            if raw.startswith("+"):
                return raw[1:]

            return raw

        return None

    def walk(obj, current_file="unknown"):
        current_file = detect_file(obj, current_file) if isinstance(obj, dict) else current_file

        if isinstance(obj, dict):
            for key in ("added_lines", "added", "additions"):
                value = obj.get(key)

                if isinstance(value, list):
                    for entry in value:
                        line = extract_line(entry)
                        if line is not None:
                            item = (current_file, line)
                            if item not in seen:
                                seen.add(item)
                                yield item

            for key in ("lines", "hunks", "changes"):
                value = obj.get(key)

                if isinstance(value, list):
                    for entry in value:
                        if isinstance(entry, dict):
                            line_type = str(entry.get("type") or entry.get("kind") or entry.get("change") or "").lower()
                            raw = str(
                                entry.get("content")
                                or entry.get("line")
                                or entry.get("text")
                                or entry.get("value")
                                or ""
                            )

                            if line_type in {"add", "added", "addition", "+"} or raw.startswith("+"):
                                line = extract_line(entry)
                                if line is not None:
                                    item = (current_file, line)
                                    if item not in seen:
                                        seen.add(item)
                                        yield item
                        elif isinstance(entry, str) and entry.startswith("+") and not entry.startswith("+++"):
                            item = (current_file, entry[1:])
                            if item not in seen:
                                seen.add(item)
                                yield item
                        else:
                            yield from walk(entry, current_file)

            for value in obj.values():
                if isinstance(value, (dict, list)):
                    yield from walk(value, current_file)

        elif isinstance(obj, list):
            for entry in obj:
                yield from walk(entry, current_file)

    yield from walk(parsed_diff)


def _append_finding(findings, *args):
    """
    Compatibility helper.

    Supports both call styles:
    1. K8s diff rules:
       _append_finding(findings, seen, file_path, severity, rule_id, issue, recommendation)

    2. Cloud Run / IAM / CI/CD rules:
       _append_finding(findings, rule_id, severity, file_path, issue, recommendation, category)
    """

    if len(args) != 6:
        raise TypeError(f"_append_finding expected 6 arguments after findings, got {len(args)}")

    # Old K8s rule call style: second argument is the dedupe set.
    if isinstance(args[0], set):
        seen, file_path, severity, rule_id, issue, recommendation = args
        category = "kubernetes"

        key = (str(file_path or "unknown"), str(rule_id or "unknown"))
        if key in seen:
            return

        seen.add(key)

    # New extended rule call style.
    else:
        rule_id, severity, file_path, issue, recommendation, category = args

    findings.append({
        "rule_id": str(rule_id or "unknown"),
        "severity": str(severity or "INFO").strip().upper(),
        "file": str(file_path or "unknown"),
        "issue": str(issue or ""),
        "recommendation": str(recommendation or ""),
        "category": str(category or "general"),
    })


def detect_cloudrun_iam_cicd_risks(parsed_diff):
    try:
        from backend.policy_loader import is_rule_group_enabled
    except Exception:
        def is_rule_group_enabled(_group):
            return True

    findings = []
    by_file = {}

    for file_path, line in _flatten_added_diff_lines(parsed_diff):
        by_file.setdefault(file_path or "unknown", []).append(str(line))

    for file_path, lines in by_file.items():
        lower_file = file_path.lower()
        text = "\n".join(lines)
        lower_text = text.lower()
        normalized_text = " ".join(lower_text.split())
        tokens = {
            part.strip().strip("'\"[],")
            for part in normalized_text.replace(":", " ").split()
        }
        tokens.discard("")

        is_gcloud_run_deploy = (
            "gcloud run deploy" in normalized_text
            or ("gcloud" in tokens and "run" in tokens and "deploy" in tokens)
        )

        is_cloud_run_related = (
            "cloudrun" in lower_file
            or "cloud-run" in lower_file
            or "service.yaml" in lower_file
            or "run deploy" in normalized_text
            or "run services" in normalized_text
            or is_gcloud_run_deploy
            or "kind: service" in normalized_text and "run.googleapis.com" in normalized_text
        )

        is_cicd_related = (
            "cloudbuild" in lower_file
            or ".github/workflows" in lower_file
            or "github/workflows" in lower_file
            or "build.yaml" in lower_file
            or "cloudbuild.yaml" in lower_file
            or "cloudbuild.yml" in lower_file
        )

        if is_rule_group_enabled("cloud_run") and is_cloud_run_related:
            if "--allow-unauthenticated" in normalized_text:
                _append_finding(
                    findings,
                    "cloudrun_allow_unauthenticated",
                    "HIGH",
                    file_path,
                    "Cloud Run deployment allows unauthenticated public access.",
                    "Require authentication unless this is an explicitly approved public endpoint.",
                    "cloud_run",
                )

            if (
                "--ingress all" in normalized_text
                or ("--ingress" in tokens and "all" in tokens)
                or "ingress: all" in lower_text
                or "run.googleapis.com/ingress: all" in lower_text
            ):
                _append_finding(
                    findings,
                    "cloudrun_ingress_all",
                    "MEDIUM",
                    file_path,
                    "Cloud Run ingress is open to all traffic.",
                    "Use internal or internal-and-cloud-load-balancing ingress when possible.",
                    "cloud_run",
                )

            if is_gcloud_run_deploy and "--service-account" not in normalized_text:
                _append_finding(
                    findings,
                    "cloudrun_service_account_missing",
                    "MEDIUM",
                    file_path,
                    "Cloud Run deployment does not specify a dedicated service account.",
                    "Deploy with a least-privilege runtime service account.",
                    "cloud_run",
                )

            if "default-compute" in normalized_text or "compute@developer.gserviceaccount.com" in normalized_text:
                _append_finding(
                    findings,
                    "cloudrun_default_service_account",
                    "HIGH",
                    file_path,
                    "Cloud Run appears to use a default compute service account.",
                    "Use a dedicated least-privilege service account instead of the default compute service account.",
                    "cloud_run",
                )

            sensitive_env_tokens = [
                "token=",
                "password=",
                "secret=",
                "api_key=",
                "apikey=",
                "private_key=",
                "client_secret=",
            ]

            if "--set-env-vars" in normalized_text and any(token in normalized_text for token in sensitive_env_tokens):
                _append_finding(
                    findings,
                    "cloudrun_plaintext_sensitive_env",
                    "HIGH",
                    file_path,
                    "Sensitive-looking values are being passed through Cloud Run environment variables.",
                    "Store secrets in Secret Manager and mount them as secrets instead of plaintext env vars.",
                    "cloud_run",
                )

        if is_rule_group_enabled("iam"):
            if "roles/owner" in normalized_text or "roles/editor" in normalized_text:
                _append_finding(
                    findings,
                    "iam_overprivileged_basic_role",
                    "HIGH",
                    file_path,
                    "A broad basic IAM role such as roles/owner or roles/editor is being granted.",
                    "Use narrowly scoped predefined or custom roles.",
                    "iam",
                )

            if "allusers" in normalized_text or "allauthenticatedusers" in normalized_text:
                _append_finding(
                    findings,
                    "iam_public_member_binding",
                    "HIGH",
                    file_path,
                    "IAM binding grants access to allUsers or allAuthenticatedUsers.",
                    "Avoid public IAM bindings unless explicitly approved and documented.",
                    "iam",
                )

        if is_rule_group_enabled("cicd") and is_cicd_related:
            if "cloudbuild" in lower_file and "serviceaccount:" not in lower_text and "service_account:" not in lower_text:
                _append_finding(
                    findings,
                    "cicd_cloudbuild_service_account_missing",
                    "MEDIUM",
                    file_path,
                    "Cloud Build configuration does not specify a dedicated build service account.",
                    "Run builds with a dedicated least-privilege Cloud Build service account.",
                    "cicd",
                )

            if ":latest" in normalized_text:
                _append_finding(
                    findings,
                    "cicd_latest_image_tag",
                    "MEDIUM",
                    file_path,
                    "CI/CD configuration references an image with the latest tag.",
                    "Use immutable image tags such as commit SHA or build ID.",
                    "cicd",
                )

            if "docker build" in normalized_text and "--build-arg" in normalized_text and any(token in normalized_text for token in ["token", "password", "secret", "api_key", "apikey"]):
                _append_finding(
                    findings,
                    "cicd_secret_build_arg",
                    "HIGH",
                    file_path,
                    "Potential secret is passed via docker build --build-arg.",
                    "Use Secret Manager or CI secret mounting mechanisms instead of build args.",
                    "cicd",
                )

    return findings


def _normalize_finding_scalar(value):
    if value is None:
        return ""

    if isinstance(value, (set, list, tuple)):
        normalized_items = [
            _normalize_finding_scalar(item)
            for item in value
            if item is not None
        ]
        normalized_items = [item for item in normalized_items if item]

        if not normalized_items:
            return ""

        return ", ".join(sorted(set(normalized_items)))

    return str(value)


def _normalize_finding_severity(value):
    text = _normalize_finding_scalar(value).upper()

    if "HIGH" in text:
        return "HIGH"

    if "MEDIUM" in text:
        return "MEDIUM"

    if "LOW" in text:
        return "LOW"

    if "INFO" in text:
        return "INFO"

    return text or "INFO"


def _normalize_policy_finding(finding):
    if not isinstance(finding, dict):
        return None

    normalized = dict(finding)

    for key in ["rule_id", "file", "issue", "recommendation", "category"]:
        if key in normalized:
            normalized[key] = _normalize_finding_scalar(normalized.get(key))

    normalized["severity"] = _normalize_finding_severity(normalized.get("severity", "INFO"))

    return normalized


def _dedupe_policy_findings(findings):
    deduped = []
    seen = set()

    for finding in findings or []:
        normalized = _normalize_policy_finding(finding)

        if not normalized:
            continue

        key = (
            normalized.get("rule_id", ""),
            normalized.get("file", ""),
            normalized.get("issue", ""),
        )

        if key in seen:
            continue

        seen.add(key)
        deduped.append(normalized)

    return deduped


# --- Extended non-Kubernetes diff detection wrapper ---

def _get_file_path(changed_file):
    return str(
        changed_file.get("file")
        or changed_file.get("filename")
        or changed_file.get("path")
        or ""
    )


def _get_added_lines(changed_file):
    return [str(line) for line in (
        changed_file.get("added_lines")
        or changed_file.get("added")
        or []
    )]


def _append_extended_finding(findings, seen, file_path, severity, rule_id, issue, recommendation, category):
    key = (str(file_path or "unknown"), str(rule_id or "unknown"))

    if key in seen:
        return

    seen.add(key)

    findings.append({
        "rule_id": str(rule_id or "unknown"),
        "severity": str(severity or "INFO").strip().upper(),
        "file": str(file_path or "unknown"),
        "issue": str(issue or ""),
        "recommendation": str(recommendation or ""),
        "category": str(category or "general"),
    })


def _line_has(lines, pattern):
    return any(re.search(pattern, str(line), re.IGNORECASE) for line in lines)


def _joined_has(joined, pattern):
    return re.search(pattern, joined, re.IGNORECASE | re.MULTILINE) is not None


def _is_github_actions_file(path):
    p = path.lower().lstrip("./")
    p = re.sub(r"^[ab]/", "", p)
    return (
        p.startswith(".github/workflows/")
        or p.startswith("github/workflows/")
    ) and p.endswith((".yml", ".yaml"))


def _is_cloudbuild_file(path):
    p = path.lower().lstrip("./")
    return p == "cloudbuild.yaml" or p == "cloudbuild.yml" or p.endswith("/cloudbuild.yaml") or p.endswith("/cloudbuild.yml")


def _is_dockerfile(path):
    p = path.lower().lstrip("./")
    return p == "dockerfile" or p.endswith("/dockerfile") or p.endswith(".dockerfile")


def _is_terraform_file(path):
    return path.lower().endswith(".tf")


def _looks_like_cloud_run_yaml(path, joined):
    p = path.lower().lstrip("./")
    return (
        "cloudrun" in p
        or "cloud-run" in p
        or "run.googleapis.com" in joined
        or "serving.knative.dev" in joined
        or "kind: Service" in joined and "template:" in joined and "containers:" in joined
    )


def _detect_extended_risks(changed_files):
    findings = []
    seen = set()

    for changed_file in changed_files or []:
        file_path = _get_file_path(changed_file)
        path = file_path.lower().lstrip("./")
        added_lines = _get_added_lines(changed_file)
        joined = "\n".join(added_lines)

        if not added_lines:
            continue

        # GitHub Actions / CI/CD
        if _is_github_actions_file(path):
            if _line_has(added_lines, r"^\s*pull_request_target\s*:"):
                _append_extended_finding(
                    findings, seen, file_path, "HIGH",
                    "ci_github_actions_pull_request_target",
                    "pull_request_target が追加されています",
                    "外部PRのコード実行リスクがあるため、pull_request へ変更するか権限を厳格に制限してください",
                    "cicd",
                )

            if _line_has(added_lines, r"^\s*permissions\s*:\s*write-all\s*$"):
                _append_extended_finding(
                    findings, seen, file_path, "HIGH",
                    "ci_github_actions_permissions_write_all",
                    "GitHub Actions に write-all 権限が追加されています",
                    "permissions は contents: read など必要最小限にしてください",
                    "cicd",
                )

            if _line_has(added_lines, r"^\s*(contents|packages|pull-requests|issues|actions)\s*:\s*write\s*$"):
                _append_extended_finding(
                    findings, seen, file_path, "MEDIUM",
                    "ci_github_actions_write_permission",
                    "GitHub Actions に write 権限が追加されています",
                    "ジョブ単位で必要最小限の権限にしてください",
                    "cicd",
                )

            if _line_has(added_lines, r"^\s*-?\s*uses\s*:\s*[^@\s#]+(\s*#.*)?$"):
                _append_extended_finding(
                    findings, seen, file_path, "HIGH",
                    "ci_github_actions_unpinned_action",
                    "uses のアクションがバージョン固定されていません",
                    "例: actions/checkout@v4 のようにタグまたはSHAで固定してください",
                    "cicd",
                )

            if _line_has(added_lines, r"^\s*uses\s*:\s*[^@\s#]+@(main|master|latest)\b"):
                _append_extended_finding(
                    findings, seen, file_path, "MEDIUM",
                    "ci_github_actions_mutable_ref",
                    "GitHub Actions が main/master/latest など可変参照を使っています",
                    "固定タグまたはコミットSHAを使用してください",
                    "cicd",
                )

            if _joined_has(joined, r"(password|token|secret|api_key|apikey)\s*:\s*['\"]?[A-Za-z0-9_\-]{8,}"):
                _append_extended_finding(
                    findings, seen, file_path, "HIGH",
                    "ci_github_actions_plaintext_secret",
                    "GitHub Actions に機密情報らしき値が平文で追加されています",
                    "GitHub Secrets または Secret Manager を参照してください",
                    "cicd",
                )

            if _joined_has(joined, r"(curl|wget)\b.*\|\s*(sh|bash)"):
                _append_extended_finding(
                    findings, seen, file_path, "HIGH",
                    "ci_github_actions_pipe_to_shell",
                    "curl/wget の結果を直接 shell 実行しています",
                    "取得元と内容を検証し、固定バージョンの公式アクションやチェックサム検証を使ってください",
                    "cicd",
                )

        # Cloud Build / Cloud Run deploy config
        if _is_cloudbuild_file(path):
            if _joined_has(joined, r"--allow-unauthenticated\b"):
                _append_extended_finding(
                    findings, seen, file_path, "HIGH",
                    "cloudbuild_cloudrun_allow_unauthenticated",
                    "Cloud Build から Cloud Run を unauthenticated 公開しています",
                    "公開が必要なWebhook以外は認証を有効化し、公開理由を明記してください",
                    "cloud_run",
                )

            if _joined_has(joined, r"gcloud\s+run\s+deploy") and not _joined_has(joined, r"--service-account\b"):
                _append_extended_finding(
                    findings, seen, file_path, "MEDIUM",
                    "cloudbuild_cloudrun_service_account_missing",
                    "Cloud Run deploy に専用 service account が指定されていません",
                    "--service-account で最小権限の実行SAを指定してください",
                    "cloud_run",
                )

            if _joined_has(joined, r"gcloud\s+run\s+deploy") and not _joined_has(joined, r"--max-instances\b"):
                _append_extended_finding(
                    findings, seen, file_path, "LOW",
                    "cloudbuild_cloudrun_max_instances_missing",
                    "Cloud Run deploy に max-instances が明示されていません",
                    "想定負荷とコストに応じて --max-instances を設定してください",
                    "cloud_run",
                )

            if _joined_has(joined, r":latest\b"):
                _append_extended_finding(
                    findings, seen, file_path, "MEDIUM",
                    "cloudbuild_image_latest_tag",
                    "Cloud Build / deploy 設定で latest タグが使われています",
                    "ビルドSHAやリリースタグなど固定可能なタグを使ってください",
                    "cicd",
                )

            if _joined_has(joined, r"--set-env-vars=.*(PASSWORD|TOKEN|SECRET|API_KEY|APIKEY)="):
                _append_extended_finding(
                    findings, seen, file_path, "HIGH",
                    "cloudbuild_plaintext_sensitive_env",
                    "Cloud Run 環境変数に機密情報らしき値を直接設定しています",
                    "--set-secrets または Secret Manager 参照に変更してください",
                    "cloud_run",
                )

        # Cloud Run YAML / Knative Service YAML
        if _looks_like_cloud_run_yaml(path, joined):
            if _joined_has(joined, r"run\.googleapis\.com/ingress\s*:\s*all") or _joined_has(joined, r"ingress\s*:\s*all"):
                _append_extended_finding(
                    findings, seen, file_path, "MEDIUM",
                    "cloudrun_ingress_all",
                    "Cloud Run ingress: all が追加されています",
                    "必要に応じて internal または internal-and-cloud-load-balancing を検討してください",
                    "cloud_run",
                )

            if _joined_has(joined, r"\ballUsers\b|\ballAuthenticatedUsers\b"):
                _append_extended_finding(
                    findings, seen, file_path, "HIGH",
                    "cloudrun_public_invoker",
                    "Cloud Run に公開アクセス権限が追加されています",
                    "公開Webhook以外は認証を有効化し、roles/run.invoker を限定してください",
                    "cloud_run",
                )

            if _joined_has(joined, r"image\s*:\s*[^\s#]+:latest\b"):
                _append_extended_finding(
                    findings, seen, file_path, "MEDIUM",
                    "cloudrun_image_latest_tag",
                    "Cloud Run コンテナイメージに latest タグが追加されています",
                    "固定タグまたはdigestを使用してください",
                    "cloud_run",
                )

            if _joined_has(joined, r"env\s*:") and _joined_has(joined, r"(PASSWORD|TOKEN|SECRET|API_KEY|APIKEY).*value\s*:"):
                _append_extended_finding(
                    findings, seen, file_path, "HIGH",
                    "cloudrun_plaintext_sensitive_env",
                    "Cloud Run 環境変数に機密情報らしき値が平文で追加されています",
                    "Secret Manager 参照に変更してください",
                    "cloud_run",
                )

        # Dockerfile / container image config
        if _is_dockerfile(path):
            if _line_has(added_lines, r"^\s*FROM\s+\S+:latest\b"):
                _append_extended_finding(
                    findings, seen, file_path, "MEDIUM",
                    "dockerfile_latest_base_image",
                    "Dockerfile のベースイメージに latest タグが使われています",
                    "固定バージョンタグまたはdigestを使用してください",
                    "container",
                )

            if _line_has(added_lines, r"^\s*USER\s+root\b") or not _line_has(added_lines, r"^\s*USER\s+"):
                _append_extended_finding(
                    findings, seen, file_path, "MEDIUM",
                    "dockerfile_non_root_user_missing",
                    "Dockerfile で非rootユーザーが明示されていません",
                    "USER で非rootユーザーを指定してください",
                    "container",
                )

            if _joined_has(joined, r"(curl|wget)\b.*\|\s*(sh|bash)"):
                _append_extended_finding(
                    findings, seen, file_path, "HIGH",
                    "dockerfile_pipe_to_shell",
                    "Dockerfile で curl/wget の結果を直接 shell 実行しています",
                    "チェックサム検証や公式パッケージを利用してください",
                    "container",
                )

            if _line_has(added_lines, r"^\s*ADD\s+https?://"):
                _append_extended_finding(
                    findings, seen, file_path, "MEDIUM",
                    "dockerfile_add_remote_url",
                    "Dockerfile の ADD で外部URLを直接取得しています",
                    "curl + checksum検証、またはCOPYに変更してください",
                    "container",
                )

            if _line_has(added_lines, r"^\s*FROM\s+") and not _line_has(added_lines, r"^\s*HEALTHCHECK\b"):
                _append_extended_finding(
                    findings, seen, file_path, "LOW",
                    "dockerfile_healthcheck_missing_advisory",
                    "Dockerfile に HEALTHCHECK が追加されていません",
                    "必要に応じて HEALTHCHECK を追加してください",
                    "container",
                )

        # Terraform / IAM
        if _is_terraform_file(path):
            if _joined_has(joined, r"\b(allUsers|allAuthenticatedUsers)\b"):
                _append_extended_finding(
                    findings, seen, file_path, "HIGH",
                    "tf_public_iam_member",
                    "Terraform で public IAM member が追加されています",
                    "allUsers / allAuthenticatedUsers を避け、必要な主体だけに絞ってください",
                    "iam",
                )

            if _joined_has(joined, r"roles/(owner|editor|.*admin)\b"):
                _append_extended_finding(
                    findings, seen, file_path, "HIGH",
                    "tf_overprivileged_iam_role",
                    "Terraform で強いIAMロールが追加されています",
                    "最小権限の個別ロールに分割してください",
                    "iam",
                )

            if _joined_has(joined, r"0\.0\.0\.0/0"):
                _append_extended_finding(
                    findings, seen, file_path, "HIGH",
                    "tf_firewall_allow_all",
                    "Terraform で 0.0.0.0/0 の許可が追加されています",
                    "CIDRを必要最小限に制限してください",
                    "iam",
                )

            if _joined_has(joined, r"google_service_account_key"):
                _append_extended_finding(
                    findings, seen, file_path, "HIGH",
                    "tf_service_account_key_created",
                    "Terraform でサービスアカウントキー作成が追加されています",
                    "Workload Identity / Secret Manager 等を使い、長期鍵の作成を避けてください",
                    "iam",
                )

    return findings


def detect_risks(changed_files):
    base_findings = _detect_base_risks(changed_files)
    extended_findings = _detect_extended_risks(changed_files)

    merged = []
    seen = set()

    for finding in list(base_findings or []) + list(extended_findings or []):
        if not isinstance(finding, dict):
            continue

        file_path = str(finding.get("file") or "unknown")
        rule_id = str(finding.get("rule_id") or "unknown")
        key = (file_path, rule_id)

        if key in seen:
            continue

        seen.add(key)

        finding["severity"] = str(finding.get("severity") or "INFO").strip().upper()
        finding["file"] = file_path
        finding["rule_id"] = rule_id
        merged.append(finding)

    return merged

