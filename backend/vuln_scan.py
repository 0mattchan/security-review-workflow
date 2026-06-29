import yaml
import json

def load_yaml(path):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def get_containers(manifest):
    return (
        manifest.get("spec", {})
        .get("template", {})
        .get("spec", {})
        .get("containers", [])
    )

def scan_k8s_deployment(manifest):
    findings = []

    manifest_name = manifest.get("metadata", {}).get("name", "unknown")
    containers = get_containers(manifest)

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

        if resources.get("limits") is None:
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

        if security_context.get("allowPrivilegeEscalation") is True:
            findings.append({
                "rule_id": "k8s_allow_privilege_escalation",
                "severity": "HIGH",
                "container": name,
                "issue": "allowPrivilegeEscalation: true が設定されています",
                "recommendation": "allowPrivilegeEscalation: false を設定してください"
            })

    return {
        "manifest_type": manifest.get("kind"),
        "manifest_name": manifest_name,
        "findings": findings
    }

if __name__ == "__main__":
    manifest = load_yaml("samples/manifest.yaml")
    result = scan_k8s_deployment(manifest)
    print(json.dumps(result, indent=2, ensure_ascii=False))
