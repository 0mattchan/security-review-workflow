import os
from pathlib import Path
from typing import Any, Dict, List

import yaml


DEFAULT_POLICY: Dict[str, Any] = {
    "version": 1,
    "action_level": "L2",
    "levels": {
        "L1": {
            "allow_pr_comment": True,
            "allow_slack_notification": True,
            "allow_remediation_pr": False,
            "allow_auto_apply": False,
        },
        "L2": {
            "allow_pr_comment": True,
            "allow_slack_notification": True,
            "allow_remediation_pr": True,
            "allow_auto_apply": False,
        },
        "L3": {
            "allow_pr_comment": True,
            "allow_slack_notification": True,
            "allow_remediation_pr": True,
            "allow_auto_apply": False,
        },
    },
    "thresholds": {
        "block_on": ["HIGH"],
        "warn_on": ["MEDIUM"],
        "pass_when_no_findings": True,
    },
    "rule_groups": {
        "kubernetes": {"enabled": True},
        "cloud_run": {"enabled": True},
        "iam": {"enabled": True},
        "cicd": {"enabled": True},
    },
}


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(base)

    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value

    return merged


def load_review_policy() -> Dict[str, Any]:
    path = Path(os.getenv("REVIEW_POLICY_PATH", "config/policy.yaml"))

    if not path.exists():
        return DEFAULT_POLICY

    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return DEFAULT_POLICY

    if not isinstance(loaded, dict):
        return DEFAULT_POLICY

    return _deep_merge(DEFAULT_POLICY, loaded)


def get_action_level(policy: Dict[str, Any] | None = None) -> str:
    policy = policy or load_review_policy()
    level = str(os.getenv("REVIEW_ACTION_LEVEL", policy.get("action_level", "L2"))).upper()

    if level not in {"L1", "L2", "L3"}:
        return "L2"

    return level


def is_rule_group_enabled(group: str, policy: Dict[str, Any] | None = None) -> bool:
    policy = policy or load_review_policy()
    groups = policy.get("rule_groups") or {}
    group_config = groups.get(group) or {}
    return bool(group_config.get("enabled", True))


def count_findings_by_severity(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    for finding in findings or []:
        severity = str(finding.get("severity", "INFO")).upper()
        counts[severity] = counts.get(severity, 0) + 1

    return counts


def decide_review_action(findings: List[Dict[str, Any]], policy: Dict[str, Any] | None = None) -> Dict[str, Any]:
    policy = policy or load_review_policy()
    action_level = get_action_level(policy)
    level_config = (policy.get("levels") or {}).get(action_level, {})
    thresholds = policy.get("thresholds") or {}

    counts = count_findings_by_severity(findings)

    block_on = {str(item).upper() for item in thresholds.get("block_on", ["HIGH"])}
    warn_on = {str(item).upper() for item in thresholds.get("warn_on", ["MEDIUM"])}

    if any(counts.get(severity, 0) > 0 for severity in block_on):
        decision = "BLOCK"
    elif any(counts.get(severity, 0) > 0 for severity in warn_on):
        decision = "WARN"
    else:
        decision = "PASS"

    return {
        "action_level": action_level,
        "decision": decision,
        "high": counts.get("HIGH", 0),
        "medium": counts.get("MEDIUM", 0),
        "low": counts.get("LOW", 0),
        "info": counts.get("INFO", 0),
        "total_issues": len(findings or []),
        "can_post_comment": bool(level_config.get("allow_pr_comment", True)),
        "can_notify_slack": bool(level_config.get("allow_slack_notification", True)),
        "can_create_remediation_pr": bool(level_config.get("allow_remediation_pr", False)),
        "can_auto_apply": bool(level_config.get("allow_auto_apply", False)),
    }
