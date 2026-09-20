from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Iterable, List, Set

from azure.mgmt.authorization import AuthorizationManagementClient

from .risk_model import DEFAULT_BUCKET

ROLE_NAME_OVERRIDES: Dict[str, str] = {
    "Owner": "privilege_escalation",
    "User Access Administrator": "privilege_escalation",
    "Role Based Access Control Administrator": "privilege_escalation",

    "Security Reader": "security_visibility",
    "Microsoft Sentinel Reader": "security_visibility",
    "Microsoft Sentinel Responder - READ ONLY": "security_visibility",
    "Workbook Reader": "security_visibility",

    "Reader": "read_only",
}


def _normalize_actions(values: Iterable[str] | None) -> List[str]:
    if not values:
        return []
    return [v.strip().lower() for v in values if v and v.strip()]


def _is_write_style_action(action: str) -> bool:
    return (
        action.endswith("*")
        or "/write" in action
        or "/delete" in action
        or "/action" in action
    )


def _extract_provider_family(action: str) -> str | None:
    """
    Extract Azure provider family from action string.

    Example:
      microsoft.compute/virtualmachines/write -> microsoft.compute
      microsoft.network/* -> microsoft.network
    """
    if not action.startswith("microsoft."):
        return None

    return action.split("/", 1)[0]


def _count_write_provider_families(actions: List[str]) -> int:
    providers: Set[str] = set()

    for action in actions:
        if not _is_write_style_action(action):
            continue

        provider = _extract_provider_family(action)
        if provider:
            providers.add(provider)

    return len(providers)


def _extract_action_suffix(action: str) -> str:
    """
    Extract the operation suffix from an Azure action string.

    Example:
      microsoft.compute/virtualmachines/write -> /write
      microsoft.network/* -> *
    """
    if action.endswith("*"):
        return "*"

    for suffix in ("/read", "/write", "/delete", "/action"):
        if suffix in action:
            return suffix

    return ""


def infer_bucket_from_actions(actions: List[str], data_actions: List[str]) -> tuple[str, str]:
    """
    Infer capability bucket from Azure control-plane and data-plane actions.

    Returns:
        (bucket, triggering_action_suffix)
    """
    all_actions = actions + data_actions

    if not all_actions:
        return DEFAULT_BUCKET, ""

    # 1) Privilege escalation / IAM control
    for a in actions:
        if (
            "microsoft.authorization/" in a
            and (
                "/write" in a
                or "roleassignments/" in a
                or "roledefinitions/" in a
                or a.endswith("*")
            )
        ):
            return "privilege_escalation", _extract_action_suffix(a)

    # 2) Data plane access
    if data_actions:
        return "data_access", _extract_action_suffix(data_actions[0])

    # 3) Security / monitoring visibility
    security_keywords = [
        "microsoft.security",
        "microsoft.securityinsights",
        "microsoft.operationalinsights",
        "microsoft.insights",
        "microsoft.monitor",
    ]

    if actions and all("/read" in a for a in actions):
        for a in actions:
            if any(keyword in a for keyword in security_keywords):
                return "security_visibility", "/read"
        return "read_only", "/read"

    # 4) Resource control
    write_actions = [a for a in actions if _is_write_style_action(a)]

    if write_actions:
        provider_count = _count_write_provider_families(actions)
        suffix = _extract_action_suffix(write_actions[0])

        if provider_count >= 3:
            return "resource_control_broad", suffix

        return "resource_control_narrow", suffix

    return DEFAULT_BUCKET, ""


def build_role_taxonomy_template(
    authz: AuthorizationManagementClient,
    subscription_id: str,
) -> Dict[str, str]:
    """
    Enumerate all role definitions visible at subscription level and classify them
    by inspecting actions and data_actions.

    Roles can be forced into custom buckets via ROLE_NAME_OVERRIDES.

    Unknown or ambiguous roles fall back to custom_or_unknown.
    """
    scope = f"/subscriptions/{subscription_id}"
    taxonomy: Dict[str, str] = {}

    for rd in authz.role_definitions.list(scope):
        role_name = getattr(rd, "role_name", None)
        if not role_name:
            continue

        role_name = role_name.strip()

        if role_name in ROLE_NAME_OVERRIDES:
            taxonomy[role_name] = ROLE_NAME_OVERRIDES[role_name]
            continue

        permissions = getattr(rd, "permissions", None) or []

        actions: List[str] = []
        data_actions: List[str] = []

        for perm in permissions:
            actions.extend(_normalize_actions(getattr(perm, "actions", None)))
            data_actions.extend(_normalize_actions(getattr(perm, "data_actions", None)))

        bucket, _ = infer_bucket_from_actions(actions, data_actions)
        taxonomy[role_name] = bucket

    return dict(sorted(taxonomy.items(), key=lambda item: item[0].lower()))


def write_role_taxonomy_template(
    taxonomy: Dict[str, str],
    output_path: Path,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as f:
        json.dump(taxonomy, f, indent=2, sort_keys=True)
        f.write("\n")