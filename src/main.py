from __future__ import annotations

import sys
import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import replace

from azure.identity import DefaultAzureCredential
from azure.mgmt.authorization import AuthorizationManagementClient

from .config_loader import load_risk_config
from .rbac_collector import (
    build_role_definition_lookup,
    collect_role_assignments,
    get_subscription_id,
)
from .risk_model import score_records, summarize_principal_risk
from .role_taxonomy_generator import infer_bucket_from_actions


def build_runtime_taxonomy(records, authz, subscription_id, analyst_taxonomy):
    """
    Build runtime classification data only for assigned roles.

    Runtime behavior:
    - If a role exists in the analyst taxonomy file, use that bucket.
    - Otherwise, infer the bucket from role permissions.

    Returns:
        runtime_taxonomy: role_name -> bucket
        runtime_actions: role_name -> triggering_action_suffix
    """
    scope = f"/subscriptions/{subscription_id}"

    role_defs = {
        rd.role_name: rd
        for rd in authz.role_definitions.list(scope)
        if getattr(rd, "role_name", None)
    }

    assigned_roles = {r.role_name for r in records}
    taxonomy = {}
    actions_map = {}

    for role in assigned_roles:
        rd = role_defs.get(role)
        if not rd:
            taxonomy[role] = "custom_or_unknown"
            actions_map[role] = ""
            continue

        actions = []
        data_actions = []

        for perm in getattr(rd, "permissions", []) or []:
            actions.extend([a.lower() for a in getattr(perm, "actions", []) or []])
            data_actions.extend([a.lower() for a in getattr(perm, "data_actions", []) or []])

        inferred_bucket, triggering_action = infer_bucket_from_actions(actions, data_actions)

        taxonomy[role] = analyst_taxonomy.get(role, inferred_bucket)
        actions_map[role] = triggering_action

    return taxonomy, actions_map


def resolve_principal_name(
    credential: DefaultAzureCredential,
    principal_id: str,
    principal_type: str,
) -> str:
    """
    Resolve a principal ID to a human-readable display name via Microsoft Graph.

    Falls back to the raw principal_id if lookup fails or the principal type
    is unsupported.
    """
    endpoint_map = {
        "User": f"https://graph.microsoft.com/v1.0/users/{urllib.parse.quote(principal_id)}?$select=displayName,userPrincipalName",
        "Group": f"https://graph.microsoft.com/v1.0/groups/{urllib.parse.quote(principal_id)}?$select=displayName",
        "ServicePrincipal": f"https://graph.microsoft.com/v1.0/servicePrincipals/{urllib.parse.quote(principal_id)}?$select=displayName,appId",
        "ManagedIdentity": f"https://graph.microsoft.com/v1.0/servicePrincipals/{urllib.parse.quote(principal_id)}?$select=displayName,appId",
    }

    url = endpoint_map.get(principal_type)
    if not url:
        return principal_id

    try:
        token = credential.get_token("https://graph.microsoft.com/.default").token

        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            },
        )

        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        return (
            data.get("displayName")
            or data.get("userPrincipalName")
            or data.get("appId")
            or principal_id
        )

    except (
        urllib.error.URLError,
        urllib.error.HTTPError,
        TimeoutError,
        KeyError,
        json.JSONDecodeError,
    ):
        return principal_id


def _bucket_rank(bucket: str) -> int:
    """
    Lower number = higher priority in the diagnostic output.
    """
    order = {
        "privilege_escalation": 0,
        "resource_control_broad": 1,
        "resource_control_narrow": 2,
        "data_access": 3,
        "security_visibility": 4,
        "read_only": 5,
        "custom_or_unknown": 6,
    }
    return order.get(bucket, 99)


def print_assigned_role_classifications(
    runtime_taxonomy: dict[str, str],
    runtime_actions: dict[str, str],
) -> None:
    """
    Print a compact view of assigned role and the reason for the classification.
    """
    print("Assigned roles:")
    print()
    print(f"{'Role':<45} {'Classification':<28} {'Reason'}")
    print("-" * 90)

    rows = sorted(
        runtime_taxonomy.items(),
        key=lambda item: (_bucket_rank(item[1]), item[0].lower()),
    )

    for role, bucket in rows:
        trigger = runtime_actions.get(role, "") or "N/A"
        print(f"{role:<45} {bucket:<28} {trigger}")

    print()


def main() -> None:
    subscription_id = get_subscription_id()

    credential = DefaultAzureCredential(
        exclude_interactive_browser_credential=True
    )
    authz = AuthorizationManagementClient(credential, subscription_id)

    role_lookup = build_role_definition_lookup(authz, subscription_id)
    records = collect_role_assignments(authz, subscription_id, role_lookup)

    cfg = load_risk_config()

    runtime_taxonomy, runtime_actions = build_runtime_taxonomy(
        records,
        authz,
        subscription_id,
        cfg.role_taxonomy,
    )

    runtime_cfg = replace(cfg, role_taxonomy=runtime_taxonomy)

    scored = score_records(records, runtime_cfg)

    scored = [
        replace(sa, triggering_action=runtime_actions.get(sa.record.role_name, ""))
        for sa in scored
    ]

    principal_summaries = summarize_principal_risk(scored, runtime_cfg)

    print(f"Enumerated roles: {len(role_lookup)}")
    print(f"Total Assigned Roles: {len(records)}")
    print()

    print_assigned_role_classifications(runtime_taxonomy, runtime_actions)

    print("Top risky principals:")
    print()

    name_cache: dict[tuple[str, str], str] = {}

    for p in principal_summaries[:10]:
        cache_key = (p.principal_id, p.principal_type)
        if cache_key not in name_cache:
            name_cache[cache_key] = resolve_principal_name(
                credential,
                p.principal_id,
                p.principal_type,
            )

        principal_name = name_cache[cache_key]

        print(
    f"Name = {principal_name} | "
    f"Type = {p.principal_type} | "
    f"ID = {p.principal_id} | "
    f"Severity = {p.cumulative_severity} | "
    f"Score = {p.cumulative_score} | "
    f"Assignments = {len(p.risky_assignments)} | "
    f"Riskiest Role = {p.highest_assignment.record.role_name}"
)

        for sa in p.risky_assignments:
            r = sa.record
            print(
                f"- {sa.severity} | "
                f"{sa.score} | "
                f"{r.role_name} | "
                f"Action = {sa.triggering_action or 'N/A'} | "
                f"Classification = {sa.bucket} | "
                f"Scope = {r.scope_type} | "
                f"Path = {r.scope}"
            )

        print()


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as e:
        print(f"\nError: {e}", file=sys.stderr)
        sys.exit(1)