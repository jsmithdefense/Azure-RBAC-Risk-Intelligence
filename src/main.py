from __future__ import annotations

import argparse
import sys
import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import replace
from typing import Dict, List

from azure.core.exceptions import ClientAuthenticationError
from azure.identity import DefaultAzureCredential
from azure.mgmt.authorization import AuthorizationManagementClient

from .ai_enrichment import run_ai_enrichment
from .config_loader import load_risk_config
from .pdf_report import generate_pdf_report
from .rbac_collector import (
    build_role_definition_lookup,
    collect_role_assignments,
    enumerate_subscriptions,
    select_subscriptions_interactive,
)
from .risk_model import score_records, summarize_principal_risk
from .report_writer import write_report
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


def get_group_member_count(
    credential: DefaultAzureCredential,
    group_id: str,
) -> int:
    """
    Get the member count for a group via Microsoft Graph.
    
    Returns:
        Number of members, or 0 if lookup fails
    """
    url = f"https://graph.microsoft.com/v1.0/groups/{urllib.parse.quote(group_id)}/members/$count"
    
    try:
        token = credential.get_token("https://graph.microsoft.com/.default").token
        
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "text/plain",
                "ConsistencyLevel": "eventual",
            },
        )
        
        with urllib.request.urlopen(req, timeout=15) as resp:
            count = int(resp.read().decode("utf-8"))
            return count
    
    except (
        urllib.error.HTTPError,
        urllib.error.URLError,
        TimeoutError,
        ValueError,
    ):
        return 0


def extract_scope_display_name(scope: str, scope_type: str) -> str:
    """
    Extract a human-readable name from an Azure scope path.
    
    Examples:
    - /subscriptions/abc/resourceGroups/MyRG → "MyRG"
    - /subscriptions/abc/resourceGroups/MyRG/providers/.../myVnet → "MyRG/myVnet"
    - /subscriptions/abc → "subscription"
    """
    if scope_type == "subscription":
        return "subscription"
    
    parts = scope.split('/')
    
    # Extract resource group name
    try:
        rg_index = parts.index('resourceGroups')
        rg_name = parts[rg_index + 1] if rg_index + 1 < len(parts) else "unknown"
    except (ValueError, IndexError):
        return scope_type  # Fallback to generic type
    
    # For resource-level, add the resource name
    if scope_type == "resource" and len(parts) > 0:
        resource_name = parts[-1]  # Last segment is resource name
        return f"{rg_name}/{resource_name}"
    
    # For resource_group level, just return the RG name
    return rg_name


def calculate_subscription_risk_scores(
    scored_assignments: list,
    selected_subs: list,
) -> list[dict]:
    """
    Calculate total risk score per subscription.
    
    Returns:
        List of dicts with subscription info and risk scores, sorted by risk (highest first)
    """
    # Group assignments by subscription
    sub_scores = {}
    
    for sa in scored_assignments:
        sub_id = sa.record.subscription_id
        if sub_id not in sub_scores:
            sub_scores[sub_id] = {
                'total_score': 0,
                'assignment_count': 0,
                'unique_principals': set(),
            }
        
        sub_scores[sub_id]['total_score'] += sa.score
        sub_scores[sub_id]['assignment_count'] += 1
        sub_scores[sub_id]['unique_principals'].add(sa.record.principal_id)
    
    # Build subscription risk summaries
    subscription_risks = []
    
    for sub in selected_subs:
        sub_id = sub['id']
        scores = sub_scores.get(sub_id, {'total_score': 0, 'assignment_count': 0, 'unique_principals': set()})
        
        subscription_risks.append({
            'id': sub_id,
            'name': sub['name'],
            'total_score': scores['total_score'],
            'assignment_count': scores['assignment_count'],
            'principal_count': len(scores['unique_principals']),
        })
    
    # Sort by total score (highest first)
    subscription_risks.sort(key=lambda x: x['total_score'], reverse=True)
    
    return subscription_risks


def print_subscription_risk_ranking(subscription_risks: list) -> None:
    """
    Print subscription risk ranking table.
    """
    print("SUBSCRIPTION RISK RANKING")
    print("="*90)
    print(f"{'Rank':<6} {'Subscription':<45} {'Risk Score':<12} {'Assignments':<13} {'Principals'}")
    print("-" * 90)
    
    for idx, sub in enumerate(subscription_risks, 1):
        print(
            f"{idx:<6} "
            f"{sub['name']:<45} "
            f"{sub['total_score']:<12} "
            f"{sub['assignment_count']:<13} "
            f"{sub['principal_count']}"
        )
    
    print()


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


def analyze_subscription(
    subscription_id: str,
    subscription_name: str,
    credential: DefaultAzureCredential,
    cfg,
) -> tuple[List, dict, dict]:
    """
    Analyze a single subscription and return records, taxonomy, and actions.
    """
    print(f"\nAnalyzing subscription: {subscription_name} ({subscription_id})")
    
    authz = AuthorizationManagementClient(credential, subscription_id)
    role_lookup = build_role_definition_lookup(authz, subscription_id)
    records = collect_role_assignments(authz, subscription_id, role_lookup)
    
    runtime_taxonomy, runtime_actions = build_runtime_taxonomy(
        records,
        authz,
        subscription_id,
        cfg.role_taxonomy,
    )
    
    print(f"  Found {len(records)} role assignments across {len(runtime_taxonomy)} roles")
    
    return records, runtime_taxonomy, runtime_actions


def main() -> None:
    parser = argparse.ArgumentParser(description="Azure RBAC Risk Analyzer")
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress AI enrichment output; only print progress lines",
    )
    args = parser.parse_args()

    try:
        credential = DefaultAzureCredential(exclude_interactive_browser_credential=True)
        available_subs = enumerate_subscriptions(credential)
    except ClientAuthenticationError:
        print("\nError: Not authenticated with Azure.")
        print("Run 'az login' and try again.\n")
        sys.exit(1)
    
    if not available_subs:
        print("No active subscriptions found.")
        sys.exit(1)
    
    selected_subs = select_subscriptions_interactive(available_subs)
    
    if not selected_subs:
        print("No subscriptions selected.")
        sys.exit(1)
    
    print(f"\nAnalyzing {len(selected_subs)} subscription(s)...\n")
    
    cfg = load_risk_config()
    
    # Collect data from all selected subscriptions
    all_records = []
    all_taxonomies = {}
    all_actions = {}
    role_subscriptions = {}
    sub_id_to_name = {sub['id']: sub['name'] for sub in selected_subs}

    # Now all_records is fully populated — build role_subscriptions here
    for record in all_records:
        if record.role_name not in role_subscriptions:
            role_subscriptions[record.role_name] = set()
        role_subscriptions[record.role_name].add(sub_id_to_name[record.subscription_id])
    
    for sub in selected_subs:
        records, taxonomy, actions = analyze_subscription(
            sub['id'],
            sub['name'],
            credential,
            cfg,
        )
        
        all_records.extend(records)
        all_taxonomies.update(taxonomy)
        all_actions.update(actions)

    for record in all_records:
        role_subscriptions.setdefault(record.role_name, set()).add(
            sub_id_to_name.get(record.subscription_id, record.subscription_id)
        )
    
    # Aggregate and score across all subscriptions
    runtime_cfg = replace(cfg, role_taxonomy=all_taxonomies)
    scored = score_records(all_records, runtime_cfg)
    
    scored = [
        replace(sa, triggering_action=all_actions.get(sa.record.role_name, ""))
        for sa in scored
    ]
    
    principal_summaries = summarize_principal_risk(scored, runtime_cfg)
    
    # Print tenant-level summary
    print()
    print("TENANT-LEVEL RISK SUMMARY")
    print("="*90)
    print(f"Subscriptions analyzed: {len(selected_subs)}")
    print(f"Assigned roles: {len(all_records)}")
    print(f"Unique Assignments: {len(all_taxonomies)}")
    print()
    
    # Calculate and display subscription risk scores
    subscription_risks = calculate_subscription_risk_scores(scored, selected_subs)
    print_subscription_risk_ranking(subscription_risks)
    
    name_cache: dict[tuple[str, str], str] = {}
    member_count_cache: dict[str, int] = {}
    top_principals = principal_summaries[:10]

    for p in top_principals:
        cache_key = (p.principal_id, p.principal_type)
        if cache_key not in name_cache:
            name_cache[cache_key] = resolve_principal_name(
                credential,
                p.principal_id,
                p.principal_type,
            )
        if p.principal_type == "Group" and p.principal_id not in member_count_cache:
            member_count_cache[p.principal_id] = get_group_member_count(
                credential,
                p.principal_id,
            )

    if not args.quiet:
        print_assigned_role_classifications(all_taxonomies, all_actions)

        print("Top risky principals:")
        print()

        for p in top_principals:
            cache_key = (p.principal_id, p.principal_type)
            principal_name = name_cache[cache_key]

            member_info = ""
            if p.principal_type == "Group":
                count = member_count_cache.get(p.principal_id, 0)
                if count > 0:
                    member_info = f" ({count} members)"

            print(
                f"Name = {principal_name}{member_info} | "
                f"Type = {p.principal_type} | "
                f"ID = {p.principal_id} | "
                f"Severity = {p.cumulative_severity} | "
                f"Score = {p.cumulative_score} | "
                f"Assignments = {len(p.risky_assignments)} | "
                f"Riskiest Role = {p.highest_assignment.record.role_name}"
            )

            for sa in p.risky_assignments:
                r = sa.record
                scope_display = extract_scope_display_name(r.scope, r.scope_type)
                print(
                    f"  - {sa.severity} | "
                    f"{sa.score} | "
                    f"{r.role_name} | "
                    f"Action = {sa.triggering_action or 'N/A'} | "
                    f"Classification = {sa.bucket} | "
                    f"Scope = {scope_display} ({r.scope_type}) | "
                    f"Sub = ...{r.subscription_id[-8:]}"
                )

            print()

    report_path = write_report(
        selected_subs=selected_subs,
        all_records=all_records,
        all_taxonomies=all_taxonomies,
        all_actions=all_actions,
        subscription_risks=subscription_risks,
        top_principals=top_principals,
        principal_names=name_cache,
        group_member_counts=member_count_cache,
    )
    print(f"Report saved to {report_path}")
    run_ai_enrichment(
        report_path=report_path,
        top_principals=top_principals,
        principal_names=name_cache,
        selected_subs=selected_subs,
        quiet=args.quiet,
    )

    export_pdf = input("Export report as PDF? [y/N]: ").strip().lower()
    if export_pdf == "y":
        try:
            pdf_path = generate_pdf_report(
                report_path=report_path,
                selected_subs=selected_subs,
                all_records=all_records,
                all_taxonomies=all_taxonomies,
                all_actions=all_actions,
                role_subscriptions=role_subscriptions,
                subscription_risks=subscription_risks,
                top_principals=top_principals,
                principal_names=name_cache,
            )
            print(f"PDF report saved to {pdf_path}")
        except Exception as exc:
            print(f"Failed to generate PDF report: {exc}")

    run_remediation = input("Run remediation engine? [y/N]: ").strip().lower()
    if run_remediation == "y":
        from .remediation_engine import run_remediation_engine
        run_remediation_engine(report_path, credential)


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as e:
        print(f"\nError: {e}", file=sys.stderr)
        sys.exit(1)