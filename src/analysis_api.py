"""
Headless analysis API.

This module is the non-interactive entry point into the RBAC analysis pipeline.
It exists so that callers which cannot answer `input()` prompts -- the MCP
server, tests, future automation -- can run the same analysis the CLI runs.

Design rules:

1. `src/main.py` is not modified. The CLI keeps its exact behavior. This module
   composes the same building blocks (`analyze_subscription`, `score_records`,
   `summarize_principal_risk`, ...) in a non-interactive order and never calls
   `select_subscriptions_interactive`, `run_ai_enrichment`, or the remediation
   engine.
2. Nothing here writes to stdout. Several pipeline functions call `print()`.
   Under an MCP stdio transport, stray stdout writes corrupt the JSON-RPC
   stream, so every call into printing code is wrapped in `_silenced()`, which
   redirects stdout to stderr.
3. Everything returned is a plain JSON-serializable dict or list of dicts, so
   callers can hand results straight to a structured-output channel.
4. Read-only. No write, no remediation. That is deliberate and is the v1 scope.
"""

from __future__ import annotations

import contextlib
import sys
from dataclasses import replace
from typing import Any, Callable, Iterator, Optional

from azure.identity import DefaultAzureCredential
from azure.mgmt.authorization import AuthorizationManagementClient

from .config_loader import load_risk_config
from .main import (
    analyze_subscription,
    calculate_subscription_risk_scores,
    get_group_member_count,
    resolve_principal_name,
)
from .rbac_collector import enumerate_subscriptions
from .scope_utils import extract_scope_display_name
from .risk_model import (
    CAPABILITY_BUCKETS,
    DEFAULT_BUCKET,
    PrincipalRiskSummary,
    ScoredAssignment,
    score_records,
    summarize_principal_risk,
)
from .role_taxonomy_generator import ROLE_NAME_OVERRIDES, infer_bucket_from_actions


@contextlib.contextmanager
def _silenced() -> Iterator[None]:
    """
    Redirect stdout to stderr for the duration of the block.

    The pipeline functions print progress lines. On an MCP stdio transport
    stdout carries the JSON-RPC framing, so those prints would corrupt the
    protocol. Sending them to stderr keeps them visible in server logs while
    leaving stdout clean.
    """
    with contextlib.redirect_stdout(sys.stderr):
        yield


def _credential() -> DefaultAzureCredential:
    """
    Build the credential the CLI uses.

    `exclude_interactive_browser_credential=True` matches main.py and is
    required here: a headless caller must never trigger a browser prompt.
    """
    return DefaultAzureCredential(exclude_interactive_browser_credential=True)


def _resolve_target_subscriptions(
    credential: DefaultAzureCredential,
    subscription_ids: Optional[list[str]],
) -> list[dict[str, str]]:
    """
    Pick which subscriptions to analyze without prompting.

    This is the non-interactive replacement for
    `select_subscriptions_interactive`. With no ids, every accessible enabled
    subscription is analyzed.
    """
    with _silenced():
        available = enumerate_subscriptions(credential)

    if not available:
        raise RuntimeError(
            "No enabled Azure subscriptions are visible to this credential. "
            "Run 'az login' and confirm the account has Reader at subscription "
            "scope."
        )

    if not subscription_ids:
        return available

    wanted = {s.strip().lower() for s in subscription_ids if s and s.strip()}
    selected = [sub for sub in available if sub["id"].lower() in wanted]

    if not selected:
        visible = ", ".join(sub["id"] for sub in available)
        raise ValueError(
            f"None of the requested subscription ids are accessible. "
            f"Requested: {sorted(wanted)}. Visible: {visible}"
        )

    return selected


def _assignment_to_dict(sa: ScoredAssignment) -> dict[str, Any]:
    """Flatten a ScoredAssignment into a JSON-safe dict."""
    record = sa.record
    return {
        "role_name": record.role_name,
        "classification": sa.bucket,
        "score": sa.score,
        "severity": sa.severity,
        "triggering_action": sa.triggering_action or None,
        "scope": record.scope,
        "scope_type": record.scope_type,
        "scope_display_name": extract_scope_display_name(record.scope, record.scope_type),
        "subscription_id": record.subscription_id,
    }


def _principal_to_dict(
    principal: PrincipalRiskSummary,
    display_name: str,
    member_count: Optional[int] = None,
) -> dict[str, Any]:
    """Flatten a PrincipalRiskSummary into a JSON-safe dict."""
    return {
        "display_name": display_name,
        "principal_id": principal.principal_id,
        "principal_type": principal.principal_type,
        "cumulative_score": principal.cumulative_score,
        "severity": principal.cumulative_severity,
        "assignment_count": len(principal.risky_assignments),
        "riskiest_role": principal.highest_assignment.record.role_name,
        "group_member_count": member_count,
        "assignments": [_assignment_to_dict(sa) for sa in principal.risky_assignments],
    }


def _enrich_principals(
    credential: DefaultAzureCredential,
    principals: list[PrincipalRiskSummary],
    resolve_names: bool,
) -> list[dict[str, Any]]:
    """
    Resolve display names and group member counts, then flatten to dicts.

    Name resolution is a Microsoft Graph round trip per principal, so it is
    optional. `resolve_principal_name` already falls back to the raw id on
    failure, which keeps a missing Graph permission from failing the whole run.
    """
    out: list[dict[str, Any]] = []

    for principal in principals:
        display_name = principal.principal_id
        member_count: Optional[int] = None

        if resolve_names:
            with _silenced():
                display_name = resolve_principal_name(
                    credential,
                    principal.principal_id,
                    principal.principal_type,
                )
                if principal.principal_type == "Group":
                    member_count = get_group_member_count(
                        credential,
                        principal.principal_id,
                    )

        out.append(_principal_to_dict(principal, display_name, member_count))

    return out


def run_analysis(
    subscription_ids: Optional[list[str]] = None,
    *,
    top_n: int = 10,
    resolve_names: bool = True,
    progress: Optional[Callable[[float, float, str], None]] = None,
) -> dict[str, Any]:
    """
    Run the full read-only RBAC analysis and return structured results.

    This is the single engine behind all three MCP tools. It mirrors the
    collect -> score -> summarize sequence in `main.main()`, minus every
    interactive step and minus AI enrichment.

    Args:
        subscription_ids: Subscription ids to analyze. None means all visible.
        top_n: How many principals to return, ranked by cumulative score.
        resolve_names: Resolve principal ids to display names via Graph.
        progress: Optional callback(current, total, message) for long runs.

    Returns:
        A JSON-serializable dict with tenant summary, subscription ranking,
        role classifications, and ranked principals.
    """
    credential = _credential()
    selected_subs = _resolve_target_subscriptions(credential, subscription_ids)

    # One step per subscription, plus scoring and name resolution.
    total_steps = len(selected_subs) + 2
    step = 0

    def report(message: str) -> None:
        nonlocal step
        step += 1
        if progress:
            progress(float(step), float(total_steps), message)

    cfg = load_risk_config()

    all_records: list = []
    all_taxonomies: dict[str, str] = {}
    all_actions: dict[str, str] = {}

    for sub in selected_subs:
        report(f"Analyzing {sub['name']}")
        with _silenced():
            records, taxonomy, actions = analyze_subscription(
                sub["id"],
                sub["name"],
                credential,
                cfg,
            )
        all_records.extend(records)
        all_taxonomies.update(taxonomy)
        all_actions.update(actions)

    report("Scoring assignments")

    # Score against the runtime taxonomy (inferred + analyst overrides), not the
    # static config taxonomy -- this is what main.py does.
    runtime_cfg = replace(cfg, role_taxonomy=all_taxonomies)
    scored = score_records(all_records, runtime_cfg)
    scored = [
        replace(sa, triggering_action=all_actions.get(sa.record.role_name, ""))
        for sa in scored
    ]

    principal_summaries = summarize_principal_risk(scored, runtime_cfg)
    top_principals = principal_summaries[:top_n]

    report("Resolving principal names")
    principals = _enrich_principals(credential, top_principals, resolve_names)

    with _silenced():
        subscription_risks = calculate_subscription_risk_scores(scored, selected_subs)

    return {
        "summary": {
            "subscriptions_analyzed": len(selected_subs),
            "total_assignments": len(all_records),
            "unique_roles_assigned": len(all_taxonomies),
            "principals_found": len(principal_summaries),
            "ai_enrichment": False,
        },
        "subscriptions": [
            {"id": sub["id"], "name": sub["name"]} for sub in selected_subs
        ],
        "subscription_risk_ranking": subscription_risks,
        "role_classifications": [
            {
                "role_name": role,
                "classification": bucket,
                "triggering_action": all_actions.get(role) or None,
            }
            for role, bucket in sorted(all_taxonomies.items())
        ],
        "principals": principals,
    }


def get_high_risk_principals(
    limit: int = 10,
    subscription_ids: Optional[list[str]] = None,
    *,
    resolve_names: bool = True,
    progress: Optional[Callable[[float, float, str], None]] = None,
) -> list[dict[str, Any]]:
    """
    Return the top `limit` riskiest principals, highest cumulative score first.

    Thin projection over run_analysis() so both tools always agree on scoring.
    """
    if limit < 1:
        raise ValueError("limit must be 1 or greater")

    result = run_analysis(
        subscription_ids,
        top_n=limit,
        resolve_names=resolve_names,
        progress=progress,
    )
    return result["principals"]


def explain_role(
    role_name: str,
    subscription_id: Optional[str] = None,
) -> dict[str, Any]:
    """
    Explain what an Azure role can do, without running a full analysis.

    Looks the role definition up in Azure, classifies it with the same
    capability inference the analyzer uses, and returns its permissions plus a
    plain-English summary. No AI call.

    Args:
        role_name: Role display name, e.g. "Contributor". Case-insensitive.
        subscription_id: Subscription to resolve the definition against.
            Defaults to the first visible subscription.
    """
    if not role_name or not role_name.strip():
        raise ValueError("role_name is required")

    role_name = role_name.strip()
    credential = _credential()
    selected = _resolve_target_subscriptions(
        credential,
        [subscription_id] if subscription_id else None,
    )
    target_sub = selected[0]

    authz = AuthorizationManagementClient(credential, target_sub["id"])
    scope = f"/subscriptions/{target_sub['id']}"

    match = None
    available: list[str] = []
    for rd in authz.role_definitions.list(scope):
        current = (getattr(rd, "role_name", None) or "").strip()
        if not current:
            continue
        available.append(current)
        if current.lower() == role_name.lower():
            match = rd
            break

    if match is None:
        suggestions = [r for r in available if role_name.lower() in r.lower()][:5]
        raise ValueError(
            f"Role '{role_name}' was not found in subscription "
            f"{target_sub['name']} ({target_sub['id']})."
            + (f" Did you mean: {', '.join(suggestions)}?" if suggestions else "")
        )

    actions: list[str] = []
    data_actions: list[str] = []
    not_actions: list[str] = []
    not_data_actions: list[str] = []

    for perm in getattr(match, "permissions", None) or []:
        actions.extend(a for a in (getattr(perm, "actions", None) or []))
        data_actions.extend(a for a in (getattr(perm, "data_actions", None) or []))
        not_actions.extend(a for a in (getattr(perm, "not_actions", None) or []))
        not_data_actions.extend(a for a in (getattr(perm, "not_data_actions", None) or []))

    # Classify exactly as the analyzer does: analyst override first, then
    # inference from the permission set.
    inferred_bucket, triggering_action = infer_bucket_from_actions(
        [a.lower() for a in actions],
        [a.lower() for a in data_actions],
    )
    override = ROLE_NAME_OVERRIDES.get(match.role_name.strip())
    classification = override or inferred_bucket

    cfg = load_risk_config()
    role_weight = cfg.role_weights.get(classification)

    return {
        "role_name": match.role_name,
        "classification": classification,
        "classification_source": "analyst_override" if override else "inferred_from_permissions",
        "summary": CAPABILITY_BUCKETS.get(classification, CAPABILITY_BUCKETS[DEFAULT_BUCKET]),
        "triggering_action": triggering_action or None,
        "role_weight": role_weight,
        "is_builtin": getattr(match, "role_type", None) == "BuiltInRole",
        "description": getattr(match, "description", None),
        "permissions": {
            "actions": actions,
            "not_actions": not_actions,
            "data_actions": data_actions,
            "not_data_actions": not_data_actions,
        },
        "evaluated_in_subscription": {
            "id": target_sub["id"],
            "name": target_sub["name"],
        },
    }
