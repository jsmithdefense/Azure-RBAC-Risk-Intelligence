from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any


def _build_report_principal(
    principal: Any,
    principal_name: str,
    member_count: int | None,
) -> dict[str, Any]:
    assignments = []
    for sa in principal.risky_assignments:
        record = sa.record
        assignments.append(
            {
                "severity": sa.severity,
                "score": sa.score,
                "role": record.role_name,
                "classification": sa.bucket,
                "triggering_action": sa.triggering_action or "N/A",
                "scope": record.scope,
                "scope_type": record.scope_type,
                "subscription_id": record.subscription_id,
            }
        )

    return {
        "name": principal_name,
        "type": principal.principal_type,
        "id": principal.principal_id,
        "member_count": member_count,
        "severity": principal.cumulative_severity,
        "cumulative_score": principal.cumulative_score,
        "riskiest_role": principal.highest_assignment.record.role_name,
        "assignments": assignments,
    }


def write_report(
    selected_subs: list[dict[str, str]],
    all_records: list[Any],
    all_taxonomies: dict[str, str],
    all_actions: dict[str, str],
    subscription_risks: list[dict[str, Any]],
    top_principals: list[Any],
    principal_names: dict[tuple[str, str], str],
    group_member_counts: dict[str, int],
) -> str:
    """
    Write a timestamped JSON report to reports/ and return a relative path.
    """
    generated_at = datetime.now().isoformat(timespec="seconds")

    metadata = {
        "generated_timestamp": generated_at,
        "subscriptions_analyzed": [
            {"name": sub["name"], "id": sub["id"]} for sub in selected_subs
        ],
        "total_assignments": len(all_records),
        "unique_roles": len(all_taxonomies),
    }

    principals = []
    for principal in top_principals:
        cache_key = (principal.principal_id, principal.principal_type)
        principal_name = principal_names.get(cache_key, principal.principal_id)
        member_count = (
            group_member_counts.get(principal.principal_id, 0)
            if principal.principal_type == "Group"
            else None
        )
        principals.append(_build_report_principal(principal, principal_name, member_count))

    role_classifications = []
    for role_name in sorted(all_taxonomies.keys(), key=str.lower):
        role_classifications.append(
            {
                "role": role_name,
                "bucket": all_taxonomies.get(role_name, "custom_or_unknown"),
                "triggering_action": all_actions.get(role_name, "") or "N/A",
            }
        )

    payload = {
        "metadata": metadata,
        "subscription_risk_ranking": subscription_risks,
        "principals": principals,
        "role_classifications": role_classifications,
    }

    project_root = Path(__file__).resolve().parents[1]
    reports_dir = project_root / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    filename = f"rbac_risk_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    output_path = reports_dir / filename
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    return str(Path("reports") / filename)
