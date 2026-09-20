from __future__ import annotations

from dataclasses import dataclass
from typing import Dict

from .config_loader import RiskConfig
from .models import RoleAssignmentRecord


# This is the full list of capability classifications. The most severe
# classification is first.
#
# This list is the only source. Each part of the tool that needs the names, the
# sequence or the meaning reads them here. These parts are: the sort in the CLI
# (main._bucket_rank), the analysis API, and the MCP server. The MCP server also
# sends this list to the client. Thus a model cannot invent a classification.
#
# The keys must agree with role_weights in config/risk_weights.json.
CAPABILITY_BUCKETS: dict[str, str] = {
    "privilege_escalation": (
        "Can modify access control. A principal with this role can grant itself "
        "or others additional permissions, which makes it the highest-impact "
        "class of assignment."
    ),
    "resource_control_broad": (
        "Can create, modify, and delete infrastructure across three or more "
        "Azure service families. Broad blast radius if the identity is "
        "compromised."
    ),
    "resource_control_narrow": (
        "Can create, modify, and delete resources within a limited set of Azure "
        "service families. Real write power, but scoped to a service domain."
    ),
    "data_access": (
        "Can read or extract stored data through the data plane, not just "
        "resource metadata. Relevant to data exfiltration risk."
    ),
    "security_visibility": (
        "Can view security or monitoring telemetry. Read-only, but reveals "
        "detection coverage and alerting posture."
    ),
    "read_only": (
        "Limited to metadata inspection. Cannot change resources or access "
        "control."
    ),
    "custom_or_unknown": (
        "Could not be classified from its permission set. Treat as unknown and "
        "review the action list manually."
    ),
}

DEFAULT_BUCKET = "custom_or_unknown"


def classify_role(role_name: str, cfg: RiskConfig) -> str:
    """
    Returns the capability bucket for a given role name.

    If the role isn't in the taxonomy map, fall back to custom_or_unknown.
    """
    return cfg.role_taxonomy.get(role_name, DEFAULT_BUCKET)


def score_assignment(record: RoleAssignmentRecord, cfg: RiskConfig) -> int:
    """
    Computes a risk score for a normalized RBAC assignment record.

    Score components:
      - role capability weight (taxonomy bucket)
      - scope weight (subscription/resource_group/resource)
      - principal modifier (User/Group/ServicePrincipal/ManagedIdentity/Unknown)
    """
    bucket = classify_role(record.role_name, cfg)

    role_weight = cfg.role_weights.get(bucket, cfg.role_weights.get(DEFAULT_BUCKET, 0))
    scope_weight = cfg.scope_weights.get(record.scope_type, 0)

    principal_type = record.principal_type or "Unknown"
    principal_mod = cfg.principal_modifiers.get(
        principal_type,
        cfg.principal_modifiers.get("Unknown", 0),
    )

    return int(role_weight + scope_weight + principal_mod)


def severity_from_score(score: int, cfg: RiskConfig) -> str:
    """
    Converts a numeric score into a severity label based on thresholds.

    Thresholds are minimum scores.
    """
    crit = cfg.severity_thresholds.get("critical", 80)
    high = cfg.severity_thresholds.get("high", 60)
    med = cfg.severity_thresholds.get("medium", 40)

    if score >= crit:
        return "Critical"
    if score >= high:
        return "High"
    if score >= med:
        return "Medium"
    return "Low"


@dataclass(frozen=True)
class ScoredAssignment:
    record: RoleAssignmentRecord
    score: int
    severity: str
    bucket: str
    triggering_action: str


@dataclass(frozen=True)
class PrincipalRiskSummary:
    principal_id: str
    principal_type: str
    cumulative_score: int
    cumulative_severity: str
    highest_assignment: ScoredAssignment
    risky_assignments: list[ScoredAssignment]


def score_records(records: list[RoleAssignmentRecord], cfg: RiskConfig) -> list[ScoredAssignment]:
    """
    Score a list of RoleAssignmentRecord objects and return highest risk first.
    """
    out: list[ScoredAssignment] = []

    for r in records:
        bucket = classify_role(r.role_name, cfg)
        s = score_assignment(r, cfg)

        out.append(
            ScoredAssignment(
                record=r,
                score=s,
                severity=severity_from_score(s, cfg),
                bucket=bucket,
                triggering_action="",
            )
        )

    out.sort(key=lambda x: x.score, reverse=True)
    return out


def summarize_principal_risk(
    scored_assignments: list[ScoredAssignment],
    cfg: RiskConfig,
) -> list[PrincipalRiskSummary]:
    """
    Group scored assignments by principal and rank principals by cumulative risk score.
    """
    grouped: Dict[tuple[str, str], list[ScoredAssignment]] = {}

    for sa in scored_assignments:
        principal_id = sa.record.principal_id
        principal_type = sa.record.principal_type or "Unknown"
        key = (principal_id, principal_type)

        grouped.setdefault(key, []).append(sa)

    summaries: list[PrincipalRiskSummary] = []

    for (principal_id, principal_type), assignments in grouped.items():
        assignments.sort(key=lambda x: x.score, reverse=True)
        highest = assignments[0]
        cumulative_score = sum(a.score for a in assignments)
        cumulative_severity = severity_from_score(cumulative_score, cfg)

        summaries.append(
            PrincipalRiskSummary(
                principal_id=principal_id,
                principal_type=principal_type,
                cumulative_score=cumulative_score,
                cumulative_severity=cumulative_severity,
                highest_assignment=highest,
                risky_assignments=assignments,
            )
        )

    summaries.sort(key=lambda x: x.cumulative_score, reverse=True)
    return summaries