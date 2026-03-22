from __future__ import annotations

from dataclasses import dataclass
from typing import Dict

from .config_loader import RiskConfig
from .models import RoleAssignmentRecord


DEFAULT_BUCKET = "custom_or_unknown"


def classify_role(role_name: str, cfg: RiskConfig) -> str:
    """
    Returns the capability bucket for a given role name.

    If the role isn't in the taxonomy map, fall back to custom_or_unknown.
    """
    return cfg.role_taxonomy.get(role_name, DEFAULT_BUCKET)


def classify_role_with_trigger(record: RoleAssignmentRecord, cfg: RiskConfig) -> tuple[str, str]:
    """
    Returns:
        (bucket, triggering_action_suffix)

    For now, the bucket comes from the runtime taxonomy map used by scoring.
    The triggering action will remain blank until main.py passes it through.
    """
    bucket = classify_role(record.role_name, cfg)
    return bucket, ""


def score_assignment(record: RoleAssignmentRecord, cfg: RiskConfig) -> int:
    """
    Computes a risk score for a normalized RBAC assignment record.

    Score components:
      - role capability weight (taxonomy bucket)
      - scope weight (subscription/resource_group/resource)
      - principal modifier (User/Group/ServicePrincipal/ManagedIdentity/Unknown)
    """
    bucket, _ = classify_role_with_trigger(record, cfg)

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
    cumulative_score: int  # renamed from highest_score
    cumulative_severity: str  # renamed from highest_severity
    highest_assignment: ScoredAssignment
    risky_assignments: list[ScoredAssignment]


def score_records(records: list[RoleAssignmentRecord], cfg: RiskConfig) -> list[ScoredAssignment]:
    """
    Score a list of RoleAssignmentRecord objects and return highest risk first.
    """
    out: list[ScoredAssignment] = []

    for r in records:
        bucket, triggering_action = classify_role_with_trigger(r, cfg)
        s = score_assignment(r, cfg)

        out.append(
            ScoredAssignment(
                record=r,
                score=s,
                severity=severity_from_score(s, cfg),
                bucket=bucket,
                triggering_action=triggering_action,
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
        
        # Calculate cumulative score across all assignments.

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