"""
This test examines the scores. It does not call Azure. It uses records that this
file makes.

Start the test from the root of the repository:

    python -m tests.test_scoring

This test does not need pytest. That is intentional. It uses `assert` and a
`__main__` block. Thus the list of requirements stays short, but the test still
fails clearly if the scores change.

Use this test when you change risk_model.py or role_taxonomy_generator.py. The
values below come from config/risk_weights.json:
  Owner  = privilege_escalation(50) + subscription(25) + ServicePrincipal(10) = 85
  Reader = read_only(5)             + resource_group(15) + User(0)            = 20
"""

from __future__ import annotations

from src.config_loader import load_risk_config
from src.models import RoleAssignmentRecord
from src.risk_model import score_records


def _record(role_name: str, scope_type: str, principal_type: str) -> RoleAssignmentRecord:
    scope = "/subscriptions/sub123"
    if scope_type == "resource_group":
        scope += "/resourceGroups/rg1"
    return RoleAssignmentRecord(
        subscription_id="sub123",
        scope=scope,
        scope_type=scope_type,
        principal_id=f"{role_name.lower()}-principal",
        principal_type=principal_type,
        role_definition_id=(
            "/subscriptions/sub123/providers/Microsoft.Authorization"
            f"/roleDefinitions/{role_name.lower()}-guid"
        ),
        role_name=role_name,
    )


def test_scoring() -> None:
    cfg = load_risk_config()

    samples = [
        _record("Owner", "subscription", "ServicePrincipal"),
        _record("Reader", "resource_group", "User"),
    ]

    scored = score_records(samples, cfg)
    by_role = {s.record.role_name: s for s in scored}

    assert len(scored) == 2, f"expected 2 scored assignments, got {len(scored)}"

    # score_records must put the highest risk first.
    assert scored[0].record.role_name == "Owner", (
        f"expected Owner ranked first, got {scored[0].record.role_name}"
    )

    owner = by_role["Owner"]
    assert owner.bucket == "privilege_escalation", f"Owner bucket: {owner.bucket}"
    assert owner.score == 85, f"Owner score: {owner.score} (expected 50+25+10)"
    assert owner.severity == "Critical", f"Owner severity: {owner.severity}"

    reader = by_role["Reader"]
    assert reader.bucket == "read_only", f"Reader bucket: {reader.bucket}"
    assert reader.score == 20, f"Reader score: {reader.score} (expected 5+15+0)"
    assert reader.severity == "Low", f"Reader severity: {reader.severity}"


if __name__ == "__main__":
    test_scoring()
    print("ok - scoring assertions passed")
