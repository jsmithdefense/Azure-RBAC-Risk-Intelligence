"""
This test examines the classification weights. It does not call Azure.

Start the test from the root of the repository:

    python -m tests.test_taxonomy_weights

The weights in config/risk_weights.json are the only source of severity order.
This test makes sure that they stay correct and complete. Two errors existed
before, and this test stops both of them:

1. `custom_or_unknown` had weight 25, and `resource_control_narrow` had 20. Thus
   a role that the tool cannot read scored higher than a role that can write.
   That is wrong. An unread role is not more dangerous than a known write role,
   and it took a position in the list of the riskiest principals.
2. `CAPABILITY_BUCKETS` declared a severity order in the sequence of its keys,
   and the weights disagreed with it. Thus the CLI showed one order and the
   scores used a different order.
"""

from __future__ import annotations

from src.config_loader import load_risk_config
from src.risk_model import CAPABILITY_BUCKETS, DEFAULT_BUCKET

# These classifications mean that the role can write, or can change access.
# An unread role must always score less than each of these.
_KNOWN_WRITE_BUCKETS = (
    "privilege_escalation",
    "resource_control_broad",
    "resource_control_narrow",
    "data_access",
)


def test_every_classification_has_a_weight() -> None:
    weights = load_risk_config().role_weights

    missing = [b for b in CAPABILITY_BUCKETS if b not in weights]
    assert not missing, f"these classifications have no weight: {missing}"

    extra = [b for b in weights if b not in CAPABILITY_BUCKETS]
    assert not extra, f"these weights have no classification: {extra}"


def test_unknown_scores_below_every_known_write_classification() -> None:
    weights = load_risk_config().role_weights
    unknown = weights[DEFAULT_BUCKET]

    for bucket in _KNOWN_WRITE_BUCKETS:
        assert unknown < weights[bucket], (
            f"{DEFAULT_BUCKET} ({unknown}) must score less than "
            f"{bucket} ({weights[bucket]}). A role that the tool cannot read "
            "must not outrank a role that can write."
        )


def test_unknown_scores_above_read_only() -> None:
    # An unread role must still appear. If it scores the same as read_only, a
    # person will not examine it.
    weights = load_risk_config().role_weights
    assert weights[DEFAULT_BUCKET] > weights["read_only"], (
        f"{DEFAULT_BUCKET} ({weights[DEFAULT_BUCKET]}) must score more than "
        f"read_only ({weights['read_only']}), or nobody will examine it."
    )


def test_privilege_escalation_is_the_highest() -> None:
    weights = load_risk_config().role_weights
    highest = max(weights, key=lambda b: weights[b])
    assert highest == "privilege_escalation", (
        f"privilege_escalation must have the highest weight, but {highest} has it. "
        "A role that can change access control is the most dangerous role."
    )


def test_read_only_is_the_lowest() -> None:
    weights = load_risk_config().role_weights
    lowest = min(weights, key=lambda b: weights[b])
    assert lowest == "read_only", (
        f"read_only must have the lowest weight, but {lowest} has it."
    )


if __name__ == "__main__":
    test_every_classification_has_a_weight()
    test_unknown_scores_below_every_known_write_classification()
    test_unknown_scores_above_read_only()
    test_privilege_escalation_is_the_highest()
    test_read_only_is_the_lowest()
    print("ok - taxonomy weight assertions passed")
