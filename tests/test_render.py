"""
Renderer regression test. No network, no Azure.

Guards the contract between ai_enrichment and its two consumers: pdf_report
splits the rendered text on its headings, and the report JSON stores it. If the
renderer drifts, the PDF silently loses content -- so assert the shape here.

Run from the repo root:

    python -m tests.test_render
"""

from __future__ import annotations

from src.ai_enrichment import _normalize_action, _render_summary_text
from src.pdf_report import _split_ai_sections

SAMPLE = {
    "capability_summary": ["Controls every resource.", "Can grant itself more access."],
    "recommended_actions": [
        {
            "priority": "HIGH",
            "effort": "Low",
            "title": "Enable MFA",
            "why": "Account is unprotected.",
            "steps": ["Open Entra ID", "Require MFA"],
            "validation": "Sign-in prompts for MFA.",
        },
        {
            "priority": "CRITICAL",
            "effort": "Medium",
            "title": "Convert to PIM eligible",
            "why": "Standing privilege.",
            "steps": ["Open PIM", "Mark eligible"],
            "validation": "Shows Eligible.",
        },
    ],
}


def test_headings_present_for_pdf() -> None:
    text = _render_summary_text(SAMPLE)
    assert "Capability Summary:" in text
    assert "Recommended Actions:" in text

    cap, rec = _split_ai_sections(text)
    assert len(cap) == 2, f"expected 2 capability lines, got {len(cap)}"
    assert rec, "pdf_report parsed no recommended-action lines"


def test_critical_sorts_first() -> None:
    text = _render_summary_text(SAMPLE)
    _, rec = _split_ai_sections(text)
    assert rec[0].startswith("1. [CRITICAL"), f"expected CRITICAL first, got {rec[0]!r}"


def test_action_title_format_is_stable() -> None:
    # pdf_report and the terminal both rely on this exact bracket format.
    text = _render_summary_text(SAMPLE)
    assert "[CRITICAL | Effort: Medium] Convert to PIM eligible" in text


def test_bad_model_output_is_normalized_not_fatal() -> None:
    assert _normalize_action({"not": "an action"}) is None, "missing title must be dropped"
    assert _normalize_action("a string") is None, "non-dict must be dropped"

    fixed = _normalize_action(
        {"title": "T", "priority": "bogus", "effort": "enormous", "steps": "one step"}
    )
    assert fixed is not None
    assert fixed["priority"] == "MEDIUM", fixed["priority"]
    assert fixed["effort"] == "Medium", fixed["effort"]
    assert fixed["steps"] == ["one step"], fixed["steps"]


def test_empty_summary_still_renders() -> None:
    text = _render_summary_text({})
    assert "Capability Summary:" in text
    cap, _ = _split_ai_sections(text)
    assert cap, "an empty response must still produce a parseable section"


if __name__ == "__main__":
    test_headings_present_for_pdf()
    test_critical_sorts_first()
    test_action_title_format_is_stable()
    test_bad_model_output_is_normalized_not_fatal()
    test_empty_summary_still_renders()
    print("ok - renderer assertions passed")
