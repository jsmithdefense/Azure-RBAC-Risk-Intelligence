"""
AI enrichment. This module makes capability summaries and remediation plans in
plain English.

The module does not depend on one supplier. The endpoint, the model and the
credential come from config/llm.json and from the environment. Refer to
src/llm_client.py. A remote service and a local model server use the same code.
There is no special condition for one or the other. Thus a company can use its
own endpoint, and the RBAC data stays in its network.

Read these two rules before you change this module:

1. **The model sends JSON. Python makes all the text.** The previous version told
   the model to make an exact text layout. It specified the indentation, the
   empty lines and the punctuation of each title. Then it used a regular
   expression to find a JSON block in that text. This is not reliable with a
   large model, and it fails with a small local model. Now the model sends data,
   and `_render_summary_text` makes the text. Thus the result is the same after
   each analysis, and the data is easy to read.

2. **The text keeps the previous layout exactly.** `pdf_report` divides the text
   at the headings "Capability Summary:" and "Recommended Actions:". The report
   file keeps the text in the field `capability_summary`. Do not change the
   layout. If you change it, you must change those two users also.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .config_loader import load_llm_defaults
from .llm_client import (
    LLMConfig,
    LLMError,
    complete_json,
    estimate_cost_usd,
    estimate_tokens,
    resolve_config,
)
from .scope_utils import extract_scope_display_name

SYSTEM_PROMPT = """You are a cloud security analyst specializing in Azure RBAC risk interpretation.

You receive JSON describing one Azure principal and its role assignments. Return ONLY a JSON object with exactly these three keys:

{
  "capability_summary": [
    "3 to 5 plain English sentences describing what this principal can actually do across the environment. Focus on operational impact and realistic abuse potential. Do not just restate role names."
  ],
  "recommended_actions": [
    {
      "priority": "CRITICAL | HIGH | MEDIUM | LOW",
      "effort": "Low | Medium | High",
      "title": "Short imperative title",
      "why": "One sentence tying this to a specific risk in the input.",
      "steps": ["Specific Azure-native step", "Another step"],
      "validation": "One concrete verifiable check."
    }
  ],
  "remediation_actions": [
    {
      "priority": "CRITICAL",
      "effort": "Low",
      "title": "Matches a recommended_actions title",
      "action_type": "remove_role_assignment | convert_to_pim_eligible | manual_review_required",
      "parameters": {
        "principal_id": "exact principal_id from the input",
        "principal_type": "exact principal_type from the input",
        "role_name": "exact role_name from the input",
        "scope": "exact full scope path from the input",
        "subscription_id": "exact subscription_id from the input",
        "subscription_name": "exact subscription_name from the input"
      },
      "validation": {
        "type": "role_assignment_absent",
        "description": "How to verify success."
      }
    }
  ]
}

Rules:
- Give 3 to 5 recommended_actions.
- Steps must be Azure-native and specific: exact portal paths such as Subscription > Access control (IAM), az CLI commands, or Microsoft Entra PIM workflows. Reference the actual role names, scopes, subscription names, and principal name from the input.
- Prefer least-privilege fixes: PIM eligible assignments, narrower scope, dedicated admin groups, just-in-time access.
- Produce one remediation_actions entry per recommended action whose type can be mapped.
- Use action_type "remove_role_assignment" to remove a permanent assignment, "convert_to_pim_eligible" to make an assignment PIM eligible, and "manual_review_required" for anything else.
- For "manual_review_required", omit "parameters" and "validation" and include a top-level "description" with plain instructions instead.
- validation.type must be "role_assignment_absent" for remove_role_assignment, otherwise "manual".
- Copy principal_id, scope, and subscription_id EXACTLY from the input. Never invent or abbreviate an identifier.
- Return only the JSON object. No prose, no markdown fence, no commentary."""

# This is the sort order. The prompt tells the model to set a priority, but the
# tool does not obey the model's sequence. Python sorts the actions. Thus a small
# model has one less opportunity to make an error.
_PRIORITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
_VALID_EFFORT = {"low": "Low", "medium": "Medium", "high": "High"}


def _build_principal_payload(
    principal: Any,
    principal_name: str,
    sub_id_to_name: dict[str, str],
) -> dict[str, Any]:
    """Make the JSON data that describes one principal. Send it to the model."""
    assignment_payloads = []
    for sa in principal.risky_assignments:
        r = sa.record
        assignment_payloads.append(
            {
                "role_name": r.role_name,
                "classification_bucket": sa.bucket,
                "triggering_action": sa.triggering_action or "N/A",
                "scope_display_name": extract_scope_display_name(r.scope, r.scope_type),
                "scope": r.scope,
                "scope_type": r.scope_type,
                "subscription_id": r.subscription_id,
                "subscription_name": sub_id_to_name.get(r.subscription_id, r.subscription_id),
            }
        )

    return {
        "principal_id": principal.principal_id,
        "principal_name": principal_name,
        "principal_type": principal.principal_type,
        "severity": principal.cumulative_severity,
        "cumulative_score": principal.cumulative_score,
        "assignments": assignment_payloads,
    }


def _select_principals(
    top_principals: list[Any],
    principal_names: dict[tuple[str, str], str],
) -> list[Any]:
    print()
    print("AI ENRICHMENT SELECTION")
    print("=" * 90)
    for idx, p in enumerate(top_principals, 1):
        name = principal_names.get((p.principal_id, p.principal_type), p.principal_id)
        print(f"{idx}. {name} | Severity = {p.cumulative_severity} | Score = {p.cumulative_score}")

    print()
    print("Select principals to enrich:")
    print("  - Enter comma-separated numbers (e.g., 1,3,5)")
    print("  - Enter 0 for all")
    print("  - Enter S to skip")
    raw = input("> ").strip()

    if not raw or raw.upper() == "S":
        return []
    if raw == "0":
        return list(top_principals)

    selected: list[Any] = []
    seen: set[int] = set()
    for token in [t.strip() for t in raw.split(",") if t.strip()]:
        try:
            idx = int(token)
        except ValueError:
            continue
        if idx < 1 or idx > len(top_principals):
            continue
        zero_idx = idx - 1
        if zero_idx in seen:
            continue
        seen.add(zero_idx)
        selected.append(top_principals[zero_idx])

    return selected


def _confirm_endpoint(
    cfg: LLMConfig,
    selected_principals: list[Any],
    principal_names: dict[tuple[str, str], str],
    sub_id_to_name: dict[str, str],
) -> dict[str, dict[str, Any]] | None:
    """
    Show the endpoint and the estimated size. Then ask the user to agree.

    The endpoint line is necessary. The user must see where the RBAC data goes,
    and must know if the data goes out of the machine. Show this before you send
    any data.

    Return the data for each principal. Return None if the user does not agree.
    """
    payload_map: dict[str, dict[str, Any]] = {}
    per_principal = []
    total_input = 0
    total_output = 0

    for p in selected_principals:
        key = f"{p.principal_id}|{p.principal_type}"
        name = principal_names.get((p.principal_id, p.principal_type), p.principal_id)
        payload_obj = _build_principal_payload(p, name, sub_id_to_name)
        payload_map[key] = payload_obj

        payload_text = json.dumps(payload_obj, ensure_ascii=True)
        input_tokens = estimate_tokens(SYSTEM_PROMPT) + estimate_tokens(payload_text)
        output_tokens = 900  # A full JSON plan is larger than the previous text.
        total_input += input_tokens
        total_output += output_tokens
        per_principal.append((name, input_tokens, output_tokens))

    print()
    print("AI ENRICHMENT ENDPOINT")
    print("=" * 90)
    print(f"  {cfg.describe_endpoint()}")
    if not cfg.is_local:
        print("  Note: principal names, role names, and scope paths will be sent to this endpoint.")
    print()
    print("Estimated size per selected principal:")
    for name, in_tok, out_tok in per_principal:
        print(f"  - {name}: ~{in_tok} input tok + ~{out_tok} output tok")

    total_cost = estimate_cost_usd(cfg, total_input, total_output)
    print()
    if total_cost is None:
        reason = "local endpoint" if cfg.is_local else f"no price configured for {cfg.model}"
        print(f"Estimated cost: none ({reason})")
    else:
        print(
            f"Total estimated cost ({cfg.model}, "
            f"{len(selected_principals)} principal(s)): ${total_cost:.6f}"
        )

    confirm = input("Proceed with AI enrichment? [y/N]: ").strip().lower()
    return payload_map if confirm == "y" else None


def _normalize_action(action: Any) -> dict[str, Any] | None:
    """
    Change one recommended action to the correct shape. Remove the action if it
    is not usable.

    A model can send an unknown priority. It can send a text string where a list
    is necessary. It can omit a field. The tool must continue in these
    conditions. Thus the function corrects what it can, and removes the rest.
    """
    if not isinstance(action, dict):
        return None

    title = str(action.get("title") or "").strip()
    if not title:
        return None

    priority = str(action.get("priority") or "MEDIUM").strip().upper()
    if priority not in _PRIORITY_ORDER:
        priority = "MEDIUM"

    effort = _VALID_EFFORT.get(str(action.get("effort") or "").strip().lower(), "Medium")

    steps = action.get("steps") or []
    if isinstance(steps, str):
        steps = [steps]
    steps = [str(s).strip() for s in steps if str(s).strip()]

    return {
        "priority": priority,
        "effort": effort,
        "title": title,
        "why": str(action.get("why") or "").strip(),
        "steps": steps,
        "validation": str(action.get("validation") or "").strip(),
    }


def _render_summary_text(data: dict[str, Any]) -> str:
    """
    Make the report text from the JSON that the model sends.

    The layout is the same layout that the prompt previously specified. This is
    intentional. `pdf_report._split_ai_sections` divides the text at these
    headings, and the report file keeps the result. Python makes the text here.
    Thus the result is the same after each analysis, and it does not depend on
    the model.
    """
    lines: list[str] = ["Capability Summary:"]

    bullets = data.get("capability_summary") or []
    if isinstance(bullets, str):
        bullets = [bullets]
    rendered_bullets = [str(b).strip() for b in bullets if str(b).strip()]
    if not rendered_bullets:
        rendered_bullets = ["No capability summary was returned."]

    for bullet in rendered_bullets:
        lines.append(f"- {bullet}")
        lines.append("")

    actions = [
        normalized
        for normalized in (_normalize_action(a) for a in (data.get("recommended_actions") or []))
        if normalized
    ]
    actions.sort(key=lambda a: _PRIORITY_ORDER[a["priority"]])

    if actions:
        lines.append("Recommended Actions:")
        lines.append("")
        for idx, action in enumerate(actions, 1):
            lines.append(f"{idx}. [{action['priority']} | Effort: {action['effort']}] {action['title']}")
            lines.append("")
            if action["why"]:
                lines.append("   Why")
                lines.append("")
                lines.append(f"   {action['why']}")
                lines.append("")
            if action["steps"]:
                lines.append("   Steps")
                lines.append("")
                for step_no, step in enumerate(action["steps"], 1):
                    lines.append(f"     {step_no}. {step}")
                lines.append("")
            if action["validation"]:
                lines.append("   Validation")
                lines.append("")
                lines.append(f"   {action['validation']}")
                lines.append("")

    return "\n".join(lines).rstrip()


def _append_enrichment_to_report(
    report_path: str,
    enrichment: dict[tuple[str, str], tuple[str, list]],
) -> None:
    """Write the summaries and the remediation actions into the report file."""
    report_file = Path(report_path)
    if not report_file.is_absolute():
        report_file = Path(__file__).resolve().parents[1] / report_file

    data = json.loads(report_file.read_text(encoding="utf-8"))
    for principal in data.get("principals", []):
        key = (principal.get("id", ""), principal.get("type", ""))
        if key in enrichment:
            summary_text, actions = enrichment[key]
            principal["capability_summary"] = summary_text
            principal["remediation_actions"] = actions
    report_file.write_text(json.dumps(data, indent=2), encoding="utf-8")


def run_ai_enrichment(
    report_path: str,
    top_principals: list[Any],
    principal_names: dict[tuple[str, str], str],
    selected_subs: list[dict[str, str]],
    quiet: bool = False,
) -> None:
    selected = _select_principals(top_principals, principal_names)
    if not selected:
        print("AI enrichment skipped.")
        return

    try:
        cfg = resolve_config(load_llm_defaults(), dict(os.environ))
    except LLMError as exc:
        print(f"AI enrichment unavailable: {exc}")
        return

    sub_id_to_name = {sub["id"]: sub["name"] for sub in selected_subs}
    payload_map = _confirm_endpoint(cfg, selected, principal_names, sub_id_to_name)
    if payload_map is None:
        print("AI enrichment cancelled.")
        return

    if not quiet:
        print()
        print("AI ENRICHMENT SUMMARY")
        print("=" * 90)

    enrichment: dict[tuple[str, str], tuple[str, list]] = {}
    total = len(selected)

    for idx, principal in enumerate(selected, 1):
        principal_name = principal_names.get(
            (principal.principal_id, principal.principal_type),
            principal.principal_id,
        )
        print(f"[{idx}/{total}] Enriching {principal_name} ...")

        key = f"{principal.principal_id}|{principal.principal_type}"
        payload_text = json.dumps(payload_map[key], ensure_ascii=True, indent=2)

        try:
            data = complete_json(cfg, SYSTEM_PROMPT, payload_text)
        except LLMError as exc:
            print(f"  Error enriching {principal_name}: {exc}")
            continue

        summary_text = _render_summary_text(data)
        actions = data.get("remediation_actions")
        actions = actions if isinstance(actions, list) else []

        enrichment[(principal.principal_id, principal.principal_type)] = (summary_text, actions)

        if not quiet:
            print(summary_text)
            if actions:
                print(f"  -> Generated {len(actions)} structured remediation action(s).")
            print()

    if not enrichment:
        print("No AI capability summaries were generated.")
        return

    try:
        _append_enrichment_to_report(report_path, enrichment)
        print(f"Updated report with capability summaries: {report_path}")
    except Exception as exc:
        print(f"Failed to append summaries to report JSON: {exc}")
