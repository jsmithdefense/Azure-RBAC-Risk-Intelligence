from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from anthropic import Anthropic

SYSTEM_PROMPT = """You are a cloud security analyst specializing in Azure RBAC risk interpretation.
Given principal-level RBAC data, produce three sections exactly in this format:

Capability Summary:
- bullet
- bullet

Recommended Actions:

1. [CRITICAL | Effort: Low] Action Title

   Why
   One sentence explaining the risk

   Steps
     1. Step
     2. Step
     3. Step

   Validation
   One sentence confirming success

2. [HIGH | Effort: Medium] Action Title
...

Remediation Actions:

```json
[
  {
    "priority": "CRITICAL",
    "effort": "Low",
    "title": "Human readable title",
    "action_type": "remove_role_assignment",
    "parameters": {
      "principal_id": "exact principal_id from input",
      "principal_type": "Group",
      "role_name": "exact role name from input",
      "scope": "exact full scope path from input",
      "subscription_id": "exact subscription_id from input",
      "subscription_name": "subscription name"
    },
    "validation": {
      "type": "role_assignment_absent",
      "description": "One sentence describing how to verify success"
    }
  }
]
```

Requirements — Capability Summary:
- Include 3-5 plain English bullets explaining what the principal can actually do across the environment.
- Focus on operational impact and realistic abuse potential, not just repeating role names.

Requirements — Recommended Actions:
- Include 3-5 recommended actions per principal, ordered by priority: all CRITICAL first, then HIGH, then MEDIUM, then LOW.
- Each action title stands alone on its own line formatted exactly as: an opening bracket, PRIORITY, space, pipe, space, Effort:, space, EFFORT_LEVEL, closing bracket, space, Action Title (e.g. [CRITICAL | Effort: Low] Action Title). Do not number the actions.
- PRIORITY must be exactly one of: CRITICAL, HIGH, MEDIUM, LOW — based on severity of the risk being addressed.
- EFFORT_LEVEL must be exactly one of: Low, Medium, High — based on how complex the remediation is to execute.
- After a blank line, include the subheading Why alone on its own line in bold, indented with three spaces, then a blank line, then one sentence explaining the specific risk (indented consistently with Why).
- After a blank line, include the subheading Steps alone on its own line in bold, (same indentation as Why), then a blank line, then numbered steps 1. 2. 3. (use more numbers if needed), each indented with five spaces so they nest under Steps.
- After a blank line, include the subheading Validation alone on its own line in bold, (same indentation as Why), then a blank line, then one sentence describing a concrete, verifiable check.

Content rules for Recommended Actions:
- Why must tie directly to the Capability Summary or assignment risks.
- Steps must be specific and Azure-native: exact portal paths (e.g. Subscription > Access control (IAM)), Azure CLI commands, or Microsoft Entra PIM / Privileged Identity Management workflows where appropriate.
- Steps must reference specific role names, resource groups or scope display names, subscription names, and principal names from the input context.
- Validation must be verifiable (e.g. IAM no longer lists the assignment, PIM state, or expected az role assignment list outcome) — not generic advice.
- Prefer Azure-native fixes: PIM eligible assignments, narrower scope, dedicated admin groups, just-in-time access where appropriate.
- Keep each action concise but complete; separate actions with a blank line.

Requirements — Remediation Actions:
- Output a valid JSON array in a markdown code block tagged as `json` under the "Remediation Actions:" heading.
- Generate one action object per Recommended Action where the action type can be mapped.
- Use action_type "remove_role_assignment" when the recommended action removes a permanent role assignment.
- Use action_type "convert_to_pim_eligible" when the recommended action converts a permanent assignment to PIM eligible.
- For any other remediation that cannot be mapped to these two types, use action_type "manual_review_required" and include a top-level "description" field with plain English instructions instead of "parameters" and "validation".
- Use EXACT values for principal_id, scope, and subscription_id from the input payload — do not approximate or invent them.
- priority and effort must match the corresponding Recommended Action.
- validation.type must be "role_assignment_absent" for remove_role_assignment actions, and "manual" for all others.
- Return only the three sections above with no preamble or closing commentary."""

MODEL_CATALOG = {
    "1": {
        "name": "claude-haiku-4-5-20251001",
        "label": "fastest, lowest cost",
        "input_per_mtok": 1.0,
        "output_per_mtok": 5.0,
    },
    "2": {
        "name": "claude-sonnet-4-6",
        "label": "recommended, balanced",
        "input_per_mtok": 3.0,
        "output_per_mtok": 15.0,
    },
    "3": {
        "name": "claude-opus-4-6",
        "label": "most intelligent, highest cost",
        "input_per_mtok": 5.0,
        "output_per_mtok": 25.0,
    },
}


def _estimate_tokens(text: str) -> int:
    # Rough approximation: 1 token ~= 4 characters for mixed English/JSON payload.
    return max(1, int(len(text) / 4))


def _estimate_cost_usd(input_tokens: int, output_tokens: int, model_info: dict[str, Any]) -> float:
    input_cost = (input_tokens / 1_000_000.0) * model_info["input_per_mtok"]
    output_cost = (output_tokens / 1_000_000.0) * model_info["output_per_mtok"]
    return input_cost + output_cost


def _extract_text_response(message: Any) -> str:
    parts: list[str] = []
    for block in getattr(message, "content", []):
        block_type = getattr(block, "type", "")
        if block_type == "text":
            parts.append(getattr(block, "text", "").strip())
    return "\n".join([p for p in parts if p]).strip()


def _scope_display_name(scope: str, scope_type: str) -> str:
    if scope_type == "subscription":
        return "subscription"

    parts = scope.split("/")
    try:
        rg_index = parts.index("resourceGroups")
        rg_name = parts[rg_index + 1] if rg_index + 1 < len(parts) else "unknown"
    except (ValueError, IndexError):
        return scope_type

    if scope_type == "resource" and parts:
        return f"{rg_name}/{parts[-1]}"
    return rg_name


def _build_principal_payload(
    principal: Any,
    principal_name: str,
    sub_id_to_name: dict[str, str],
) -> dict[str, Any]:
    assignment_payloads = []
    for sa in principal.risky_assignments:
        r = sa.record
        assignment_payloads.append(
            {
                "role_name": r.role_name,
                "classification_bucket": sa.bucket,
                "triggering_action": sa.triggering_action or "N/A",
                "scope_display_name": _scope_display_name(r.scope, r.scope_type),
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
        "instruction": (
            "Return 3-5 plain English bullet points describing what this principal can "
            "actually do across the environment. Focus on operational impact."
        ),
    }


def _select_principals(top_principals: list[Any], principal_names: dict[tuple[str, str], str]) -> list[Any]:
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

    if not raw:
        return []
    if raw.upper() == "S":
        return []
    if raw == "0":
        return list(top_principals)

    selected: list[Any] = []
    seen = set()
    for token in [t.strip() for t in raw.split(",") if t.strip()]:
        try:
            idx = int(token)
            if idx < 1 or idx > len(top_principals):
                continue
            zero_idx = idx - 1
            if zero_idx in seen:
                continue
            seen.add(zero_idx)
            selected.append(top_principals[zero_idx])
        except ValueError:
            continue
    return selected


def _select_model_and_confirm(
    selected_principals: list[Any],
    principal_names: dict[tuple[str, str], str],
    sub_id_to_name: dict[str, str],
) -> tuple[str, dict[str, dict[str, Any]]] | None:
    print()
    print("AI MODEL SELECTION")
    print("=" * 90)
    print("1. claude-haiku-4-5-20251001 — fastest, lowest cost ($1/$5 per MTok)")
    print("2. claude-sonnet-4-6 — recommended, balanced ($3/$15 per MTok)")
    print("3. claude-opus-4-6 — most intelligent, highest cost ($5/$25 per MTok)")
    model_choice = input("Select model [1-3, default 2]: ").strip() or "2"
    if model_choice not in MODEL_CATALOG:
        print("Invalid selection. Defaulting to claude-sonnet-4-6.")
        model_choice = "2"
    model_info = MODEL_CATALOG[model_choice]

    payload_map: dict[str, dict[str, Any]] = {}
    total_input_tokens = 0
    total_output_tokens = 0
    per_principal = []

    for p in selected_principals:
        key = f"{p.principal_id}|{p.principal_type}"
        principal_name = principal_names.get((p.principal_id, p.principal_type), p.principal_id)
        payload_obj = _build_principal_payload(p, principal_name, sub_id_to_name)
        payload_text = json.dumps(payload_obj, ensure_ascii=True)
        input_tokens = _estimate_tokens(SYSTEM_PROMPT) + _estimate_tokens(payload_text)
        output_tokens = 400
        total_input_tokens += input_tokens
        total_output_tokens += output_tokens
        estimated_cost = _estimate_cost_usd(input_tokens, output_tokens, model_info)
        per_principal.append((principal_name, input_tokens, output_tokens, estimated_cost))
        payload_map[key] = payload_obj

    print()
    print("Estimated cost per selected principal:")
    for name, in_tok, out_tok, est_cost in per_principal:
        print(f"  - {name}: ~{in_tok} input tok + ~{out_tok} output tok -> ${est_cost:.6f}")

    total_estimated = _estimate_cost_usd(total_input_tokens, total_output_tokens, model_info)
    print()
    print(
        f"Total estimated cost ({model_info['name']}, {len(selected_principals)} principal(s)): "
        f"${total_estimated:.6f}"
    )
    confirm = input("Proceed with AI enrichment? [y/N]: ").strip().lower()
    if confirm != "y":
        return None

    return model_info["name"], payload_map


def _parse_remediation_actions(text: str) -> list | None:
    """Extract the JSON array from the Remediation Actions code block, if present."""
    match = re.search(r"```json\s*(\[.*?\])\s*```", text, re.DOTALL)
    if not match:
        return None
    try:
        return json.loads(match.group(1))
    except json.JSONDecodeError:
        return None


def _strip_remediation_section(text: str) -> str:
    """Remove the 'Remediation Actions:' section and everything after it."""
    lines = text.splitlines()
    out: list[str] = []
    for line in lines:
        if line.strip() == "Remediation Actions:":
            break
        out.append(line)
    return "\n".join(out).rstrip()


def _append_capability_summary_to_report(
    report_path: str,
    summaries: dict[tuple[str, str], str],
) -> None:
    report_file = Path(report_path)
    if not report_file.is_absolute():
        report_file = Path(__file__).resolve().parents[1] / report_file

    data = json.loads(report_file.read_text(encoding="utf-8"))
    for principal in data.get("principals", []):
        key = (principal.get("id", ""), principal.get("type", ""))
        if key in summaries:
            full_text = summaries[key]
            principal["capability_summary"] = _strip_remediation_section(full_text)
            actions = _parse_remediation_actions(full_text)
            principal["remediation_actions"] = actions if actions is not None else []
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
        print("AI test skipped.")
        return

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        print("AI enrichment unavailable: ANTHROPIC_API_KEY environment variable is not set.")
        print("  To set it run: export ANTHROPIC_API_KEY=your_key_here")
        return

    sub_id_to_name = {sub["id"]: sub["name"] for sub in selected_subs}
    model_and_payloads = _select_model_and_confirm(selected, principal_names, sub_id_to_name)
    if not model_and_payloads:
        print("AI enrichment cancelled.")
        return

    model_name, payload_map = model_and_payloads
    client = Anthropic(api_key=api_key)

    if not quiet:
        print()
        print("AI ENRICHMENT SUMMARY")
        print("=" * 90)

    summaries: dict[tuple[str, str], str] = {}
    total = len(selected)
    for idx, principal in enumerate(selected, 1):
        principal_name = principal_names.get(
            (principal.principal_id, principal.principal_type),
            principal.principal_id,
        )
        print(f"[{idx}/{total}] Enriching {principal_name} ...")

        key = f"{principal.principal_id}|{principal.principal_type}"
        payload_obj = payload_map[key]
        try:
            response = client.messages.create(
                model=model_name,
                max_tokens=4000,
                system=SYSTEM_PROMPT,
                messages=[
                    {
                        "role": "user",
                        "content": json.dumps(payload_obj, ensure_ascii=True, indent=2),
                    }
                ],
            )
            summary_text = _extract_text_response(response) or "- Unable to generate summary."
            summaries[(principal.principal_id, principal.principal_type)] = summary_text
            # Improve terminal readability without changing the stored report content.
            formatted = []
            lines = summary_text.splitlines()
            in_capability = False
            in_recommended = False

            def _is_bullet(line: str) -> bool:
                s = line.lstrip()
                return s.startswith("- ")

            def _is_step(line: str) -> bool:
                s = line.lstrip()
                return len(s) > 1 and s[0].isdigit() and s[1] == "."

            for line in lines:
                stripped = line.strip()

                # Stop rendering at the Remediation Actions section
                if stripped == "Remediation Actions:":
                    break

                if stripped == "Capability Summary:":
                    formatted.append(line)
                    in_capability = True
                    in_recommended = False
                    continue

                if stripped == "Recommended Actions:":
                    if formatted and formatted[-1].strip() != "":
                        formatted.append("")
                    formatted.append(line)
                    in_capability = False
                    in_recommended = True
                    continue

                if in_capability and _is_bullet(line):
                    if formatted and _is_bullet(formatted[-1]):
                        formatted.append("")
                    formatted.append(line)
                    continue

                if in_recommended and _is_step(line):
                    prev = formatted[-1] if formatted else ""
                    if prev and _is_step(prev):
                        formatted.append("")
                    formatted.append(line)
                    continue

                formatted.append(line)

            parsed_actions = _parse_remediation_actions(summary_text)
            if not quiet:
                print("\n".join(formatted).rstrip())
                if parsed_actions is not None:
                    print(f"  -> Generated {len(parsed_actions)} structured remediation action(s).")
                print()
        except Exception as exc:
            print(f"  Error enriching {principal_name}: {exc}")
            continue

    if not summaries:
        print("No AI capability summaries were generated.")
        return

    try:
        _append_capability_summary_to_report(report_path, summaries)
        print(f"Updated report with capability summaries: {report_path}")
    except Exception as exc:
        print(f"Failed to append summaries to report JSON: {exc}")
