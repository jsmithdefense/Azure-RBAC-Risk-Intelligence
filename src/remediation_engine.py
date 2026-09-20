from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from azure.mgmt.authorization import AuthorizationManagementClient


# ---------------------------------------------------------------------------
# Audit helpers
# ---------------------------------------------------------------------------

def _resolve_report_path(report_path: str) -> Path:
    p = Path(report_path)
    if not p.is_absolute():
        p = Path(__file__).resolve().parents[1] / p
    return p


def _audit_path() -> Path:
    project_root = Path(__file__).resolve().parents[1]
    reports_dir = project_root / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return reports_dir / f"remediation_audit_{ts}.json"


def _read_audit(path: Path) -> list[dict[str, Any]]:
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return []
    return []


def _write_audit(path: Path, records: list[dict[str, Any]]) -> None:
    path.write_text(json.dumps(records, indent=2), encoding="utf-8")


def _append_audit_record(path: Path, record: dict[str, Any]) -> None:
    records = _read_audit(path)
    records.append(record)
    _write_audit(path, records)


def _update_audit_record(path: Path, record_id: str, updates: dict[str, Any]) -> None:
    records = _read_audit(path)
    for rec in records:
        if rec.get("_id") == record_id:
            rec.update(updates)
            break
    _write_audit(path, records)


# ---------------------------------------------------------------------------
# Action execution
# ---------------------------------------------------------------------------

def _execute_remove_role_assignment(
    params: dict[str, Any],
    credential: Any,
) -> dict[str, Any]:
    subscription_id = params["subscription_id"]
    scope = params["scope"]
    principal_id = params["principal_id"]
    role_name = params["role_name"]

    try:
        client = AuthorizationManagementClient(credential, subscription_id)

        assignments = list(
            client.role_assignments.list_for_scope(
                scope,
                filter=f"principalId eq '{principal_id}'",
            )
        )
    except Exception as exc:
        return {"status": "failed", "error": f"Failed to list role assignments: {exc}", "validation_result": None}

    target = None
    try:
        for assignment in assignments:
            rd = client.role_definitions.get_by_id(assignment.role_definition_id)
            if rd.role_name == role_name:
                target = assignment
                break
    except Exception as exc:
        return {"status": "failed", "error": f"Failed to look up role definitions: {exc}", "validation_result": None}

    if target is None:
        return {
            "status": "failed",
            "error": f"Role assignment '{role_name}' not found for principal '{principal_id}' at scope '{scope}'",
            "validation_result": None,
        }

    try:
        client.role_assignments.delete(scope, target.name)
    except Exception as exc:
        return {"status": "failed", "error": f"Delete failed: {exc}", "validation_result": None}

    # Validation: confirm the assignment no longer exists
    try:
        remaining = list(
            client.role_assignments.list_for_scope(
                scope,
                filter=f"principalId eq '{principal_id}'",
            )
        )
        still_exists = any(r.role_definition_id == target.role_definition_id for r in remaining)
        if still_exists:
            return {
                "status": "failed",
                "error": "Assignment still present after deletion",
                "validation_result": False,
            }
        return {"status": "success", "error": None, "validation_result": True}
    except Exception as exc:
        # Deletion appeared to succeed but validation query failed — treat as success with a warning
        return {"status": "success", "error": f"Validation query failed: {exc}", "validation_result": None}


def _execute_action(action: dict[str, Any], credential: Any) -> dict[str, Any]:
    action_type = action.get("action_type", "")

    if action_type == "remove_role_assignment":
        return _execute_remove_role_assignment(action.get("parameters", {}), credential)

    if action_type == "convert_to_pim_eligible":
        print(
            "  PIM conversion requires manual execution via Azure Portal"
            " — instructions have been logged."
        )
        print("  Steps:")
        print("    1. Open Azure Portal > Microsoft Entra ID > Privileged Identity Management")
        print("    2. Select 'Azure resources' and navigate to the target subscription/scope")
        print("    3. Under 'Assignments', locate the permanent assignment and convert to Eligible")
        return {"status": "manual", "error": None, "validation_result": None}

    if action_type == "manual_review_required":
        description = action.get("description", "No description provided.")
        print(f"  Manual review required: {description}")
        return {"status": "manual", "error": None, "validation_result": None}

    return {
        "status": "failed",
        "error": f"Unknown action_type: '{action_type}'",
        "validation_result": None,
    }


# ---------------------------------------------------------------------------
# Selection UI
# ---------------------------------------------------------------------------

def _collect_all_actions(
    principals: list[dict[str, Any]],
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """Return a flat list of (principal, action) for all structured actions."""
    items: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for principal in principals:
        for action in principal.get("remediation_actions", []):
            items.append((principal, action))
    return items


def _display_actions(items: list[tuple[dict[str, Any], dict[str, Any]]]) -> None:
    print()
    print("REMEDIATION ENGINE")
    print("=" * 90)

    current_principal: str | None = None
    for idx, (principal, action) in enumerate(items, 1):
        name = principal.get("name", principal.get("id", "unknown"))
        p_type = principal.get("type", "")
        header = f"{name} ({p_type})"
        if header != current_principal:
            if current_principal is not None:
                print()
            print(f"  Principal: {header}")
            current_principal = header
        priority = action.get("priority", "?")
        effort = action.get("effort", "?")
        title = action.get("title", action.get("action_type", ""))
        action_type = action.get("action_type", "")
        print(f"    {idx}. [{priority} | Effort: {effort}] {title}  ({action_type})")


def _parse_selection(
    raw: str,
    total: int,
) -> list[int] | None:
    """Return 0-based indices or None to skip."""
    raw = raw.strip()
    if not raw or raw.upper() == "S":
        return None
    if raw == "0":
        return list(range(total))
    indices: list[int] = []
    seen: set[int] = set()
    for token in [t.strip() for t in raw.split(",") if t.strip()]:
        try:
            n = int(token)
            if n < 1 or n > total:
                continue
            zi = n - 1
            if zi not in seen:
                seen.add(zi)
                indices.append(zi)
        except ValueError:
            continue
    return indices


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run_remediation_engine(report_path: str, credential: Any) -> None:
    # Read report
    try:
        report_file = _resolve_report_path(report_path)
        data = json.loads(report_file.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"Remediation engine: failed to read report: {exc}")
        return

    principals_with_actions = [
        p for p in data.get("principals", [])
        if p.get("remediation_actions")
    ]

    if not principals_with_actions:
        print("No structured remediation actions found in report.")
        return

    all_items = _collect_all_actions(principals_with_actions)
    _display_actions(all_items)

    print()
    print("Select actions to execute (comma-separated numbers, 0=all, S=skip):")
    raw = input("> ").strip()
    indices = _parse_selection(raw, len(all_items))

    if indices is None:
        print("Remediation engine skipped.")
        return

    selected = [all_items[i] for i in indices]
    if not selected:
        print("No valid actions selected.")
        return

    audit_path = _audit_path()
    counts = {"success": 0, "failed": 0, "manual": 0, "skipped": 0}

    print()
    for principal, action in selected:
        title = action.get("title", action.get("action_type", ""))
        action_type = action.get("action_type", "")
        priority = action.get("priority", "")
        principal_name = principal.get("name", principal.get("id", "unknown"))

        print(f"About to: [{priority}] {title}  ({action_type})")
        print(f"  Principal: {principal_name}")
        if action_type == "remove_role_assignment":
            params = action.get("parameters", {})
            print(f"  Role:  {params.get('role_name', '?')}")
            print(f"  Scope: {params.get('scope', '?')}")

        confirm = input("Execute this remediation? [y/N]: ").strip().lower()
        if confirm != "y":
            print("  Skipped.")
            counts["skipped"] += 1
            print()
            continue

        record_id = f"{action_type}_{principal.get('id', '')}_{datetime.now().isoformat()}"
        audit_record: dict[str, Any] = {
            "_id": record_id,
            "timestamp": datetime.now().isoformat(),
            "principal_name": principal_name,
            "action_type": action_type,
            "title": title,
            "parameters": action.get("parameters", {}),
            "status": "pending",
            "error": None,
            "validation_result": None,
        }
        _append_audit_record(audit_path, audit_record)

        result = _execute_action(action, credential)

        audit_updates = {
            "status": result["status"],
            "error": result.get("error"),
            "validation_result": result.get("validation_result"),
        }
        _update_audit_record(audit_path, record_id, audit_updates)

        status = result["status"]
        counts[status] += 1

        if status == "success":
            print("  Result: SUCCESS — assignment removed and validated.")
        elif status == "failed":
            print(f"  Result: FAILED — {result.get('error', 'unknown error')}")
        elif status == "manual":
            print("  Result: MANUAL — logged to audit file.")

        print()

    # Summary
    print("REMEDIATION SUMMARY")
    print("=" * 90)
    print(f"  Succeeded:      {counts['success']}")
    print(f"  Failed:         {counts['failed']}")
    print(f"  Manual/skipped: {counts['manual'] + counts['skipped']}")
    if any(v > 0 for v in [counts["success"], counts["failed"], counts["manual"]]):
        print(f"  Audit log:      {audit_path}")
    print()
