"""
Azure RBAC scope parsing.

This module owns everything that interprets a scope string, so the rest of the
codebase does not re-implement it. Both functions here were previously
duplicated across main.py, ai_enrichment.py and pdf_report.py.
"""


def classify_scope(scope: str) -> str:
    """
    Classifies an Azure RBAC scope into a simplified category.

    Returns:
        subscription
        resource_group
        resource
    """
    scope = scope.lower()

    if "/resourcegroups/" not in scope:
        return "subscription"

    if "/providers/" not in scope:
        return "resource_group"

    return "resource"


def extract_scope_display_name(scope: str, scope_type: str) -> str:
    """
    Produce a short human-readable name for a scope.

    Subscription scopes have no meaningful sub-name, so they render as
    "subscription". Resource-group scopes render as the group name, and resource
    scopes render as "<resource group>/<resource>". Anything unparseable falls
    back to the scope type rather than raising.
    """
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
