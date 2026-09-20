"""
This module reads an Azure RBAC scope string.

All the code that interprets a scope is in this module. Thus the other modules
do not write this logic again. Both functions were previously in three modules:
main.py, ai_enrichment.py and pdf_report.py.
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
    Make a short name for a scope. A person can read this name.

    A subscription scope has no sub-name. Thus it becomes "subscription". A
    resource group scope becomes the name of the group. A resource scope becomes
    "<resource group>/<resource>". If the function cannot read the scope, it
    returns the scope type. It does not raise an error.
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
