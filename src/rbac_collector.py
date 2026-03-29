import os
from typing import Dict, List, Optional

from azure.identity import DefaultAzureCredential
from azure.mgmt.authorization import AuthorizationManagementClient

from .models import RoleAssignmentRecord
from .scope_utils import classify_scope

def enumerate_subscriptions(credential: DefaultAzureCredential) -> List[Dict[str, str]]:
    """
    Enumerate all subscriptions accessible to the credential.
    
    Returns:
        List of dicts with 'id', 'name', 'state' keys
    """
    from azure.mgmt.subscription import SubscriptionClient
    
    sub_client = SubscriptionClient(credential)
    subscriptions = []
    
    for sub in sub_client.subscriptions.list():
        if sub.state == "Enabled":  # Only include active subscriptions
            subscriptions.append({
                'id': sub.subscription_id,
                'name': sub.display_name,
                'state': sub.state
            })
    
    return subscriptions


def select_subscriptions_interactive(
    available_subs: List[Dict[str, str]]
) -> List[Dict[str, str]]:
    """
    Present subscriptions to user and let them choose which to analyze.
    
    Returns:
        Selected subscriptions (or all if user chooses that option)
    """
    print("\nAvailable subscriptions:")
    print(f"{'No':<5} {'Name':<50} {'ID':<40} {'State'}")
    print("-" * 100)
    
    for idx, sub in enumerate(available_subs, 1):
        print(f"[{idx}]{'':<3} {sub['name']:<50} {sub['id']:<40} {sub['state']}")
    
    print(f"\n[0]    Analyze all subscriptions")
    print()
    
    choice = input("Select subscriptions to analyze (comma-separated numbers, or 0 for all): ").strip()
    
    if choice == "0":
        return available_subs
    
    try:
        indices = [int(x.strip()) for x in choice.split(",")]
        selected = [available_subs[i - 1] for i in indices if 1 <= i <= len(available_subs)]
        return selected if selected else available_subs
    except (ValueError, IndexError):
        print("Invalid selection, analyzing all subscriptions.")
        return available_subs

def get_subscription_id() -> str:
    sub_id = os.environ.get("AZURE_SUBSCRIPTION_ID")
    if not sub_id:
        raise RuntimeError(
            "AZURE_SUBSCRIPTION_ID is not set. Run:\n"
            "  export AZURE_SUBSCRIPTION_ID=$(az account show --query id -o tsv)"
        )
    return sub_id


def build_role_definition_lookup(
    authz: AuthorizationManagementClient, subscription_id: str
) -> Dict[str, str]:
    """
    Returns a dict mapping full role_definition_id -> role_name.

    Azure role assignments DO NOT store role names. This lookup converts Azure API output into a normalized RBAC record.
    """
    scope = f"/subscriptions/{subscription_id}"
    lookup: Dict[str, str] = {}

    for rd in authz.role_definitions.list(scope):
        if rd.id and rd.role_name:
            lookup[rd.id] = rd.role_name

    return lookup


def collect_role_assignments(
    authz: AuthorizationManagementClient,
    subscription_id: str,
    role_lookup: Dict[str, str],
    *,
    scope: Optional[str] = None,
) -> List[RoleAssignmentRecord]:
    """
    Collect role assignments visible under a scope and normalize them.

    - scope defaults to subscription scope
    - role_name is resolved via role_lookup
    - scope_type is derived from the resolved scope string
    """
    target_scope = scope or f"/subscriptions/{subscription_id}"
    records: List[RoleAssignmentRecord] = []

    for ra in authz.role_assignments.list_for_scope(target_scope):
        resolved_scope = ra.scope or target_scope
        rd_id = ra.role_definition_id or ""
        role_name = role_lookup.get(rd_id, "UNKNOWN_ROLE")

        records.append(
            RoleAssignmentRecord(
                subscription_id=subscription_id,
                scope=resolved_scope,
                scope_type=classify_scope(resolved_scope),
                principal_id=ra.principal_id or "UNKNOWN_PRINCIPAL",
                principal_type=ra.principal_type,
                role_definition_id=rd_id,
                role_name=role_name,
            )
        )

    return records

