"""
This is the MCP server. It gives Azure RBAC risk analysis as three tools. The
tools only read data.

The server uses fastmcp 4.0.5. It does not use the official `mcp` SDK 2.2.0
directly. There are three reasons:
1. fastmcp 4.0.5 needs mcp 2.2.0. Thus fastmcp is a layer above the official
   SDK. It is not a different product, and the protocol is the same.
2. `Context.report_progress(progress, total, message)` is available. The
   analysis tool needs it, because the analysis can take 120 seconds. A tool
   that returns a dict also gets structuredContent automatically.
3. `Context.elicit` is available. Version 1.1 needs it for the remediation tool,
   because that tool must ask the user to agree.

These tools only read. That is intentional. No tool changes Azure. Version 1.1
will add a remediation tool, but only with a step that asks the user to agree,
and with limits.

The server sends the list of classifications in three places: the server
instructions, the description of each tool, and the resource
azure-rbac://taxonomy. This is intentional. A client that sees only one
classification at a time will invent a classification that does not exist. If
the server sends the full list, the client cannot do this.
"""

from __future__ import annotations

import asyncio
import os
from typing import Annotated, Any, Optional

from fastmcp import Context, FastMCP
from pydantic import Field

from .analysis_api import explain_role as _explain_role
from .analysis_api import get_high_risk_principals as _get_high_risk_principals
from .analysis_api import run_analysis as _run_analysis
from .config_loader import load_risk_config
from .risk_model import CAPABILITY_BUCKETS

# The server puts this text in the instructions and in each tool description.
# Thus the full list goes to the client with each initialize and tools/list.
_BUCKET_LIST = ", ".join(CAPABILITY_BUCKETS)
_VOCABULARY_NOTE = (
    f"Role classifications are a closed set of exactly {len(CAPABILITY_BUCKETS)} "
    f"values: {_BUCKET_LIST}. Never report a classification outside this list; "
    "read the azure-rbac://taxonomy resource or call azure_rbac_explain_role if "
    "you need a role's classification."
)

mcp = FastMCP(
    name="azure-rbac",
    instructions=(
        "Read-only Azure RBAC risk analysis. Enumerates role assignments, "
        "classifies roles by what their permissions actually allow, and scores "
        "principals by cumulative privilege across subscriptions. "
        "Use azure_rbac_get_high_risk for 'who is riskiest', azure_rbac_analyze "
        "for a full tenant picture, and azure_rbac_explain_role to understand a "
        "single role. These tools never modify Azure; they only read.\n\n"
        + _VOCABULARY_NOTE
    ),
)


@mcp.resource(
    "azure-rbac://taxonomy",
    name="capability_taxonomy",
    description=(
        "The complete set of role capability classifications this server can "
        "return, each with its meaning and its risk weight. Ordered most to "
        "least severe. Use this to interpret any 'classification' field."
    ),
    mime_type="application/json",
)
def capability_taxonomy() -> dict[str, Any]:
    """Send the full list of classifications and the weight of each one."""
    role_weights = load_risk_config().role_weights

    # Sort by weight. The weights are the only source of severity order, so this
    # makes the "ordering" field below correct.
    ordered = sorted(
        CAPABILITY_BUCKETS.items(),
        key=lambda item: -role_weights.get(item[0], 0),
    )

    return {
        "ordering": "most severe first, by risk_weight",
        "classifications": [
            {
                "name": bucket,
                "description": description,
                "risk_weight": role_weights.get(bucket),
            }
            for bucket, description in ordered
        ],
    }


def _default_subscription_ids(subscription_id: Optional[str]) -> Optional[list[str]]:
    """
    Change one optional subscription id to the list that the API needs.

    If the argument is empty, the function uses AZURE_SUBSCRIPTION_ID. Thus you
    can limit the server to one subscription with the configuration. None means
    all the subscriptions that you can see.
    """
    if subscription_id and subscription_id.strip():
        return [subscription_id.strip()]

    env_sub = os.environ.get("AZURE_SUBSCRIPTION_ID", "").strip()
    return [env_sub] if env_sub else None


def _progress_reporter(ctx: Context):
    """
    Make a function that reports progress. The function is safe in a thread.

    `run_analysis()` operates in a worker thread, because `asyncio.to_thread`
    starts it. But `ctx.report_progress` is a coroutine, and it belongs to the
    event loop. `run_coroutine_threadsafe` connects the two. Thus the progress
    goes from the worker to the client, and no thread touches the loop
    incorrectly.

    You must call this function from a loop that operates, that is, from a tool
    coroutine.
    """
    loop = asyncio.get_running_loop()

    def report(current: float, total: float, message: str) -> None:
        asyncio.run_coroutine_threadsafe(
            ctx.report_progress(progress=current, total=total, message=message),
            loop,
        )

    return report


@mcp.tool(
    name="azure_rbac_analyze",
    description=(
        "Run a full read-only RBAC risk analysis across Azure subscriptions. "
        "Returns tenant summary, per-subscription risk ranking, role "
        "classifications, and ranked principals. Takes 30-120 seconds. "
        + _VOCABULARY_NOTE
    ),
)
async def azure_rbac_analyze(
    ctx: Context,
    subscription_id: Annotated[
        Optional[str],
        Field(description="Subscription to analyze. Omit to analyze all visible subscriptions."),
    ] = None,
    top_n: Annotated[
        int,
        Field(ge=1, le=100, description="How many principals to return, ranked by cumulative risk."),
    ] = 10,
    resolve_names: Annotated[
        bool,
        Field(description="Resolve principal ids to display names via Microsoft Graph. Slower but far more readable."),
    ] = True,
) -> dict[str, Any]:
    """Full RBAC analysis. Read-only."""
    await ctx.info("Starting Azure RBAC analysis")

    result = await asyncio.to_thread(
        _run_analysis,
        _default_subscription_ids(subscription_id),
        top_n=top_n,
        resolve_names=resolve_names,
        progress=_progress_reporter(ctx),
    )

    summary = result["summary"]
    await ctx.info(
        f"Analyzed {summary['subscriptions_analyzed']} subscription(s), "
        f"{summary['total_assignments']} assignments"
    )
    return result


@mcp.tool(
    name="azure_rbac_get_high_risk",
    description=(
        "Return the riskiest principals ranked by cumulative privilege across "
        "all accessible subscriptions. Use this to answer 'who has too much "
        "access'. Each returned assignment carries a classification. Read-only. "
        + _VOCABULARY_NOTE
    ),
)
async def azure_rbac_get_high_risk(
    ctx: Context,
    limit: Annotated[
        int,
        Field(ge=1, le=100, description="How many principals to return."),
    ] = 10,
    subscription_id: Annotated[
        Optional[str],
        Field(description="Restrict to one subscription. Omit for all visible subscriptions."),
    ] = None,
) -> dict[str, Any]:
    """Top N riskiest principals. Read-only."""
    await ctx.info(f"Finding top {limit} riskiest principals")

    principals = await asyncio.to_thread(
        _get_high_risk_principals,
        limit,
        _default_subscription_ids(subscription_id),
        resolve_names=True,
        progress=_progress_reporter(ctx),
    )

    return {"principals": principals}


@mcp.tool(
    name="azure_rbac_explain_role",
    description=(
        "Explain what a specific Azure role can actually do: its capability "
        "classification, full permission set, and a plain-English summary. "
        "Fast -- does not run a full analysis. Read-only. "
        + _VOCABULARY_NOTE
    ),
)
async def azure_rbac_explain_role(
    ctx: Context,
    role_name: Annotated[
        str,
        Field(description="Role display name, for example 'Contributor' or 'User Access Administrator'."),
    ],
    subscription_id: Annotated[
        Optional[str],
        Field(description="Subscription to resolve the role definition against. Defaults to the first visible subscription."),
    ] = None,
) -> dict[str, Any]:
    """Explain a single role. Read-only."""
    await ctx.info(f"Looking up role: {role_name}")

    subs = _default_subscription_ids(subscription_id)
    return await asyncio.to_thread(
        _explain_role,
        role_name,
        subs[0] if subs else None,
    )


def main() -> None:
    """Run the server over stdio, the standard transport for a local MCP server."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
