#!/usr/bin/env python
"""
Launcher for the Azure RBAC MCP server.

`src/mcp_server.py` uses package-relative imports (`from .analysis_api import ...`),
so it cannot be run as a loose script -- `python src/mcp_server.py` fails with
"attempted relative import with no known parent package". It must be run as a
module: `python -m src.mcp_server`, which requires the repo root to be the
working directory.

MCP clients do not reliably control the working directory of a server they spawn,
so relying on that is fragile. This launcher pins the repo root onto sys.path and
invokes the server, which makes the command work from any working directory.

Register this file as the MCP server command.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.mcp_server import main  # noqa: E402  (import must follow sys.path setup)

if __name__ == "__main__":
    main()
