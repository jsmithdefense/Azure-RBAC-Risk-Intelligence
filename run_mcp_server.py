#!/usr/bin/env python
"""
This file starts the Azure RBAC MCP server.

`src/mcp_server.py` uses imports that are relative to the package. For example,
`from .analysis_api import ...`. Thus you cannot start that file directly. The
command `python src/mcp_server.py` fails with this message: "attempted relative
import with no known parent package". You must start it as a module with
`python -m src.mcp_server`, and the working directory must be the root of the
repository.

An MCP client does not always set the working directory of the server that it
starts. Thus you must not depend on the working directory. This file adds the
root of the repository to sys.path and then starts the server. Thus the command
operates from any directory.

Use this file as the MCP server command.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.mcp_server import main  # noqa: E402  (set sys.path before this import)

if __name__ == "__main__":
    main()
