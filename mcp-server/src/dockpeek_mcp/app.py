"""Shared MCP application singletons — imported by server.py and all tool modules."""
from __future__ import annotations

import logging

from mcp.server.fastmcp import FastMCP

from .config import Config
from .client import DockPeekClient

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("dockpeek-mcp")

config = Config()
client = DockPeekClient(config)

mcp = FastMCP(
    "dockpeek-security",
    instructions="DockPeek Security MCP — Docker container fleet intelligence and CVE scanning for SOC operations",
)
