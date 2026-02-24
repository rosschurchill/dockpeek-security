"""DockPeek Security MCP Server — main entry point."""
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

# Import tool modules to trigger @mcp.tool() registration.
# Each module imports `mcp` and `client` from this file and
# decorates its functions with @mcp.tool().
from .tools import fleet, security, scanning, logs, updates, system  # noqa: E402, F401


def main() -> None:
    logger.info("Starting DockPeek MCP server, connecting to %s", config.url)
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
