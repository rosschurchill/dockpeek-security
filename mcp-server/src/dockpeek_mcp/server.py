"""DockPeek Security MCP Server — main entry point."""
from __future__ import annotations

from .app import mcp, config, logger  # noqa: F401

# Import tool modules to trigger @mcp.tool() registration.
from .tools import fleet, security, scanning, logs, updates, system  # noqa: E402, F401


def main() -> None:
    logger.info("Starting DockPeek MCP server, connecting to %s", config.url)
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
