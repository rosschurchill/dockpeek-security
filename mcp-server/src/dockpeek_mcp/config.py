"""Configuration loaded from environment variables."""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    """DockPeek MCP server configuration.

    All values are loaded from environment variables at construction time.
    DOCKPEEK_PASSWORD is required — the server will refuse to start without it.
    """

    url: str
    username: str
    password: str
    verify_ssl: bool
    timeout: int

    def __init__(self) -> None:
        password = os.environ.get("DOCKPEEK_PASSWORD")
        if not password:
            raise RuntimeError(
                "DOCKPEEK_PASSWORD environment variable is required but not set. "
                "Set it to the DockPeek admin password before starting the MCP server."
            )

        # frozen=True means we must use object.__setattr__ for init
        object.__setattr__(self, "url", os.environ.get("DOCKPEEK_URL", "http://localhost:5051").rstrip("/"))
        object.__setattr__(self, "username", os.environ.get("DOCKPEEK_USERNAME", "admin"))
        object.__setattr__(self, "password", password)
        object.__setattr__(self, "verify_ssl", os.environ.get("DOCKPEEK_VERIFY_SSL", "true").lower() in ("true", "1", "yes"))
        object.__setattr__(self, "timeout", int(os.environ.get("DOCKPEEK_TIMEOUT", "30")))
