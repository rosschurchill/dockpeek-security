"""Configuration loaded from environment variables."""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    """DockPeek MCP server configuration.

    All values are loaded from environment variables at construction time.
    Either DOCKPEEK_API_KEY or DOCKPEEK_PASSWORD must be set — the server
    will refuse to start without at least one of them.

    When DOCKPEEK_API_KEY is set it takes precedence: the client sends the
    key via the X-API-Key header and skips the form-based login flow entirely.
    """

    url: str
    username: str
    password: str
    api_key: str
    verify_ssl: bool
    timeout: int

    def __init__(self) -> None:
        api_key = os.environ.get("DOCKPEEK_API_KEY", "")
        password = os.environ.get("DOCKPEEK_PASSWORD", "")

        if not api_key and not password:
            raise RuntimeError(
                "Either DOCKPEEK_API_KEY or DOCKPEEK_PASSWORD environment variable is required. "
                "Set DOCKPEEK_API_KEY for header-based auth or DOCKPEEK_PASSWORD for form-based login."
            )

        # frozen=True means we must use object.__setattr__ for init
        object.__setattr__(self, "url", os.environ.get("DOCKPEEK_URL", "http://localhost:5051").rstrip("/"))
        object.__setattr__(self, "username", os.environ.get("DOCKPEEK_USERNAME", "admin"))
        object.__setattr__(self, "password", password)
        object.__setattr__(self, "api_key", api_key)
        object.__setattr__(self, "verify_ssl", os.environ.get("DOCKPEEK_VERIFY_SSL", "true").lower() in ("true", "1", "yes"))
        object.__setattr__(self, "timeout", int(os.environ.get("DOCKPEEK_TIMEOUT", "30")))
