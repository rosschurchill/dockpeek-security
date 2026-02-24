"""HTTP client for the DockPeek Security Flask application."""
from __future__ import annotations

import logging
from typing import Any

import requests

from .config import Config

logger = logging.getLogger("dockpeek-mcp.client")


class DockPeekError(Exception):
    """Raised when a DockPeek API request fails."""


class DockPeekClient:
    """Session-based HTTP client for DockPeek Security.

    Handles cookie-based authentication (Flask-Login) with automatic
    re-authentication when the session expires (DockPeek returns a 302
    redirect to /login on expired sessions).

    Authentication is lazy — the first call to get() or post() will
    trigger a login if the session is not yet established.
    """

    def __init__(self, config: Config) -> None:
        self._config = config
        self._base_url = config.url
        self._session = requests.Session()
        self._session.verify = config.verify_ssl
        self._authenticated = False

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def authenticate(self) -> None:
        """Authenticate against DockPeek's /login endpoint.

        DockPeek uses Flask-Login with form-based POST.  A successful
        login returns a 302 redirect to '/'.  The session cookie is
        stored in self._session automatically.
        """
        login_url = f"{self._base_url}/login"
        logger.info("Authenticating to DockPeek at %s", login_url)

        resp = self._session.post(
            login_url,
            data={"username": self._config.username, "password": self._config.password},
            allow_redirects=False,
            timeout=self._config.timeout,
        )

        # Flask-Login returns 302 to '/' on success
        if resp.status_code == 302:
            location = resp.headers.get("Location", "")
            if "/login" not in location:
                self._authenticated = True
                logger.info("Authentication successful")
                return

        # If we get here, login failed
        self._authenticated = False
        raise DockPeekError(
            f"Authentication failed (HTTP {resp.status_code}). "
            "Check DOCKPEEK_USERNAME and DOCKPEEK_PASSWORD."
        )

    # ------------------------------------------------------------------
    # Internal request handling
    # ------------------------------------------------------------------

    def _request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        """Make an authenticated request, re-authenticating if the session expired.

        Args:
            method: HTTP method (GET, POST, etc.)
            path: URL path relative to the DockPeek base URL (e.g. '/data')
            **kwargs: Passed through to requests.Session.request()

        Returns:
            The requests.Response object.

        Raises:
            DockPeekError: On authentication failure or HTTP errors.
        """
        kwargs.setdefault("timeout", self._config.timeout)
        url = f"{self._base_url}{path}"

        # Lazy authentication on first request
        if not self._authenticated:
            self.authenticate()

        resp = self._session.request(method, url, allow_redirects=False, **kwargs)

        # Detect session expiry: DockPeek redirects to /login
        if resp.status_code == 302 and "/login" in resp.headers.get("Location", ""):
            logger.info("Session expired, re-authenticating")
            self.authenticate()
            resp = self._session.request(method, url, allow_redirects=False, **kwargs)

        # Raise on HTTP errors (4xx, 5xx)
        if resp.status_code >= 400:
            raise DockPeekError(
                f"{method.upper()} {path} returned HTTP {resp.status_code}: {resp.text[:500]}"
            )

        return resp

    # ------------------------------------------------------------------
    # Convenience methods
    # ------------------------------------------------------------------

    def get(self, path: str, **kwargs: Any) -> Any:
        """GET request returning parsed JSON."""
        resp = self._request("GET", path, **kwargs)
        return resp.json()

    def post(self, path: str, **kwargs: Any) -> Any:
        """POST request returning parsed JSON."""
        resp = self._request("POST", path, **kwargs)
        return resp.json()
