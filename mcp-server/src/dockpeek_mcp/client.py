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

    Supports two authentication modes:

    API key mode (preferred):
        Set DOCKPEEK_API_KEY in the environment.  The key is sent via the
        X-API-Key request header on every request.  No login flow is needed
        and the client is considered authenticated immediately.  A 401
        response means the key is invalid — no retry is attempted.

    Password mode (fallback):
        Set DOCKPEEK_PASSWORD (and optionally DOCKPEEK_USERNAME).  Uses
        Flask-Login form-based POST.  DockPeek returns a 302 redirect to
        '/' on success and stores a session cookie.  The client
        re-authenticates automatically when the session expires (detected
        via a 302 redirect back to /login).

    Authentication is lazy — the first call to get() or post() triggers
    login if the session is not yet established (password mode only).
    """

    def __init__(self, config: Config) -> None:
        self._config = config
        self._base_url = config.url
        self._session = requests.Session()
        self._session.verify = config.verify_ssl
        self._use_api_key = bool(config.api_key)

        if self._use_api_key:
            self._session.headers["X-API-Key"] = config.api_key
            # No login round-trip required — mark as authenticated immediately.
            self._authenticated = True
            logger.info("API key auth configured; skipping form-based login")
        else:
            self._authenticated = False

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def authenticate(self) -> None:
        """Authenticate against DockPeek's /login endpoint.

        Only used in password mode.  DockPeek uses Flask-Login with a
        form-based POST.  A successful login returns a 302 redirect to
        '/'.  The session cookie is stored in self._session automatically.

        This method is a no-op when API key auth is active.
        """
        if self._use_api_key:
            # API key is already set on the session headers; nothing to do.
            return

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
        """Make an authenticated request.

        In password mode, re-authenticates automatically when the session
        expires (DockPeek redirects to /login with a 302).

        In API key mode, a 401 means the key is invalid or the server does
        not recognise it — this is raised immediately without retrying.

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

        # Lazy authentication on first request (password mode only)
        if not self._authenticated:
            self.authenticate()

        resp = self._session.request(method, url, allow_redirects=False, **kwargs)

        if self._use_api_key:
            # API key auth: a 401 means the key is wrong — do not retry.
            if resp.status_code == 401:
                raise DockPeekError(
                    f"{method.upper()} {path} returned HTTP 401. "
                    "DOCKPEEK_API_KEY is invalid or not accepted by the server."
                )
        else:
            # Password auth: detect session expiry via redirect to /login.
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
