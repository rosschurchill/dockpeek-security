"""System health, notifications, and infrastructure tools."""
from __future__ import annotations

from dockpeek_mcp.app import mcp, client


@mcp.tool()
def dockpeek_health_check() -> str:
    """Check whether the DockPeek Security application is healthy and reachable.

    Queries the /health endpoint which returns the application status, current
    timestamp, and the running DockPeek version. This endpoint does not require
    authentication and is used for liveness probes.

    Use this as the first call in any session to confirm the DockPeek instance is
    reachable before making further API calls. Also useful for verifying that a
    recently deployed or restarted DockPeek container has come back up correctly.
    A healthy response confirms the Flask application is serving requests.
    """
    try:
        data = client.get("/health")
    except Exception as e:
        return (
            f"DockPeek health check FAILED: {e}\n"
            "The DockPeek instance may be down, unreachable, or the configured URL is wrong.\n"
            "Check the DOCKPEEK_URL environment variable and verify the container is running."
        )

    status = data.get("status", "unknown")
    timestamp = data.get("timestamp", "unknown")
    version = data.get("version", "unknown")

    lines = [
        "DockPeek Health Check",
        f"  Status:    {status.upper()}",
        f"  Version:   {version}",
        f"  Timestamp: {timestamp}",
    ]

    if status.lower() != "healthy":
        lines.append(
            f"\nWARNING: DockPeek reported status '{status}' instead of 'healthy'. "
            "Investigate the application logs."
        )

    return "\n".join(lines)


@mcp.tool()
def dockpeek_get_notification_status() -> str:
    """Get the status of the ntfy push notification integration.

    Returns whether ntfy notifications are enabled, the configured ntfy topic URL,
    and any configuration or connectivity issues. DockPeek can send security alerts
    (new critical CVEs, scan failures) to an ntfy topic for real-time SOC alerting.

    Use this to verify that alert delivery is functioning correctly. If notifications
    are disabled, critical security events (new CRITICAL CVEs, scanner health issues)
    will only be visible by polling DockPeek — not pushed to your alerting channel.
    Configure ntfy with the NTFY_URL environment variable in DockPeek.
    """
    try:
        data = client.get("/api/notifications/status")
    except Exception as e:
        return f"Error fetching notification status: {e}"

    enabled = data.get("enabled", False)
    error = data.get("error")

    if error and not enabled:
        return (
            f"Notifications: UNAVAILABLE\n"
            f"Error: {error}\n"
            "The notifications module is not installed or configured."
        )

    lines = [
        "Notification Status (ntfy)",
        f"  Enabled: {'yes' if enabled else 'no'}",
    ]

    if not enabled:
        lines.append(
            "\nNotifications are disabled. Set the NTFY_URL environment variable "
            "in DockPeek to enable push alerts for security events."
        )
        return "\n".join(lines)

    # If enabled, display all remaining fields from the status response
    for key, value in data.items():
        if key in ("enabled", "error"):
            continue
        formatted_key = key.replace("_", " ").title()
        lines.append(f"  {formatted_key}: {value}")

    return "\n".join(lines)


@mcp.tool()
def dockpeek_get_traefik_routes() -> str:
    """Get the current Traefik HTTP routing table — all public routes and their backend services.

    Retrieves all configured Traefik routers from the Traefik API, including the router name,
    rule (domain/path match), entrypoints (web/websecure), TLS status, service name, and
    provider (Docker labels, file config, etc.).

    This is essential for security audits — it shows exactly which services are publicly
    exposed, on which domains, and whether TLS is enabled. Routes without TLS on a public
    entrypoint represent a cleartext exposure risk. Unexpected routes may indicate
    misconfigured or forgotten services that should be reviewed or removed.

    Requires TRAEFIK_API_URL to be configured in DockPeek. If Traefik integration is
    not enabled, a clear message is returned rather than an error.
    """
    try:
        data = client.get("/api/traefik/routes")
    except Exception as e:
        return f"Error fetching Traefik routes: {e}"

    if not data.get("enabled"):
        return (
            "Traefik integration is not enabled on this DockPeek instance.\n"
            f"Message: {data.get('message', 'Set TRAEFIK_API_URL to enable.')}"
        )

    routes = data.get("routes") or []
    count = data.get("count", len(routes))

    lines = [
        f"Traefik Routing Table: {count} route(s)",
        "",
    ]

    if not routes:
        lines.append("No routes found in the Traefik routing table.")
        return "\n".join(lines)

    # Group by provider for readability
    by_provider: dict[str, list] = {}
    for r in routes:
        provider = r.get("provider", "unknown")
        by_provider.setdefault(provider, []).append(r)

    for provider, provider_routes in sorted(by_provider.items()):
        lines.append(f"Provider: {provider} ({len(provider_routes)} routes)")
        for r in sorted(provider_routes, key=lambda x: x.get("name", "")):
            name = r.get("name") or r.get("router") or "?"
            rule = r.get("rule") or r.get("match") or "?"
            entrypoints = r.get("entrypoints") or r.get("entry_points") or []
            service = r.get("service") or r.get("backend") or "?"
            tls = r.get("tls")
            status = r.get("status", "")

            if isinstance(entrypoints, list):
                ep_str = ", ".join(entrypoints)
            else:
                ep_str = str(entrypoints)

            tls_str = " [TLS]" if tls else " [NO TLS]"
            status_str = f" status={status}" if status and status != "enabled" else ""

            lines.append(f"  {name}")
            lines.append(f"    Rule:         {rule}")
            lines.append(f"    Entrypoints:  {ep_str}{tls_str}")
            lines.append(f"    Service:      {service}{status_str}")

            # Flag potentially concerning routes
            if not tls and "websecure" not in ep_str.lower():
                lines.append("    WARNING: No TLS configured — traffic may be cleartext")

        lines.append("")

    # Security summary
    no_tls_routes = [
        r for r in routes
        if not r.get("tls") and "websecure" not in str(r.get("entrypoints", "")).lower()
    ]
    if no_tls_routes:
        lines.append(
            f"SECURITY NOTE: {len(no_tls_routes)} route(s) appear to have no TLS. "
            "Review these for cleartext exposure."
        )

    return "\n".join(lines).rstrip()
