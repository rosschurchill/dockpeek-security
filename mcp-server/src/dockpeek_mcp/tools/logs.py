"""Container log retrieval tools."""
from __future__ import annotations

from dockpeek_mcp.app import mcp, client


@mcp.tool()
def dockpeek_get_container_logs(
    container_name: str,
    server_name: str,
    lines: int = 200,
) -> str:
    """Retrieve recent log output from a running or stopped Docker container.

    Fetches the tail of the container's stdout/stderr log with timestamps. Logs are
    returned as plain text, one line per entry. Useful for investigating runtime errors,
    crash loops, authentication failures, or unexpected container behaviour during
    incident response.

    Args:
        container_name: Exact container name as shown in the fleet overview.
                        Case-sensitive — must match the Docker container name exactly.
        server_name: Name of the Docker server hosting the container. Required — there
                     is no default. Use dockpeek_get_fleet_overview() to find the
                     server name if unknown.
        lines: Number of log lines to retrieve from the tail of the log.
               Default 200. Maximum 1000 (enforced regardless of input).

    For security investigations, look for:
    - Authentication failures (401, 403, 'unauthorized', 'forbidden')
    - Repeated connection attempts from unexpected IPs
    - Stack traces or panic messages suggesting exploitation
    - Unexpected process spawning or file access errors
    - Configuration errors that may indicate tampering
    """
    lines = min(lines, 1000)

    try:
        data = client.post(
            "/get-container-logs",
            json={
                "container_name": container_name,
                "server_name": server_name,
                "tail": lines,
            },
        )
    except Exception as e:
        return f"Error fetching logs for '{container_name}' on '{server_name}': {e}"

    if not data.get("success"):
        err = data.get("error") or data.get("message") or "unknown error"
        return (
            f"Failed to retrieve logs for '{container_name}' on server '{server_name}'.\n"
            f"Error: {err}\n"
            "Verify the container name and server name with dockpeek_get_fleet_overview()."
        )

    log_lines = data.get("logs") or data.get("output") or ""

    # Normalise: the API may return a string or a list
    if isinstance(log_lines, list):
        log_text = "\n".join(log_lines)
    else:
        log_text = str(log_lines)

    line_count = log_text.count("\n") + (1 if log_text.strip() else 0)

    header = (
        f"Logs: {container_name} @ {server_name} "
        f"(last {lines} lines requested, {line_count} returned)\n"
        + "-" * 60
    )

    if not log_text.strip():
        return f"{header}\n(no log output)"

    return f"{header}\n{log_text}"
