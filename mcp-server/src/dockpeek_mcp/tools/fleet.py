"""Fleet overview tools — container listing and filtering."""
from __future__ import annotations

from dockpeek_mcp.server import mcp, client


@mcp.tool()
def dockpeek_get_fleet_overview() -> str:
    """Get a complete operational overview of all Docker containers across all servers.

    Returns container names, images, running status, compose stack membership, exposed
    ports, CVE vulnerability summary (critical/high/medium/low counts), and whether an
    image update is available.

    Use this as the first tool in any SOC investigation — it gives you immediate
    situational awareness of the entire container fleet, highlights which containers
    have unpatched vulnerabilities, and flags containers running outdated images.

    The CVE summary uses data from cached Trivy scans. 'Scanning...' means a scan has
    not yet completed for that image. Containers marked 'UPDATE AVAILABLE' are running
    a stale local image and should be checked for security patches.
    """
    try:
        data = client.get("/data")
    except Exception as e:
        return f"Error fetching fleet data: {e}"

    containers = data.get("containers", [])
    servers = data.get("servers", [])

    server_names = [s.get("name", "?") for s in servers] if servers else []
    lines = [
        f"Fleet Overview: {len(containers)} containers"
        + (f" across {len(server_names)} server(s): {', '.join(server_names)}" if server_names else "")
    ]

    running_count = sum(1 for c in containers if c.get("status", "").lower() == "running")
    lines.append(f"Running: {running_count}/{len(containers)}")
    lines.append("")

    for c in containers:
        status = c.get("status", "unknown").upper()
        name = c.get("name", "?")
        image = c.get("image", "?")
        stack = c.get("stack") or "none"
        server = c.get("server", "")

        # CVE summary
        vuln = c.get("vulnerability_summary") or {}
        scan_status = vuln.get("scan_status")
        if scan_status == "scanned":
            crit = vuln.get("critical", 0)
            high = vuln.get("high", 0)
            med = vuln.get("medium", 0)
            low = vuln.get("low", 0)
            total = crit + high + med + low
            if total == 0:
                cve_str = " | CVEs: Clean"
            else:
                cve_str = f" | CVEs: {crit}C/{high}H/{med}M/{low}L"
        elif scan_status in ("not_scanned", "skipped", None):
            cve_str = " | CVEs: Not scanned"
        elif scan_status in ("failed", "error"):
            cve_str = " | CVEs: Scan error"
        else:
            cve_str = " | CVEs: Scanning..."

        update_str = " | UPDATE AVAILABLE" if c.get("update_available") else ""

        # Ports
        ports = c.get("ports") or []
        port_parts = []
        for p in ports:
            hp = p.get("host_port", "")
            cp = p.get("container_port", "")
            if hp:
                port_parts.append(f"{hp}->{cp}" if cp else hp)
        port_str = f" | ports: {', '.join(port_parts)}" if port_parts else ""

        server_str = f" [{server}]" if server else ""

        lines.append(
            f"  [{status}]{server_str} {name} ({image})"
            f" stack={stack}{port_str}{cve_str}{update_str}"
        )

    return "\n".join(lines)


@mcp.tool()
def dockpeek_get_container_status() -> str:
    """Get the current running/stopped state of every container in the fleet.

    Queries the /status endpoint which pulls live Docker state (not cached data),
    including exit codes for stopped containers and start times for running ones.
    For Docker Swarm services it shows replica task counts (running/total).

    Use this when you need a lightweight, up-to-date status check without full
    fleet metadata — for example, to verify a container restarted after remediation,
    or to detect containers that have recently crashed (exited with non-zero code).

    Exit code 137 = OOM kill. Exit code 1 = application error. Exit code 0 = clean stop.
    """
    try:
        data = client.get("/status")
    except Exception as e:
        return f"Error fetching container status: {e}"

    statuses = data.get("statuses", [])
    if not statuses:
        return "No container status data available."

    lines = [f"Container Status: {len(statuses)} entries"]
    lines.append("")

    # Group by server
    by_server: dict[str, list[dict]] = {}
    for s in statuses:
        server = s.get("server", "unknown")
        by_server.setdefault(server, []).append(s)

    for server, items in sorted(by_server.items()):
        lines.append(f"Server: {server}")
        for item in sorted(items, key=lambda x: x.get("name", "")):
            name = item.get("name", "?")
            status = item.get("status", "unknown")
            exit_code = item.get("exit_code")
            started_at = item.get("started_at", "")

            exit_str = ""
            if exit_code is not None and exit_code != 0:
                exit_str = f" (exit={exit_code})"
            elif exit_code == 0 and status.lower() != "running":
                exit_str = " (exit=0)"

            started_str = ""
            if started_at and started_at != "0001-01-01T00:00:00Z":
                # Truncate to readable date/time
                started_str = f" started={started_at[:19]}"

            lines.append(f"  {name}: {status}{exit_str}{started_str}")
        lines.append("")

    return "\n".join(lines).rstrip()


@mcp.tool()
def dockpeek_find_container(query: str, server: str = "", status: str = "") -> str:
    """Search and filter containers by name, image, or stack across the fleet.

    Performs case-insensitive substring matching against container name, image name,
    and stack name. Optionally narrow results by server name and/or container status.

    Args:
        query: Search string matched against name, image, and stack (case-insensitive).
               Pass an empty string to list all containers (then use server/status filters).
        server: Filter to a specific server name. Leave empty for all servers.
        status: Filter by container status, e.g. 'running', 'exited'. Leave empty for all.

    Use this to quickly locate a specific container when you know part of its name or
    image, or to find all containers from a particular stack. For example, searching
    'postgres' will find all PostgreSQL containers regardless of which stack they belong to.
    """
    try:
        data = client.get("/data")
    except Exception as e:
        return f"Error fetching fleet data: {e}"

    containers = data.get("containers", [])
    query_lower = query.lower()
    server_lower = server.lower()
    status_lower = status.lower()

    matches = []
    for c in containers:
        # Server filter
        if server_lower and server_lower not in c.get("server", "").lower():
            continue
        # Status filter
        if status_lower and status_lower not in c.get("status", "").lower():
            continue
        # Query filter (skip if empty to match all)
        if query_lower:
            haystack = " ".join([
                c.get("name", ""),
                c.get("image", ""),
                c.get("stack", "") or "",
            ]).lower()
            if query_lower not in haystack:
                continue
        matches.append(c)

    if not matches:
        filters = []
        if query:
            filters.append(f"query='{query}'")
        if server:
            filters.append(f"server='{server}'")
        if status:
            filters.append(f"status='{status}'")
        return f"No containers matched filters: {', '.join(filters) or '(none)'}"

    lines = [f"Found {len(matches)} container(s):"]
    lines.append("")
    for c in matches:
        name = c.get("name", "?")
        image = c.get("image", "?")
        c_status = c.get("status", "unknown")
        stack = c.get("stack") or "none"
        c_server = c.get("server", "")

        vuln = c.get("vulnerability_summary") or {}
        scan_status = vuln.get("scan_status")
        if scan_status == "scanned":
            crit = vuln.get("critical", 0)
            high = vuln.get("high", 0)
            med = vuln.get("medium", 0)
            low = vuln.get("low", 0)
            total = crit + high + med + low
            cve_str = "Clean" if total == 0 else f"{crit}C/{high}H/{med}M/{low}L"
        elif scan_status in ("failed", "error"):
            cve_str = "Scan error"
        else:
            cve_str = "Not scanned"

        update_flag = " [UPDATE AVAILABLE]" if c.get("update_available") else ""

        lines.append(f"  Name:    {name}")
        lines.append(f"  Server:  {c_server}")
        lines.append(f"  Image:   {image}")
        lines.append(f"  Status:  {c_status}")
        lines.append(f"  Stack:   {stack}")
        lines.append(f"  CVEs:    {cve_str}{update_flag}")

        ports = c.get("ports") or []
        if ports:
            port_parts = []
            for p in ports:
                hp = p.get("host_port", "")
                cp = p.get("container_port", "")
                port_parts.append(f"{hp}->{cp}" if cp else hp)
            lines.append(f"  Ports:   {', '.join(port_parts)}")

        lines.append("")

    return "\n".join(lines).rstrip()


@mcp.tool()
def dockpeek_export_fleet_data(server: str = "all") -> str:
    """Export complete fleet inventory as structured JSON for offline analysis or SIEM ingestion.

    Retrieves the full container export from DockPeek including container names, servers,
    stacks, images, status, exit codes, ports, and Traefik routes. This is the canonical
    data export format used for audit trails and integration with external tooling.

    Args:
        server: Server name to export containers from, or 'all' for the full fleet.
                Passing a specific server name filters the export to that host only.

    Use this to capture a point-in-time snapshot of the fleet for incident documentation,
    compliance reporting, or feeding into a SIEM. The JSON output includes an export
    timestamp and DockPeek version for audit traceability.
    """
    try:
        path = f"/export/json?server={server}"
        # The export endpoint returns JSON with Content-Disposition for download;
        # the client.get() call still parses the JSON body correctly.
        data = client.get(path)
    except Exception as e:
        return f"Error exporting fleet data: {e}"

    import json
    export_info = data.get("export_info", {})
    containers = data.get("containers", [])

    lines = [
        "Fleet Export",
        f"  Timestamp:  {export_info.get('timestamp', 'unknown')}",
        f"  Version:    {export_info.get('dockpeek_version', 'unknown')}",
        f"  Filter:     {export_info.get('server_filter', server)}",
        f"  Containers: {export_info.get('total_containers', len(containers))}",
        "",
        "--- JSON Export ---",
        json.dumps(data, indent=2),
    ]
    return "\n".join(lines)
