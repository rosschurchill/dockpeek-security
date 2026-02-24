"""Security and CVE intelligence tools."""
from __future__ import annotations

from dockpeek_mcp.server import mcp, client


@mcp.tool()
def dockpeek_get_security_summary() -> str:
    """Get the fleet-wide security posture: aggregated CVE counts across all scanned containers.

    Returns the total number of Critical, High, Medium, Low, and Unknown severity
    vulnerabilities found by Trivy across the entire container fleet. Also lists
    per-container breakdowns sorted by severity so the highest-risk containers are
    immediately visible.

    Scanned vs unscanned counts are included — containers not yet scanned represent
    unknown risk and should be prioritised for scanning.

    Use this as the primary security dashboard tool. Critical and High CVEs with
    available fixes should be escalated for immediate patching. The per-container
    list tells you exactly which images to remediate first.
    """
    try:
        data = client.get("/api/security/summary")
    except Exception as e:
        return f"Error fetching security summary: {e}"

    if not data.get("trivy_enabled"):
        return (
            "Trivy scanning is not enabled on this DockPeek instance.\n"
            "Set the TRIVY_SERVER_URL environment variable to enable CVE scanning."
        )

    trivy_healthy = data.get("trivy_healthy", False)
    summary = data.get("summary") or {}
    containers = data.get("containers") or []

    total = summary.get("total", 0)
    crit = summary.get("critical", 0)
    high = summary.get("high", 0)
    med = summary.get("medium", 0)
    low = summary.get("low", 0)
    unknown = summary.get("unknown", 0)
    scanned = summary.get("scanned_containers", 0)
    unscanned = summary.get("unscanned_containers", 0)

    lines = [
        "Fleet Security Summary",
        f"  Trivy scanner: {'healthy' if trivy_healthy else 'UNHEALTHY'}",
        f"  Containers scanned:   {scanned}",
        f"  Containers unscanned: {unscanned} (unknown risk)",
        "",
        "CVE Totals (all scanned containers combined):",
        f"  CRITICAL : {crit}",
        f"  HIGH     : {high}",
        f"  MEDIUM   : {med}",
        f"  LOW      : {low}",
        f"  UNKNOWN  : {unknown}",
        f"  TOTAL    : {total}",
    ]

    if crit > 0:
        lines.append(f"\n  *** {crit} CRITICAL vulnerabilities require immediate attention ***")
    if high > 0:
        lines.append(f"  *** {high} HIGH vulnerabilities should be prioritised for patching ***")

    if containers:
        # Sort by combined critical+high weight
        containers_sorted = sorted(
            containers,
            key=lambda c: (
                c.get("summary", {}).get("critical", 0) * 1000
                + c.get("summary", {}).get("high", 0) * 100
                + c.get("summary", {}).get("medium", 0) * 10
                + c.get("summary", {}).get("low", 0)
            ),
            reverse=True,
        )

        lines.append("")
        lines.append("Per-Container Breakdown (highest risk first):")
        for c in containers_sorted:
            s = c.get("summary", {})
            c_crit = s.get("critical", 0)
            c_high = s.get("high", 0)
            c_med = s.get("medium", 0)
            c_low = s.get("low", 0)
            c_total = s.get("total", 0)
            scanned_at = c.get("scan_timestamp", "")[:19] if c.get("scan_timestamp") else "unknown"

            risk_label = ""
            if c_crit > 0:
                risk_label = " [CRITICAL RISK]"
            elif c_high > 0:
                risk_label = " [HIGH RISK]"
            elif c_med > 0:
                risk_label = " [MEDIUM RISK]"

            lines.append(
                f"  {c.get('container','?')} ({c.get('server','?')}){risk_label}"
            )
            lines.append(f"    Image:   {c.get('image','?')}")
            lines.append(
                f"    CVEs:    {c_crit}C/{c_high}H/{c_med}M/{c_low}L  total={c_total}"
            )
            lines.append(f"    Scanned: {scanned_at}")
    else:
        lines.append("")
        lines.append("No per-container scan results available yet.")

    return "\n".join(lines)


@mcp.tool()
def dockpeek_get_container_vulnerabilities(image: str, server_name: str = "") -> str:
    """Get detailed CVE list for a specific container image from the Trivy scan cache.

    Returns individual vulnerability records including CVE ID, severity, affected package,
    installed version, fixed version (if available), and vulnerability title/description.
    This is the drill-down tool — use it after identifying a high-risk image from the
    security summary.

    Args:
        image: Full image name including tag, e.g. 'nginx:1.25.3' or
               'ghcr.io/linuxserver/radarr:latest'. Must match exactly what DockPeek
               shows in the fleet overview (the image field).
        server_name: Docker server name for image digest lookup. Providing this improves
                     cache hit accuracy. Leave empty to use image name only.

    The 'fixed_version' field is critical for remediation planning — if a fix exists,
    update to that version. If fixed_version is empty, no patch is available yet and
    compensating controls may be needed.
    """
    try:
        path = f"/api/vulnerabilities/{image}"
        if server_name:
            path += f"?server_name={server_name}"
        data = client.get(path)
    except Exception as e:
        return f"Error fetching vulnerabilities for '{image}': {e}"

    if not data.get("cached"):
        return (
            f"No cached scan results for image: {image}\n"
            "Trigger a scan first with: dockpeek_scan_image(image='{image}')"
        )

    result = data.get("result") or {}
    scan_ts = result.get("scan_timestamp", "unknown")[:19] if result.get("scan_timestamp") else "unknown"
    image_name = result.get("image_name", image)

    summary = result.get("summary") or {}
    crit = summary.get("critical", 0)
    high = summary.get("high", 0)
    med = summary.get("medium", 0)
    low = summary.get("low", 0)
    total = summary.get("total", 0)

    lines = [
        f"Vulnerabilities: {image_name}",
        f"  Scan timestamp: {scan_ts}",
        f"  Total CVEs: {total}  ({crit}C / {high}H / {med}M / {low}L)",
        "",
    ]

    vulns = result.get("vulnerabilities") or []
    if not vulns:
        lines.append("No vulnerabilities found — image is clean.")
        return "\n".join(lines)

    # Group by severity for readability
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    by_severity: dict[str, list] = {sev: [] for sev in severity_order}
    for v in vulns:
        sev = (v.get("severity") or "UNKNOWN").upper()
        by_severity.setdefault(sev, []).append(v)

    for sev in severity_order:
        sev_vulns = by_severity.get(sev, [])
        if not sev_vulns:
            continue
        lines.append(f"--- {sev} ({len(sev_vulns)}) ---")
        for v in sev_vulns:
            vuln_id = v.get("vulnerability_id", "?")
            pkg = v.get("pkg_name", "?")
            installed = v.get("installed_version", "?")
            fixed = v.get("fixed_version") or "no fix available"
            title = v.get("title") or v.get("description") or ""
            if title and len(title) > 120:
                title = title[:117] + "..."

            lines.append(f"  {vuln_id}")
            lines.append(f"    Package:  {pkg} {installed}")
            lines.append(f"    Fix:      {fixed}")
            if title:
                lines.append(f"    Summary:  {title}")
        lines.append("")

    return "\n".join(lines).rstrip()


@mcp.tool()
def dockpeek_get_security_trends() -> str:
    """Get security trend analysis showing whether the fleet's CVE posture is improving or degrading.

    Compares current scan results against historical scan data to classify each container's
    trend as 'improving', 'degrading', 'stable', or 'unknown'. Also reports the count of
    new vulnerabilities discovered in the last 24 hours.

    Degrading containers have gained new CVEs since the last scan and should be investigated
    immediately — this could indicate a recently disclosed vulnerability in a widely-used
    package. Improving containers have had vulnerabilities patched (either via image update
    or base OS patch).

    Use this tool for daily security briefings and to track remediation progress over time.
    """
    try:
        data = client.get("/api/security/trends")
    except Exception as e:
        return f"Error fetching security trends: {e}"

    if not data.get("trivy_enabled"):
        return (
            "Trivy scanning is not enabled on this DockPeek instance.\n"
            "Set the TRIVY_SERVER_URL environment variable to enable CVE scanning."
        )

    overall = data.get("overall_trend", "unknown")
    trends = data.get("trends") or {}
    container_trends = data.get("container_trends") or []

    improving = trends.get("improving", 0)
    degrading = trends.get("degrading", 0)
    stable = trends.get("stable", 0)
    unknown = trends.get("unknown", 0)
    new_vulns_24h = trends.get("total_new_vulns", 0)

    overall_label = overall.upper()
    if overall == "degrading":
        overall_label = "DEGRADING -- investigate new CVEs immediately"
    elif overall == "improving":
        overall_label = "IMPROVING -- remediation is working"
    elif overall == "stable":
        overall_label = "STABLE -- no significant change"

    lines = [
        "Security Trend Analysis",
        f"  Overall fleet trend: {overall_label}",
        f"  New CVEs (last 24h): {new_vulns_24h}",
        "",
        "Trend breakdown:",
        f"  Improving:  {improving} containers",
        f"  Degrading:  {degrading} containers",
        f"  Stable:     {stable} containers",
        f"  Unknown:    {unknown} containers (insufficient scan history)",
    ]

    if container_trends:
        # Show degrading first, then improving
        degrading_items = [ct for ct in container_trends if ct.get("trend") == "degrading"]
        improving_items = [ct for ct in container_trends if ct.get("trend") == "improving"]
        stable_items = [ct for ct in container_trends if ct.get("trend") == "stable"]

        if degrading_items:
            lines.append("")
            lines.append("DEGRADING containers (gained new CVEs):")
            for ct in degrading_items:
                dc = ct.get("delta_critical", 0)
                dh = ct.get("delta_high", 0)
                delta_str = ""
                if dc or dh:
                    delta_str = f" (+{dc}C/+{dh}H)"
                lines.append(
                    f"  {ct.get('container','?')} [{ct.get('server','?')}]"
                    f"  {ct.get('image','?')}{delta_str}"
                )

        if improving_items:
            lines.append("")
            lines.append("IMPROVING containers (CVEs reduced):")
            for ct in improving_items:
                dc = ct.get("delta_critical", 0)
                dh = ct.get("delta_high", 0)
                delta_str = f" ({dc:+d}C/{dh:+d}H)" if (dc or dh) else ""
                lines.append(
                    f"  {ct.get('container','?')} [{ct.get('server','?')}]"
                    f"  {ct.get('image','?')}{delta_str}"
                )

        if stable_items:
            lines.append("")
            lines.append(f"Stable: {len(stable_items)} container(s) (no change)")

    return "\n".join(lines)


@mcp.tool()
def dockpeek_get_new_vulnerabilities(hours: int = 24, severity: str = "") -> str:
    """Get vulnerabilities first discovered within a specified lookback window.

    Queries the scan history database for CVEs that appeared for the first time within
    the last N hours. Useful for morning security briefings ('what's new since yesterday?')
    and incident response ('have any new critical CVEs appeared in the last hour?').

    Args:
        hours: How many hours back to look for newly discovered vulnerabilities.
               Default 24 hours. Use 1-4 for near-real-time monitoring.
        severity: Filter by severity level: 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', or
                  'UNKNOWN'. Leave empty to return all severities.

    Requires scan history to be enabled (SCAN_HISTORY_DB_PATH environment variable).
    New critical/high CVEs should trigger immediate investigation — check whether a
    fix is available and plan patching accordingly.
    """
    try:
        path = f"/api/security/new-vulnerabilities?hours={hours}"
        if severity:
            path += f"&severity={severity.upper()}"
        data = client.get(path)
    except Exception as e:
        return f"Error fetching new vulnerabilities: {e}"

    if not data.get("enabled"):
        return (
            "Scan history is not enabled on this DockPeek instance.\n"
            f"Message: {data.get('message', 'Set SCAN_HISTORY_DB_PATH to enable.')}"
        )

    vulns = data.get("vulnerabilities") or []
    count = data.get("count", len(vulns))
    sev_label = f" [{severity.upper()}]" if severity else ""

    if not vulns:
        return (
            f"No new vulnerabilities{sev_label} discovered in the last {hours} hour(s)."
        )

    lines = [
        f"New Vulnerabilities{sev_label} — last {hours} hour(s): {count} found",
        "",
    ]

    for v in vulns:
        vuln_id = v.get("vulnerability_id") or v.get("cve_id") or "?"
        sev = (v.get("severity") or "UNKNOWN").upper()
        pkg = v.get("pkg_name") or v.get("package") or "?"
        image = v.get("image_name") or v.get("image") or "?"
        fixed = v.get("fixed_version") or "no fix"
        discovered = (v.get("discovered_at") or v.get("first_seen") or "")[:19]

        lines.append(f"  [{sev}] {vuln_id}")
        lines.append(f"    Image:     {image}")
        lines.append(f"    Package:   {pkg}")
        lines.append(f"    Fix:       {fixed}")
        if discovered:
            lines.append(f"    Seen at:   {discovered}")
        lines.append("")

    return "\n".join(lines).rstrip()


@mcp.tool()
def dockpeek_get_scan_history(image: str, server_name: str = "", limit: int = 5) -> str:
    """Get historical vulnerability scan records for a specific image.

    Shows the scan-over-scan progression of CVE counts for an image, allowing you to
    see whether vulnerabilities are being resolved or accumulating. Also includes a
    trend calculation (improving/degrading/stable) based on the delta between the two
    most recent scans.

    Args:
        image: Full image name including tag, e.g. 'linuxserver/sonarr:latest'.
        server_name: Docker server name used to resolve the image digest for history
                     lookup. Required for accurate history — without it the server
                     cannot determine the correct image digest.
        limit: Maximum number of historical scan records to return (default 5, max ~20).

    Use this when investigating a specific container's CVE trajectory — for example,
    to confirm that an image update actually reduced the vulnerability count, or to
    demonstrate compliance improvement to a security auditor.
    """
    try:
        path = f"/api/security/history/{image}?limit={limit}"
        if server_name:
            path += f"&server_name={server_name}"
        data = client.get(path)
    except Exception as e:
        return f"Error fetching scan history for '{image}': {e}"

    if not data.get("enabled"):
        return (
            "Scan history is not enabled on this DockPeek instance.\n"
            f"Message: {data.get('message', 'Set SCAN_HISTORY_DB_PATH to enable.')}"
        )

    history = data.get("history") or []
    trend_data = data.get("trend") or {}

    lines = [
        f"Scan History: {data.get('image', image)}",
        f"  Digest: {data.get('image_digest', 'unknown')}",
        "",
    ]

    trend_dir = trend_data.get("direction", "unknown")
    prev_total = trend_data.get("previous_total")
    curr_total = trend_data.get("current_total")
    dc = trend_data.get("delta_critical", 0)
    dh = trend_data.get("delta_high", 0)
    scan_count = trend_data.get("scan_count", 0)

    lines.append(f"Trend: {trend_dir.upper()} ({scan_count} scan(s) recorded)")
    if prev_total is not None and curr_total is not None:
        lines.append(
            f"  Previous total: {prev_total}  Current total: {curr_total}"
        )
    if dc or dh:
        lines.append(f"  Critical delta: {dc:+d}  High delta: {dh:+d}")

    if not history:
        lines.append("\nNo scan history records found for this image.")
        return "\n".join(lines)

    lines.append(f"\nHistory ({len(history)} record(s), newest first):")
    for entry in history:
        ts = (entry.get("scan_timestamp") or entry.get("timestamp") or "")[:19]
        crit = entry.get("critical", 0)
        high = entry.get("high", 0)
        med = entry.get("medium", 0)
        low = entry.get("low", 0)
        total = entry.get("total", crit + high + med + low)
        lines.append(
            f"  {ts}  total={total}  {crit}C/{high}H/{med}M/{low}L"
        )

    return "\n".join(lines)


@mcp.tool()
def dockpeek_get_security_status() -> str:
    """Get the health status of the Trivy vulnerability scanner integration.

    Returns whether Trivy is enabled and currently reachable, the configured server URL,
    and cache statistics (number of cached results, cache age, memory usage).

    Use this to diagnose why scans are failing or not updating — for example, if the
    Trivy server is unreachable, all vulnerability data will be stale. A healthy scanner
    is a prerequisite for meaningful CVE intelligence.
    """
    try:
        data = client.get("/api/security/status")
    except Exception as e:
        return f"Error fetching security status: {e}"

    enabled = data.get("trivy_enabled", False)
    healthy = data.get("trivy_healthy", False)
    url = data.get("trivy_server_url") or "not configured"
    cache = data.get("cache_stats") or {}

    if not enabled:
        return (
            "Trivy scanner: DISABLED\n"
            "Set the TRIVY_SERVER_URL environment variable to enable CVE scanning.\n"
            f"Configured URL: {url}"
        )

    lines = [
        "Trivy Scanner Status",
        f"  Enabled:   yes",
        f"  Healthy:   {'YES' if healthy else 'NO -- scanner unreachable!'}",
        f"  URL:       {url}",
    ]

    if cache:
        lines.append("")
        lines.append("Cache Statistics:")
        for k, v in cache.items():
            lines.append(f"  {k}: {v}")

    if not healthy:
        lines.append(
            "\nWARNING: Trivy server is unreachable. "
            "CVE data may be stale. Check the Trivy container and network connectivity."
        )

    return "\n".join(lines)


@mcp.tool()
def dockpeek_get_security_stats() -> str:
    """Get database statistics for the scan history store.

    Returns counts of stored scan records, database size, oldest and newest scan
    timestamps, and any other metadata the scan history database exposes.

    Use this for capacity planning (is the database growing too large?) and to verify
    that the scan history system is functioning correctly (records are being written
    after each scan).
    """
    try:
        data = client.get("/api/security/stats")
    except Exception as e:
        return f"Error fetching security stats: {e}"

    if not data:
        return "No security statistics available (scan history may not be enabled)."

    lines = ["Scan History Database Statistics"]
    lines.append("")

    if isinstance(data, dict):
        for key, value in data.items():
            formatted_key = key.replace("_", " ").title()
            lines.append(f"  {formatted_key}: {value}")
    else:
        lines.append(str(data))

    return "\n".join(lines)
