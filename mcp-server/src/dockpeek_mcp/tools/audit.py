"""Container security audit tool — comprehensive single-call container intelligence."""
from __future__ import annotations

from dockpeek_mcp.app import mcp, client


@mcp.tool()
def dockpeek_audit_container(container_name: str, include_logs: bool = False, log_lines: int = 50) -> str:
    """Run a comprehensive security audit on a single container, returning everything
    a SOC analyst needs in one call.

    Combines container metadata, CVE vulnerability detail, scan history trend,
    image update status, exposed ports, stack membership, and optionally recent
    logs into a single structured report.

    Args:
        container_name: Exact container name as shown in the fleet overview (case-insensitive
                        substring match — e.g. 'sonarr' will match 'sonarr' container).
        include_logs: Set True to append the last N log lines to the audit report.
                      Defaults to False to keep the report concise. Enable when
                      investigating runtime issues or suspicious behaviour.
        log_lines: Number of log tail lines to include when include_logs=True.
                   Default 50. Maximum 200 for audit reports.

    This is the primary investigation tool — use it when you need the full picture
    on a specific container. For fleet-wide situational awareness, use
    dockpeek_get_fleet_overview() or dockpeek_get_security_summary() instead.

    The report sections are:
    1. IDENTITY — name, image, server, stack, status, ports
    2. SECURITY — CVE summary with full vulnerability list
    3. TREND — scan-over-scan progression (improving/degrading/stable)
    4. UPDATES — whether a newer image version is available in the registry
    5. LOGS (optional) — recent container output for runtime investigation
    """
    log_lines = min(log_lines, 200)
    lines: list[str] = []

    # ── 1. Find the container in fleet data ──────────────────────────
    try:
        fleet_data = client.get("/data")
    except Exception as e:
        return f"Error fetching fleet data: {e}"

    containers = fleet_data.get("containers", [])
    query_lower = container_name.lower()

    target = None
    for c in containers:
        if query_lower == c.get("name", "").lower():
            target = c
            break
    # Fallback: substring match
    if target is None:
        for c in containers:
            if query_lower in c.get("name", "").lower():
                target = c
                break

    if target is None:
        return (
            f"Container '{container_name}' not found in the fleet.\n"
            "Use dockpeek_find_container() to search by partial name."
        )

    name = target.get("name", "?")
    image = target.get("image", "?")
    server = target.get("server", "?")
    status = target.get("status", "unknown")
    stack = target.get("stack") or "none"
    update_available = target.get("update_available", False)

    # Ports
    ports = target.get("ports") or []
    port_parts = []
    for p in ports:
        hp = p.get("host_port", "")
        cp = p.get("container_port", "")
        if hp:
            port_parts.append(f"{hp}->{cp}" if cp else hp)
    port_str = ", ".join(port_parts) if port_parts else "none exposed"

    lines.append("=" * 60)
    lines.append(f"  CONTAINER AUDIT: {name}")
    lines.append("=" * 60)
    lines.append("")
    lines.append("1. IDENTITY")
    lines.append(f"   Name:    {name}")
    lines.append(f"   Image:   {image}")
    lines.append(f"   Server:  {server}")
    lines.append(f"   Stack:   {stack}")
    lines.append(f"   Status:  {status.upper()}")
    lines.append(f"   Ports:   {port_str}")

    # ── 2. CVE Security Detail ───────────────────────────────────────
    lines.append("")
    lines.append("2. SECURITY (CVE Vulnerabilities)")

    vuln_summary = target.get("vulnerability_summary") or {}
    scan_status = vuln_summary.get("scan_status")

    if scan_status == "scanned":
        crit = vuln_summary.get("critical", 0)
        high = vuln_summary.get("high", 0)
        med = vuln_summary.get("medium", 0)
        low = vuln_summary.get("low", 0)
        total = crit + high + med + low

        risk = "CLEAN"
        if crit > 0:
            risk = "CRITICAL"
        elif high > 0:
            risk = "HIGH"
        elif med > 0:
            risk = "MEDIUM"
        elif low > 0:
            risk = "LOW"

        lines.append(f"   Risk Level: {risk}")
        lines.append(f"   Total CVEs: {total}  ({crit}C / {high}H / {med}M / {low}L)")

        # Fetch detailed CVE list
        if total > 0:
            try:
                vuln_path = f"/api/vulnerabilities/{image}"
                if server:
                    vuln_path += f"?server_name={server}"
                vuln_data = client.get(vuln_path)
                result = vuln_data.get("result") or {}
                vulns = result.get("vulnerabilities") or []

                if vulns:
                    # Show critical and high CVEs with details
                    important = [v for v in vulns if (v.get("severity") or "").upper() in ("CRITICAL", "HIGH")]
                    if important:
                        lines.append("")
                        lines.append(f"   Critical/High CVEs ({len(important)}):")
                        for v in important[:20]:  # Cap at 20 for readability
                            vid = v.get("vulnerability_id", "?")
                            sev = (v.get("severity") or "?").upper()
                            pkg = v.get("pkg_name", "?")
                            installed = v.get("installed_version", "?")
                            fixed = v.get("fixed_version") or "no fix"
                            lines.append(f"     [{sev}] {vid}")
                            lines.append(f"       Package: {pkg} {installed} -> fix: {fixed}")
                        if len(important) > 20:
                            lines.append(f"       ... and {len(important) - 20} more")

                    # Count fixable
                    fixable = sum(1 for v in vulns if v.get("fixed_version"))
                    lines.append("")
                    lines.append(f"   Fixable CVEs: {fixable}/{total} have patches available")
            except Exception:
                lines.append("   (detailed CVE list unavailable)")
        else:
            lines.append("   No vulnerabilities found — image is clean.")
    elif scan_status in ("failed", "error"):
        lines.append("   Scan Status: FAILED — re-scan with dockpeek_scan_image()")
    else:
        lines.append("   Scan Status: Not yet scanned")
        lines.append("   Action: Run dockpeek_scan_image() to assess vulnerabilities")

    # ── 3. Scan History Trend ────────────────────────────────────────
    lines.append("")
    lines.append("3. TREND (Scan History)")

    try:
        history_path = f"/api/security/history/{image}?limit=5"
        if server:
            history_path += f"&server_name={server}"
        history_data = client.get(history_path)

        if history_data.get("enabled"):
            trend = history_data.get("trend") or {}
            direction = trend.get("direction", "unknown").upper()
            scan_count = trend.get("scan_count", 0)
            dc = trend.get("delta_critical", 0)
            dh = trend.get("delta_high", 0)

            lines.append(f"   Direction:  {direction}")
            lines.append(f"   Scans:      {scan_count} on record")
            if dc or dh:
                lines.append(f"   Delta:      {dc:+d} critical, {dh:+d} high since last scan")

            history = history_data.get("history") or []
            if history:
                lines.append("   History:")
                for entry in history[:5]:
                    ts = (entry.get("scan_timestamp") or "")[:19]
                    t = entry.get("total", 0)
                    c = entry.get("critical", 0)
                    h = entry.get("high", 0)
                    lines.append(f"     {ts}  total={t}  {c}C/{h}H")
        else:
            lines.append("   Scan history not enabled on this instance.")
    except Exception:
        lines.append("   (scan history unavailable)")

    # ── 4. Update Status ─────────────────────────────────────────────
    lines.append("")
    lines.append("4. UPDATES")

    if update_available:
        lines.append("   LOCAL UPDATE AVAILABLE — container is running a stale image")
        lines.append("   Action: Restart container to pick up the newer local image")
    else:
        lines.append("   Local image: up to date")

    # Check registry for newer version
    try:
        version_data = client.get(f"/api/version/check/{image}")
        if version_data.get("newer_version"):
            nv = version_data["newer_version"]
            tag = nv.get("tag", "?")
            lines.append(f"   Registry: newer version '{tag}' available")
            lines.append("   Action: Pull and deploy the newer image for security patches")
        elif version_data.get("checked"):
            lines.append("   Registry: running latest version")
    except Exception:
        lines.append("   Registry: (version check unavailable)")

    # ── 5. Logs (optional) ───────────────────────────────────────────
    if include_logs:
        lines.append("")
        lines.append(f"5. LOGS (last {log_lines} lines)")
        lines.append("-" * 60)

        try:
            log_data = client.post(
                "/get-container-logs",
                json={
                    "container_name": name,
                    "server_name": server,
                    "tail": log_lines,
                },
            )
            if log_data.get("success"):
                log_text = log_data.get("logs") or log_data.get("output") or ""
                if isinstance(log_text, list):
                    log_text = "\n".join(log_text)
                lines.append(str(log_text) if log_text.strip() else "(no log output)")
            else:
                lines.append(f"   (log retrieval failed: {log_data.get('error', 'unknown')})")
        except Exception as e:
            lines.append(f"   (log retrieval failed: {e})")

    lines.append("")
    lines.append("=" * 60)
    lines.append("  END OF AUDIT")
    lines.append("=" * 60)

    return "\n".join(lines)
