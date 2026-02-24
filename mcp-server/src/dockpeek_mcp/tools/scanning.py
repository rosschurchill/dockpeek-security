"""Vulnerability scan trigger and cache management tools."""
from __future__ import annotations

from dockpeek_mcp.app import mcp, client


@mcp.tool()
def dockpeek_scan_image(image: str, server_name: str = "", force: bool = False) -> str:
    """Trigger a Trivy vulnerability scan for a specific container image.

    WRITE OPERATION — this initiates an active security scan against the Trivy server.
    The scan may take 10-60 seconds depending on image size and Trivy server load.
    Results are cached after scanning; subsequent calls without force=True will use
    the cached result.

    Args:
        image: Full image name including tag, e.g. 'nginx:1.25.3' or
               'ghcr.io/linuxserver/sonarr:latest'. Use the exact image string from
               the fleet overview.
        server_name: Docker server name used to extract the image digest for more
                     accurate cache keying. If omitted, Trivy scans by image name
                     only (slightly less precise for multi-arch images).
        force: Set to True to bypass the scan cache and force a fresh scan regardless
               of whether cached results exist. Use this when you suspect the cached
               data is stale or after an image has been updated in place.

    After scanning, call dockpeek_get_container_vulnerabilities(image) to retrieve
    the full CVE list. If Trivy is unavailable (503), check the scanner health with
    dockpeek_get_security_status() first.
    """
    try:
        body: dict = {}
        if server_name:
            body["server_name"] = server_name
        if force:
            body["force"] = True

        data = client.post(f"/api/scan/{image}", json=body)
    except Exception as e:
        return f"Error triggering scan for '{image}': {e}"

    status = data.get("status", "unknown")
    result = data.get("result") or {}

    if status == "error" or data.get("error"):
        err = data.get("error", "unknown error")
        return (
            f"Scan failed for image: {image}\n"
            f"Error: {err}\n"
            "Check dockpeek_get_security_status() to verify Trivy is healthy."
        )

    scan_ts = result.get("scan_timestamp", "")[:19] if result.get("scan_timestamp") else "unknown"
    summary = result.get("summary") or {}
    crit = summary.get("critical", 0)
    high = summary.get("high", 0)
    med = summary.get("medium", 0)
    low = summary.get("low", 0)
    total = summary.get("total", 0)

    lines = [
        f"Scan complete: {image}",
        f"  Status:    {status}",
        f"  Scanned:   {scan_ts}",
        f"  Total CVEs: {total}",
        f"    CRITICAL: {crit}",
        f"    HIGH:     {high}",
        f"    MEDIUM:   {med}",
        f"    LOW:      {low}",
    ]

    if crit > 0:
        lines.append(
            f"\n  *** {crit} CRITICAL vulnerabilities found — "
            "run dockpeek_get_container_vulnerabilities() for details ***"
        )
    elif high > 0:
        lines.append(
            f"\n  {high} HIGH vulnerabilities found — "
            "run dockpeek_get_container_vulnerabilities() for details"
        )
    elif total == 0:
        lines.append("\n  Image is clean — no vulnerabilities found.")

    return "\n".join(lines)


@mcp.tool()
def dockpeek_clear_scan_cache() -> str:
    """Clear the Trivy vulnerability scan result cache.

    WRITE OPERATION — removes all cached scan results from DockPeek's in-memory cache.
    After clearing, subsequent calls to get vulnerability data will show 'not scanned'
    until images are scanned again. This does NOT delete scan history records from the
    persistent database — only the in-memory result cache.

    Use this when you know images have been updated (e.g. after a mass image pull and
    restart) and you want to force fresh scans rather than serving stale cached results.
    Also useful if cached data appears corrupted or inconsistent.

    After clearing the cache, trigger new scans with dockpeek_scan_image() for the
    containers you want to re-evaluate.
    """
    try:
        data = client.post("/api/security/cache/clear", json={})
    except Exception as e:
        return f"Error clearing scan cache: {e}"

    status = data.get("status", "unknown")
    cache_stats = data.get("cache_stats") or {}

    lines = [
        "Scan Cache Cleared",
        f"  Status: {status}",
    ]

    if cache_stats:
        lines.append("")
        lines.append("Cache state after clear:")
        for k, v in cache_stats.items():
            lines.append(f"  {k}: {v}")

    lines.append(
        "\nAll in-memory scan results have been removed. "
        "Re-scan images to repopulate vulnerability data."
    )

    return "\n".join(lines)
