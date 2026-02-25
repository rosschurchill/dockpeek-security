"""Container and image update checking tools."""
from __future__ import annotations

from dockpeek_mcp.app import mcp, client


@mcp.tool()
def dockpeek_check_outdated_containers() -> str:
    """Check all containers fleet-wide for available newer image versions.

    Queries the Docker registry for each container's image tag and reports which
    containers are running an outdated image version. This uses version tag comparison
    (not digest comparison) — it looks for semantically newer tags in the registry.

    This operation contacts external Docker registries (Docker Hub, GHCR, etc.) and
    may take 30-120 seconds for large fleets. Results are not cached.

    Use this for weekly hygiene checks to identify containers that should be updated
    for security patch coverage. Containers running outdated images may be missing
    published CVE fixes even if your current image scans clean — newer versions may
    have patched vulnerabilities discovered after your image was pulled.

    Note: This checks version tag availability only. For digest-based update detection
    (same tag, new image content), use dockpeek_check_container_updates() instead.
    """
    try:
        data = client.post("/api/version/check-all", json={})
    except Exception as e:
        return f"Error checking for outdated containers: {e}"

    updates_available = data.get("updates_available") or []
    count = data.get("count", len(updates_available))
    checked = data.get("checked", 0)
    errors = data.get("errors", 0)

    lines = [
        "Outdated Container Check (registry version comparison)",
        f"  Containers checked: {checked}",
        f"  Updates available:  {count}",
        f"  Check errors:       {errors}",
    ]

    if not updates_available:
        lines.append("\nAll checked containers appear to be on the latest available version.")
        if errors > 0:
            lines.append(
                f"Note: {errors} container(s) could not be checked "
                "(private registries or network errors)."
            )
        return "\n".join(lines)

    lines.append("")
    lines.append("Containers with newer versions available:")
    for u in updates_available:
        container = u.get("container", "?")
        server = u.get("server", "?")
        image = u.get("image", "?")
        current = u.get("current_version", "?")
        latest = u.get("latest_version", "?")
        lines.append(f"  {container} [{server}]")
        lines.append(f"    Image:   {image}")
        lines.append(f"    Current: {current}")
        lines.append(f"    Latest:  {latest}")
        lines.append("")

    return "\n".join(lines).rstrip()


@mcp.tool()
def dockpeek_check_image_version(image: str) -> str:
    """Check whether a newer version is available for a specific image tag.

    Queries the appropriate Docker registry (Docker Hub, GHCR, GitLab, etc.) to
    determine whether a semantically newer version tag exists for the given image.
    Returns the latest available version tag if one is found.

    Args:
        image: Image name with optional tag, e.g. 'nginx:1.25.3', 'portainer/portainer-ce:latest',
               or 'ghcr.io/linuxserver/radarr:5.2.0'. If no tag is specified, 'latest' is assumed.

    Use this for targeted version checks on specific containers identified as potentially
    outdated. More precise and faster than checking the entire fleet.
    """
    try:
        data = client.get(f"/api/version/check/{image}")
    except Exception as e:
        return f"Error checking version for '{image}': {e}"

    if data.get("error"):
        return (
            f"Version check failed for '{image}'\n"
            f"Error: {data.get('error')}\n"
            "The image may be from a private registry or the registry may be unreachable."
        )

    newer = data.get("newer_available", False)
    current = data.get("current_version", "unknown")
    latest = data.get("latest_version")
    image_name = data.get("image", image)

    lines = [f"Version Check: {image_name}"]
    lines.append(f"  Current version: {current}")

    if newer and latest:
        lines.append(f"  Latest version:  {latest}")
        lines.append(f"  Status:          UPDATE AVAILABLE ({current} -> {latest})")
        lines.append(
            "\nRecommendation: Update the image to reduce exposure to patched CVEs. "
            "Scan the new version with dockpeek_scan_image() after updating."
        )
    else:
        lines.append("  Status:          Up to date (no newer version found)")

    return "\n".join(lines)


@mcp.tool()
def dockpeek_list_image_versions(image: str, limit: int = 20) -> str:
    """List available version tags for a Docker image from its registry.

    Retrieves the most recent available tags for an image, annotated with whether
    each tag is semantically newer than the currently running version and whether it
    appears to be a stable release (vs pre-release/RC).

    Args:
        image: Image name with optional current tag, e.g. 'nginx:1.24.0' or
               'linuxserver/sonarr:latest'. The current tag is used to determine
               which listed versions are newer.
        limit: Maximum number of version tags to return. Default 20. Reduce for
               images with very large tag histories.

    Use this when planning an upgrade path — rather than jumping straight to 'latest',
    you can inspect intermediate versions to understand the version progression.
    Versions marked is_stable=false (RCs, betas, alphas) should generally be avoided
    in production unless there is a specific security fix that has not been backported.
    """
    try:
        data = client.get(f"/api/version/list/{image}?limit={limit}")
    except Exception as e:
        return f"Error listing versions for '{image}': {e}"

    if data.get("error"):
        return (
            f"Failed to list versions for '{image}'\n"
            f"Error: {data.get('error')}\n"
            "The image may be from a private registry or the registry may be unreachable."
        )

    image_name = data.get("image", image)
    versions = data.get("versions") or []
    count = data.get("count", len(versions))

    lines = [
        f"Available Versions: {image_name}",
        f"  Showing {count} version(s) (limit={limit})",
        "",
    ]

    if not versions:
        lines.append("No version information available.")
        return "\n".join(lines)

    newer_versions = [v for v in versions if v.get("is_newer")]

    if newer_versions:
        lines.append(f"Newer versions available ({len(newer_versions)}):")
        for v in newer_versions:
            stable_label = "" if v.get("is_stable") else " [pre-release]"
            lines.append(f"  {v.get('tag', '?')}{stable_label}")
        lines.append("")

    lines.append("All versions (newest first):")
    for v in versions:
        tag = v.get("tag", "?")
        is_newer = v.get("is_newer", False)
        is_stable = v.get("is_stable", True)

        markers = []
        if is_newer:
            markers.append("newer")
        if not is_stable:
            markers.append("pre-release")

        marker_str = f"  [{', '.join(markers)}]" if markers else ""
        lines.append(f"  {tag}{marker_str}")

    stable_newer = [v for v in newer_versions if v.get("is_stable")]
    if not stable_newer and newer_versions:
        lines.append(
            "\nNote: No stable newer versions found. "
            "Pre-release versions are available but not recommended for production."
        )

    return "\n".join(lines)


@mcp.tool()
def dockpeek_update_container(server_name: str, container_name: str, new_image: str = "") -> str:
    """Trigger an update (restart/redeploy) for a specific container.

    WRITE OPERATION — this will stop the running container and recreate it with
    the specified (or current) image. When Portainer integration is configured on
    the DockPeek instance, the update goes through the Portainer stack API so the
    container stays within its compose stack. Without Portainer, the raw Docker API
    is used as a fallback.

    Args:
        server_name: Docker server name hosting the container (e.g. 'TVSP01').
        container_name: Exact container name to update.
        new_image: Optional new image tag to upgrade to, e.g. 'linuxserver/sonarr:4.0.17'.
                   Leave empty to restart with the current (potentially freshly-pulled) image.

    Use this after confirming that a container has an available update (via
    dockpeek_check_container_updates or dockpeek_check_outdated_containers).
    For version upgrades, first check available versions with
    dockpeek_list_image_versions() to choose an appropriate target tag.
    """
    try:
        body: dict = {
            "server_name": server_name,
            "container_name": container_name,
        }
        if new_image:
            body["new_image"] = new_image

        data = client.post("/update-container", json=body)
    except Exception as e:
        return f"Error updating container '{container_name}': {e}"

    if data.get("error"):
        return f"Update failed for '{container_name}': {data['error']}"

    status = data.get("status", "unknown")
    message = data.get("message", "")

    lines = [f"Container Update: {container_name} [{server_name}]"]
    lines.append(f"  Status:  {status.upper()}")
    if message:
        lines.append(f"  Detail:  {message}")
    if new_image:
        lines.append(f"  Image:   {new_image}")

    # Check Portainer path
    if "portainer" in message.lower() or "stack" in message.lower():
        lines.append("  Method:  Portainer stack redeploy (in-stack)")
    else:
        lines.append("  Method:  Docker API direct")

    return "\n".join(lines)


@mcp.tool()
def dockpeek_check_container_updates(server_filter: str = "all") -> str:
    """Check whether containers are running stale local images (same tag, new digest available).

    This checks whether the image digest currently used by running containers matches
    the locally stored image ID for that tag. A mismatch means the tag has been updated
    (e.g. a ':latest' image was re-pulled and now has newer content) but the container
    is still using the old version.

    Args:
        server_filter: Limit the update check to a specific server by name, or pass
                       'all' (default) to check the entire fleet.

    This is distinct from dockpeek_check_outdated_containers() which queries the
    external registry for newer tags. This tool checks LOCAL image state — it detects
    updates that have already been pulled to the host but not yet applied (container
    not restarted). Particularly relevant for ':latest' tagged images which receive
    security patches without version increments.
    """
    try:
        body: dict = {"server_filter": server_filter if server_filter else "all"}
        data = client.post("/check-updates", json=body)
    except Exception as e:
        return f"Error checking container updates: {e}"

    if data.get("error"):
        return f"Update check failed: {data.get('error')}"

    updates = data.get("updates") or {}
    cancelled = data.get("cancelled", False)
    progress = data.get("progress") or {}
    processed = progress.get("processed", 0)
    total = progress.get("total", 0)

    if cancelled:
        lines = [
            "Update check was cancelled before completion.",
            f"  Processed {processed} of {total} containers.",
        ]
        return "\n".join(lines)

    updates_needed = {k: v for k, v in updates.items() if v}
    no_update = {k: v for k, v in updates.items() if not v}

    lines = [
        f"Container Update Check (server: {server_filter})",
        f"  Containers checked:         {len(updates)}",
        f"  Containers needing restart: {len(updates_needed)}",
        f"  Containers up to date:      {len(no_update)}",
    ]

    if updates_needed:
        lines.append("")
        lines.append("Containers running STALE images (restart required to apply update):")
        for key in sorted(updates_needed):
            server, container = key.split(":", 1) if ":" in key else ("?", key)
            lines.append(f"  {container} [{server}]")
    else:
        lines.append("\nAll containers are running their current local image version.")

    return "\n".join(lines)


@mcp.tool()
def dockpeek_get_auto_update_status() -> str:
    """Get the current auto-update scheduler configuration and status.

    Returns the fleet-wide auto-update configuration, including whether scheduled
    updates are enabled, the check interval, dry-run mode state, Portainer integration
    status, how many containers are eligible for auto-update, and when the last
    scheduled run occurred.

    Use this before triggering a manual run (dockpeek_trigger_auto_update) to confirm
    the scheduler is configured correctly and to understand how many containers are
    in scope. Dry-run mode means no actual restarts will occur — updates are simulated
    and logged only, which is safe for verifying eligibility counts in production.
    """
    try:
        data = client.get("/api/auto-update/status")
    except Exception as e:
        return f"Error fetching auto-update status: {e}"

    if data.get("error"):
        return f"Auto-update status unavailable: {data['error']}"

    enabled = data.get("enabled", False)
    interval_hours = data.get("interval", 0)
    dry_run = data.get("dry_run", False)
    last_run = data.get("last_run")
    eligible_count = data.get("eligible_count", 0)
    history_count = data.get("history_count", 0)
    portainer_configured = data.get("portainer_configured", False)

    # Human-readable interval
    if interval_hours == 1:
        interval_str = "1 hour"
    elif interval_hours < 24:
        interval_str = f"{interval_hours} hours"
    elif interval_hours == 24:
        interval_str = "24 hours (daily)"
    elif interval_hours == 168:
        interval_str = "168 hours (weekly)"
    else:
        interval_str = f"{interval_hours} hours"

    lines = [
        "Auto-Update Scheduler Status",
        f"  Enabled:              {'YES' if enabled else 'NO'}",
        f"  Check interval:       {interval_str}",
        f"  Dry-run mode:         {'ON (simulate only, no restarts)' if dry_run else 'OFF (live updates)'}",
        f"  Portainer configured: {'YES' if portainer_configured else 'NO (Docker API fallback)'}",
        f"  Eligible containers:  {eligible_count}",
        f"  History entries:      {history_count}",
        f"  Last run:             {last_run if last_run else 'Never'}",
    ]

    if not enabled:
        lines.append(
            "\nScheduler is disabled. Use dockpeek_trigger_auto_update() to run a "
            "one-off check, or enable the scheduler in DockPeek configuration."
        )
    elif dry_run:
        lines.append(
            "\nDry-run mode is active — no containers will be restarted. "
            "Disable dry-run in configuration to allow live updates."
        )

    return "\n".join(lines)


@mcp.tool()
def dockpeek_trigger_auto_update() -> str:
    """Trigger an immediate auto-update run across all eligible containers.

    WRITE OPERATION (unless dry-run mode is enabled) — this will pull updated
    images and restart containers that have newer image content available. The
    operation respects the scheduler's dry-run setting: if dry-run is ON, no
    containers are actually restarted and results reflect what would have happened.

    When Portainer integration is configured, updates go through the Portainer
    stack API so containers remain within their compose stacks. Without Portainer,
    the raw Docker API is used as a fallback.

    Use dockpeek_get_auto_update_status() first to confirm eligible container count
    and dry-run mode before triggering. Review results and check
    dockpeek_get_auto_update_history() afterwards for a persistent audit trail.
    """
    try:
        data = client.post("/api/auto-update/trigger", json={})
    except Exception as e:
        return f"Error triggering auto-update: {e}"

    if not data.get("success"):
        error = data.get("error", "Unknown error")
        return f"Auto-update run failed: {error}"

    summary = data.get("summary") or {}
    checked = summary.get("checked", 0)
    updated = summary.get("updated", 0)
    skipped = summary.get("skipped", 0)
    failed = summary.get("failed", 0)
    details = summary.get("details") or []

    lines = [
        "Auto-Update Run Complete",
        f"  Containers checked: {checked}",
        f"  Updated:            {updated}",
        f"  Skipped:            {skipped}",
        f"  Failed:             {failed}",
    ]

    updated_details = [d for d in details if d.get("status") in ("updated", "dry-run")]
    failed_details = [d for d in details if d.get("status") == "failed"]

    if updated_details:
        lines.append("")
        lines.append("Updated containers:")
        for d in updated_details:
            container = d.get("container", "?")
            server = d.get("server", "?")
            old_img = d.get("old_image", "?")
            new_img = d.get("new_image", "?")
            method = d.get("method", "?")
            status = d.get("status", "?")
            lines.append(f"  {container} [{server}]  ({status})")
            lines.append(f"    {old_img}  ->  {new_img}")
            lines.append(f"    Method: {method}")

    if failed_details:
        lines.append("")
        lines.append("Failed containers:")
        for d in failed_details:
            container = d.get("container", "?")
            server = d.get("server", "?")
            error = d.get("error") or "no detail"
            lines.append(f"  {container} [{server}]")
            lines.append(f"    Error: {error}")

    if not updated_details and not failed_details and skipped == checked:
        lines.append("\nAll eligible containers are already up to date — nothing to update.")

    return "\n".join(lines)


@mcp.tool()
def dockpeek_get_auto_update_history(limit: int = 20) -> str:
    """Retrieve the auto-update event history as an audit timeline.

    Returns a chronological log of every auto-update action recorded by DockPeek,
    including both successful updates and failures. Each entry shows the container,
    server, old and new image references, the update method used, and any error
    detail for failed attempts.

    Args:
        limit: Maximum number of history entries to return, newest first. Default 20.
               Increase for full audit coverage (up to 50 via the API).

    Use this after a scheduled or manual update run to verify what changed and
    confirm that containers were updated via the expected method (Portainer stack
    vs Docker API direct). Failed entries should be investigated — common causes
    include Portainer connectivity loss, image pull failures, and containers that
    were stopped at update time.
    """
    try:
        data = client.get(f"/api/auto-update/history?limit={limit}")
    except Exception as e:
        return f"Error fetching auto-update history: {e}"

    if data.get("error"):
        return f"Auto-update history unavailable: {data['error']}"

    history = data.get("history") or []

    if not history:
        return (
            "Auto-Update History\n"
            "  No update events recorded yet.\n"
            "  Run dockpeek_trigger_auto_update() or wait for a scheduled run."
        )

    lines = [
        f"Auto-Update History  (showing {len(history)} of last {limit} entries)",
        "",
    ]

    for entry in history:
        timestamp = entry.get("timestamp", "?")
        container = entry.get("container", "?")
        server = entry.get("server", "?")
        old_image = entry.get("old_image", "?")
        new_image = entry.get("new_image", "?")
        status = entry.get("status", "?")
        method = entry.get("method", "?")
        error = entry.get("error")

        status_upper = status.upper()
        lines.append(f"[{timestamp}]  {container} [{server}]  {status_upper}")
        lines.append(f"  {old_image}  ->  {new_image}")
        lines.append(f"  Method: {method}")
        if error:
            lines.append(f"  Error:  {error}")
        lines.append("")

    return "\n".join(lines).rstrip()
