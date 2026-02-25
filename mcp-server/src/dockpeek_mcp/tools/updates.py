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
