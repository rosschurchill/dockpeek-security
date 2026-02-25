"""
Auto-updater for Docker containers.

Scans containers with the `dockpeek.update.auto=true` label and automatically
updates them when a newer version is available in the version checker cache.

Updates are performed via Portainer (stack-aware) when configured, with a
Docker API fallback for standalone containers.

Environment variables:
  AUTO_UPDATE_ENABLED    Global kill switch (default: true)
  AUTO_UPDATE_INTERVAL   Seconds between check cycles (default: 86400 = daily)
  AUTO_UPDATE_DRY_RUN    Log without acting (default: false)
  AUTO_UPDATE_BATCH_SIZE Max containers updated per cycle (default: 3)
"""

import fcntl
import json
import logging
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Persistent history file — same volume as API keys DB
HISTORY_FILE = os.environ.get(
    'AUTO_UPDATE_HISTORY_FILE',
    '/app/data/auto_update_history.json'
)


class AutoUpdater:
    """Opt-in automatic container updater.

    Only containers labelled `dockpeek.update.auto=true` are eligible.
    Containers with `dockpeek.update.action=skip` or `=pin` are always
    skipped, even when auto=true.
    """

    def __init__(self):
        self.enabled = os.environ.get('AUTO_UPDATE_ENABLED', 'true').lower() == 'true'
        self.interval = int(os.environ.get('AUTO_UPDATE_INTERVAL', '86400'))
        self.dry_run = os.environ.get('AUTO_UPDATE_DRY_RUN', 'false').lower() == 'true'
        self.batch_size = int(os.environ.get('AUTO_UPDATE_BATCH_SIZE', '3'))
        self._app = None  # Flask app reference, set by start()
        self._history_file = Path(HISTORY_FILE)

        if self.dry_run:
            logger.info("AutoUpdater: DRY RUN mode — no containers will be modified")

    @contextmanager
    def _ensure_app_context(self):
        """Provide a Flask app context, reusing the current one if available."""
        from flask import has_app_context, current_app
        if has_app_context():
            yield
        elif self._app:
            with self._app.app_context():
                yield
        else:
            raise RuntimeError("AutoUpdater has no Flask app reference — call start(app) first")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check_and_update(self) -> dict:
        """Main entry point: scan all containers and auto-update eligible ones.

        Must be called within a Flask app context (uses get_all_data()).

        Returns a summary dict with counts and per-container details.
        """
        if not self.enabled:
            logger.debug("AutoUpdater: disabled, skipping cycle")
            return {"status": "disabled", "updated": 0, "skipped": 0, "failed": 0, "details": []}

        logger.info("AutoUpdater: starting check cycle")
        results = []
        updated = skipped = failed = 0

        try:
            eligible = self.get_eligible_containers()
        except Exception as exc:
            logger.error("AutoUpdater: failed to get eligible containers: %s", exc)
            return {"status": "error", "error": str(exc), "updated": 0, "skipped": 0, "failed": 0, "details": []}

        if not eligible:
            logger.info("AutoUpdater: no eligible containers found")
            return {"status": "ok", "updated": 0, "skipped": 0, "failed": 0, "details": []}

        logger.info("AutoUpdater: %d eligible container(s), batch_size=%d", len(eligible), self.batch_size)

        for container in eligible[:self.batch_size]:
            name = container.get('name', 'unknown')
            new_version = container.get('latest_version')

            if self.dry_run:
                logger.info(
                    "AutoUpdater [DRY RUN]: would update '%s' to %s",
                    name, new_version
                )
                record = {
                    "container": name,
                    "server": container.get('server'),
                    "image": container.get('image'),
                    "old_version": container.get('image', '').split(':')[-1] if ':' in container.get('image', '') else 'unknown',
                    "new_version": new_version,
                    "status": "dry_run",
                    "method": None,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                results.append(record)
                self._append_history(record)
                skipped += 1
                continue

            try:
                result = self.perform_update(container)
                record = {
                    "container": name,
                    "server": container.get('server'),
                    "image": container.get('image'),
                    "old_version": result.get('old_version'),
                    "new_version": result.get('new_version'),
                    "status": result.get('status'),
                    "method": result.get('method'),
                    "message": result.get('message'),
                    "error": result.get('error'),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                results.append(record)
                self._append_history(record)

                if result.get('status') == 'success':
                    updated += 1
                elif result.get('status') == 'blocked':
                    skipped += 1
                else:
                    failed += 1

            except Exception as exc:
                logger.error("AutoUpdater: unhandled error updating '%s': %s", name, exc)
                record = {
                    "container": name,
                    "server": container.get('server'),
                    "image": container.get('image'),
                    "status": "error",
                    "error": str(exc),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                results.append(record)
                self._append_history(record)
                failed += 1

        logger.info(
            "AutoUpdater: cycle complete — updated=%d skipped=%d failed=%d",
            updated, skipped, failed
        )
        return {
            "status": "ok",
            "updated": updated,
            "skipped": skipped,
            "failed": failed,
            "details": results,
        }

    def get_eligible_containers(self) -> list:
        """Return containers that are auto-update eligible with a newer version available.

        Eligibility requires ALL of:
        - orchestration.auto_update == True
        - update_action not in ('skip', 'pin')
        - container status is 'running' (not unhealthy/stopped/errored)
        - newer_version_available == True and latest_version is set

        Results are sorted by orchestration.update_order (ascending, None last).
        """
        from .get_data import get_all_data

        with self._ensure_app_context():
            data = get_all_data()

        containers = data.get('containers', [])
        eligible = []

        for c in containers:
            orchestration = c.get('orchestration') or {}

            # Must have opt-in label
            if not orchestration.get('auto_update'):
                continue

            # Respect block labels — skip/pin always wins
            update_action = (orchestration.get('update_action') or '').lower()
            if update_action in ('skip', 'pin'):
                logger.debug(
                    "AutoUpdater: skipping '%s' — update_action=%s",
                    c.get('name'), update_action
                )
                continue

            # Skip unhealthy / non-running containers
            status = (c.get('status') or '').lower()
            if status != 'running':
                logger.debug(
                    "AutoUpdater: skipping '%s' — status=%s",
                    c.get('name'), status
                )
                continue

            # Must have a newer version detected
            if not c.get('newer_version_available') or not c.get('latest_version'):
                continue

            eligible.append(c)

        # Sort by update_order (numeric ascending), containers without order sort last
        def _order_key(c):
            raw = (c.get('orchestration') or {}).get('update_order')
            try:
                return (0, int(raw))
            except (TypeError, ValueError):
                return (1, 0)

        eligible.sort(key=_order_key)
        return eligible

    def perform_update(self, container: dict) -> dict:
        """Update a single container to its latest available version.

        Flow:
          1. Pre-pull the new image via Docker API on the container's server.
          2. Attempt Portainer stack update (pullImage=False since we pre-pulled).
          3. Fall back to ContainerUpdater (Docker API direct) if Portainer fails.

        Returns a result dict with keys:
          status       — 'success' | 'failed' | 'blocked' | 'error'
          method       — 'portainer' | 'docker_api' | None
          old_version  — tag portion of old image
          new_version  — new tag
          message      — human-readable summary (on success)
          error        — error string (on failure)
        """
        from .docker_utils import discover_docker_clients
        from .portainer_client import PortainerClient
        from .update_manager import ContainerUpdater

        container_name = container['name']
        server_name = container.get('server', '')
        image = container.get('image', '')
        new_tag = container.get('latest_version', '')

        # Derive new full image reference: replace tag portion
        if ':' in image:
            repo = image.rsplit(':', 1)[0]
        else:
            repo = image
        new_image = f"{repo}:{new_tag}"

        old_version = image.split(':')[-1] if ':' in image else 'unknown'

        logger.info(
            "AutoUpdater: updating '%s' on '%s': %s -> %s",
            container_name, server_name, image, new_image
        )

        # Find the Docker client for this container's server
        servers = discover_docker_clients()
        docker_client = None
        for s in servers:
            if s['name'] == server_name and s.get('client'):
                docker_client = s['client']
                break

        if docker_client is None:
            msg = f"No active Docker client found for server '{server_name}'"
            logger.error("AutoUpdater: %s", msg)
            return {"status": "error", "error": msg, "old_version": old_version, "new_version": new_tag}

        # Step 1: Pre-pull the new image
        try:
            logger.info("AutoUpdater: pre-pulling %s on %s", new_image, server_name)
            pull_repo, pull_tag = (new_image.rsplit(':', 1) if ':' in new_image else (new_image, 'latest'))
            docker_client.images.pull(pull_repo, tag=pull_tag)
            logger.info("AutoUpdater: pre-pull complete for %s", new_image)
        except Exception as exc:
            msg = f"Pre-pull failed for {new_image}: {exc}"
            logger.error("AutoUpdater: %s", msg)
            return {"status": "error", "error": msg, "old_version": old_version, "new_version": new_tag, "method": None}

        # Step 2: Try Portainer first
        if PortainerClient.is_configured():
            try:
                portainer = PortainerClient()
                stack_info = portainer.get_container_stack(container_name)
                if stack_info:
                    stack_id = stack_info['stack_id']
                    service_name = stack_info.get('service_name')

                    if not service_name:
                        service_name = portainer.find_service_for_container(stack_id, container_name)

                    image_updates = {service_name: new_image} if service_name else None
                    result = portainer.redeploy_stack(
                        stack_id,
                        image_updates=image_updates,
                        pull_image=False,
                    )

                    if result.get('success'):
                        stack_name = result.get('stack_name', stack_id)
                        logger.info(
                            "AutoUpdater: '%s' updated via Portainer stack '%s'",
                            container_name, stack_name
                        )
                        return {
                            "status": "success",
                            "method": "portainer",
                            "old_version": old_version,
                            "new_version": new_tag,
                            "message": f"Updated '{container_name}' to {new_image} via Portainer stack '{stack_name}'.",
                        }

                    logger.warning(
                        "AutoUpdater: Portainer redeploy failed for '%s': %s — falling back to Docker API",
                        container_name, result.get('error')
                    )
                else:
                    logger.info(
                        "AutoUpdater: '%s' not in any Portainer stack — falling back to Docker API",
                        container_name
                    )
            except Exception as exc:
                logger.warning(
                    "AutoUpdater: Portainer path failed for '%s': %s — falling back to Docker API",
                    container_name, exc
                )

        # Step 3: Fall back to Docker API
        try:
            with ContainerUpdater(docker_client, server_name) as updater:
                result = updater.update(container_name, force=True, new_image=new_image)

            status = result.get('status', 'error')
            if status == 'success':
                logger.info("AutoUpdater: '%s' updated via Docker API", container_name)
                return {
                    "status": "success",
                    "method": "docker_api",
                    "old_version": old_version,
                    "new_version": new_tag,
                    "message": result.get('message', f"Updated '{container_name}' to {new_image}."),
                }
            elif status == 'blocked':
                return {
                    "status": "blocked",
                    "method": "docker_api",
                    "old_version": old_version,
                    "new_version": new_tag,
                    "message": result.get('message'),
                }
            else:
                return {
                    "status": "failed",
                    "method": "docker_api",
                    "old_version": old_version,
                    "new_version": new_tag,
                    "error": result.get('message', 'Docker API update failed'),
                }

        except Exception as exc:
            msg = str(exc)
            logger.error("AutoUpdater: Docker API update failed for '%s': %s", container_name, msg)
            return {
                "status": "error",
                "method": "docker_api",
                "old_version": old_version,
                "new_version": new_tag,
                "error": msg,
            }

    def get_history(self, limit: int = 50) -> list:
        """Return recent auto-update history records, newest first."""
        records = self._read_history()
        records.sort(key=lambda r: r.get('timestamp', ''), reverse=True)
        return records[:limit]

    def get_status(self) -> dict:
        """Return current auto-update configuration and aggregate stats."""
        history = self._read_history()
        total = len(history)
        successes = sum(1 for r in history if r.get('status') == 'success')
        failures = sum(1 for r in history if r.get('status') in ('failed', 'error'))

        return {
            "enabled": self.enabled,
            "dry_run": self.dry_run,
            "interval_seconds": self.interval,
            "batch_size": self.batch_size,
            "history_total": total,
            "history_successes": successes,
            "history_failures": failures,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _read_history(self) -> list:
        """Read history records from the JSON file (shared-read safe)."""
        if not self._history_file.exists():
            return []
        try:
            with open(self._history_file, 'r') as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_SH)
                try:
                    data = json.load(f)
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            return data if isinstance(data, list) else []
        except (json.JSONDecodeError, IOError) as exc:
            logger.warning("AutoUpdater: failed to read history file: %s", exc)
            return []

    def _append_history(self, record: dict) -> None:
        """Append a single record to the history file (exclusive-write safe)."""
        try:
            self._history_file.parent.mkdir(parents=True, exist_ok=True)
            # Read-modify-write under exclusive lock
            with open(self._history_file, 'a+') as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    f.seek(0)
                    try:
                        records = json.load(f)
                        if not isinstance(records, list):
                            records = []
                    except (json.JSONDecodeError, ValueError):
                        records = []
                    records.append(record)
                    # Keep at most 500 records to bound file growth
                    if len(records) > 500:
                        records = records[-500:]
                    f.seek(0)
                    f.truncate()
                    json.dump(records, f, indent=2)
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except IOError as exc:
            logger.warning("AutoUpdater: failed to write history: %s", exc)


# Module-level singleton
auto_updater = AutoUpdater()
