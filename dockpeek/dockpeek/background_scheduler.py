"""
Background scheduler for keeping CVE and version data fresh.
Runs periodic refreshes so data is ready when users open the page.

Uses file locking to ensure only ONE Gunicorn worker runs the scheduler.
Other workers skip scheduler startup but still read from shared caches.
"""

import os
import fcntl
import logging
import threading
import time
from typing import Optional

logger = logging.getLogger(__name__)

# Lock file to ensure only one worker runs the scheduler
SCHEDULER_LOCK_FILE = '/tmp/dockpeek_scheduler.lock'


class BackgroundScheduler:
    """
    Scheduler for background data refresh tasks.

    Uses file locking to ensure only ONE Gunicorn worker runs the scheduler.
    Other workers skip scheduler startup but still benefit from shared caches.
    """

    def __init__(self):
        self._refresh_thread: Optional[threading.Thread] = None
        self._version_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._scheduler_lock_fd = None
        self._is_scheduler_owner = False
        self._app = None  # Flask app reference for app context

        # Configuration from environment
        self.enabled = os.environ.get('BACKGROUND_REFRESH_ENABLED', 'true').lower() == 'true'
        self.refresh_interval = int(os.environ.get('BACKGROUND_REFRESH_INTERVAL', '300'))  # 5 min default
        self.version_interval = int(os.environ.get('VERSION_CHECK_INTERVAL', '3600'))  # 1 hour default

    def _try_acquire_scheduler_lock(self) -> bool:
        """
        Try to acquire the scheduler lock file.

        Only one worker across all Gunicorn processes will succeed.
        The lock is held for the lifetime of the worker process.

        Returns:
            True if this worker should run the scheduler, False otherwise.
        """
        try:
            # Keep file open for lifetime of process to maintain lock
            self._scheduler_lock_fd = open(SCHEDULER_LOCK_FILE, 'w')
            # Non-blocking exclusive lock - fails immediately if already held
            fcntl.flock(self._scheduler_lock_fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            # Write our PID to the lock file for debugging
            self._scheduler_lock_fd.write(str(os.getpid()))
            self._scheduler_lock_fd.flush()
            logger.info(f"Acquired scheduler lock (PID {os.getpid()})")
            return True
        except (IOError, OSError):
            # Another worker already has the lock
            if self._scheduler_lock_fd:
                self._scheduler_lock_fd.close()
                self._scheduler_lock_fd = None
            logger.info(f"Scheduler running in another worker, skipping (PID {os.getpid()})")
            return False

    def start(self, app=None):
        """Start background refresh threads (only if we acquire the lock)."""
        if app:
            self._app = app

        if not self.enabled:
            logger.info("Background refresh disabled")
            return

        # Only one worker should run the scheduler
        self._is_scheduler_owner = self._try_acquire_scheduler_lock()
        if not self._is_scheduler_owner:
            # Another worker has the lock, skip scheduler
            # This worker will still read from shared file-based caches
            return

        logger.info(f"Starting background scheduler (refresh: {self.refresh_interval}s, version: {self.version_interval}s)")

        # Start CVE refresh thread
        self._refresh_thread = threading.Thread(target=self._refresh_loop, daemon=True, name="cve-refresh")
        self._refresh_thread.start()

        # Start version check thread
        self._version_thread = threading.Thread(target=self._version_loop, daemon=True, name="version-refresh")
        self._version_thread.start()

    def stop(self):
        """Stop background threads and release lock."""
        self._stop_event.set()

        # Release scheduler lock if we own it
        if self._scheduler_lock_fd:
            try:
                fcntl.flock(self._scheduler_lock_fd.fileno(), fcntl.LOCK_UN)
                self._scheduler_lock_fd.close()
                logger.info("Released scheduler lock")
            except Exception as e:
                logger.debug(f"Error releasing scheduler lock: {e}")
            self._scheduler_lock_fd = None

    def _refresh_loop(self):
        """Background loop for CVE data refresh."""
        # Initial delay to let app fully start
        time.sleep(30)

        while not self._stop_event.is_set():
            try:
                logger.debug("Background CVE refresh starting...")
                self._do_refresh()
                logger.debug("Background CVE refresh complete")
            except Exception as e:
                logger.error(f"Background refresh error: {e}")

            # Wait for next interval
            self._stop_event.wait(self.refresh_interval)

    def _version_loop(self):
        """Background loop for version checking."""
        # Short initial delay to let app start, then check versions
        time.sleep(5)

        while not self._stop_event.is_set():
            try:
                logger.debug("Background version check starting...")
                self._do_version_check()
                logger.debug("Background version check complete")
            except Exception as e:
                logger.error(f"Background version check error: {e}")

            # Wait for next interval
            self._stop_event.wait(self.version_interval)

    def _do_refresh(self):
        """Perform data refresh to trigger CVE scans."""
        try:
            if not self._app:
                logger.error("Refresh skipped: no Flask app reference")
                return

            from .get_data import get_all_data
            # get_all_data() requires Flask app context for current_app.config
            with self._app.app_context():
                get_all_data()
        except Exception as e:
            logger.error(f"Refresh failed: {e}")

    def _do_version_check(self):
        """Perform version checking for all images."""
        try:
            import docker
            from .version_checker import version_checker

            # Get containers directly from Docker (no Flask context needed)
            client = docker.from_env()
            containers = client.containers.list(all=True)

            # Get unique images using Config.Image (the original image reference)
            # instead of image.tags[0] which can return inconsistent results
            images = set()
            for c in containers:
                image_name = c.attrs.get('Config', {}).get('Image', '')
                if not image_name and c.image and c.image.tags:
                    image_name = c.image.tags[0]
                if image_name:
                    images.add(image_name)

            logger.info(f"Background version check for {len(images)} images")

            updates_found = 0
            for image in images:
                try:
                    result = version_checker.check_for_newer_version(image)
                    if result and result.is_newer:
                        updates_found += 1
                        logger.info(f"Update available: {image} -> {result.tag}")
                except Exception as e:
                    logger.debug(f"Version check failed for {image}: {e}")

            logger.info(f"Background version check complete: {updates_found} updates found")

        except Exception as e:
            logger.error(f"Version check failed: {e}")


# Global scheduler instance
scheduler = BackgroundScheduler()
