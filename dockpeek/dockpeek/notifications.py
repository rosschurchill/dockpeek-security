"""
ntfy notification integration for DockPeek Security.

Sends alerts when critical vulnerabilities are discovered.
"""

import os
import logging
import requests
from dataclasses import dataclass
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from threading import Lock

logger = logging.getLogger(__name__)


@dataclass
class NotificationConfig:
    """Configuration for ntfy notifications."""
    enabled: bool
    server_url: str
    topic: str
    priority_critical: str
    priority_high: str
    cooldown_minutes: int
    min_critical_threshold: int
    min_high_threshold: int


class NtfyNotifier:
    """
    ntfy notification client for vulnerability alerts.

    Sends notifications when critical/high vulnerabilities are found,
    with configurable thresholds and cooldown to prevent spam.
    """

    def __init__(self):
        self._config = self._load_config()
        self._last_notifications: Dict[str, datetime] = {}
        self._lock = Lock()

    def _load_config(self) -> NotificationConfig:
        """Load configuration from environment variables."""
        server_url = os.environ.get('NTFY_URL', '').rstrip('/')
        topic = os.environ.get('NTFY_TOPIC', 'security-alerts')

        return NotificationConfig(
            enabled=bool(server_url) and os.environ.get('NTFY_ENABLED', 'true').lower() == 'true',
            server_url=server_url,
            topic=topic,
            priority_critical=os.environ.get('NTFY_PRIORITY_CRITICAL', 'urgent'),
            priority_high=os.environ.get('NTFY_PRIORITY_HIGH', 'high'),
            cooldown_minutes=int(os.environ.get('NTFY_COOLDOWN_MINUTES', '60')),
            min_critical_threshold=int(os.environ.get('NTFY_MIN_CRITICAL', '1')),
            min_high_threshold=int(os.environ.get('NTFY_MIN_HIGH', '10'))
        )

    @property
    def is_enabled(self) -> bool:
        """Check if ntfy notifications are enabled."""
        return self._config.enabled

    def _should_notify(self, cache_key: str) -> bool:
        """Check if we should send a notification (respecting cooldown)."""
        with self._lock:
            last_time = self._last_notifications.get(cache_key)
            if last_time:
                cooldown = timedelta(minutes=self._config.cooldown_minutes)
                if datetime.now() - last_time < cooldown:
                    return False
            return True

    def _mark_notified(self, cache_key: str):
        """Mark that we've sent a notification."""
        with self._lock:
            self._last_notifications[cache_key] = datetime.now()

    def _send_notification(
        self,
        title: str,
        message: str,
        priority: str = 'default',
        tags: Optional[List[str]] = None,
        click_url: Optional[str] = None
    ) -> bool:
        """
        Send a notification to ntfy.

        Args:
            title: Notification title
            message: Notification body
            priority: Priority level (min, low, default, high, urgent)
            tags: List of emoji tags
            click_url: URL to open when notification is clicked

        Returns:
            True if notification was sent successfully
        """
        if not self.is_enabled:
            return False

        url = f"{self._config.server_url}/{self._config.topic}"

        headers = {
            'Title': title,
            'Priority': priority
        }

        if tags:
            headers['Tags'] = ','.join(tags)

        if click_url:
            headers['Click'] = click_url

        try:
            response = requests.post(
                url,
                data=message.encode('utf-8'),
                headers=headers,
                timeout=10
            )
            response.raise_for_status()
            logger.info(f"Notification sent: {title}")
            return True

        except requests.RequestException as e:
            logger.error(f"Failed to send notification: {e}")
            return False

    def notify_scan_complete(
        self,
        image: str,
        container: str,
        server: str,
        critical: int,
        high: int,
        medium: int,
        low: int,
        dockpeek_url: Optional[str] = None
    ) -> bool:
        """
        Send notification when a vulnerability scan completes with significant findings.

        Args:
            image: Docker image name
            container: Container name
            server: Server name
            critical: Number of critical vulnerabilities
            high: Number of high vulnerabilities
            medium: Number of medium vulnerabilities
            low: Number of low vulnerabilities
            dockpeek_url: Optional URL to DockPeek dashboard

        Returns:
            True if notification was sent
        """
        if not self.is_enabled:
            return False

        # Check thresholds
        if critical < self._config.min_critical_threshold and high < self._config.min_high_threshold:
            logger.debug(f"Scan results below threshold for {container}: {critical} critical, {high} high")
            return False

        # Check cooldown
        cache_key = f"scan:{image}"
        if not self._should_notify(cache_key):
            logger.debug(f"Notification cooldown active for {image}")
            return False

        # Determine priority and tags
        if critical >= self._config.min_critical_threshold:
            priority = self._config.priority_critical
            tags = ['rotating_light', 'skull', 'warning']
            severity = 'CRITICAL'
        else:
            priority = self._config.priority_high
            tags = ['warning', 'shield']
            severity = 'HIGH'

        # Build message
        title = f"[{severity}] Vulnerabilities in {container}"
        message = (
            f"Container: {container}\n"
            f"Server: {server}\n"
            f"Image: {image}\n"
            f"\n"
            f"Vulnerabilities Found:\n"
            f"  Critical: {critical}\n"
            f"  High: {high}\n"
            f"  Medium: {medium}\n"
            f"  Low: {low}\n"
            f"  Total: {critical + high + medium + low}"
        )

        success = self._send_notification(
            title=title,
            message=message,
            priority=priority,
            tags=tags,
            click_url=dockpeek_url
        )

        if success:
            self._mark_notified(cache_key)

        return success

    def notify_new_critical_cves(
        self,
        cves: List[Dict[str, Any]],
        dockpeek_url: Optional[str] = None
    ) -> bool:
        """
        Send notification about newly discovered critical CVEs.

        Args:
            cves: List of CVE dictionaries with 'cve_id', 'container', 'image' keys
            dockpeek_url: Optional URL to DockPeek dashboard

        Returns:
            True if notification was sent
        """
        if not self.is_enabled or not cves:
            return False

        # Check cooldown
        cache_key = "new_cves"
        if not self._should_notify(cache_key):
            return False

        count = len(cves)
        title = f"[ALERT] {count} New Critical CVEs Discovered"

        # List first 5 CVEs
        cve_list = '\n'.join([
            f"  - {cve['cve_id']} in {cve.get('container', 'unknown')}"
            for cve in cves[:5]
        ])

        if count > 5:
            cve_list += f"\n  ... and {count - 5} more"

        message = (
            f"New critical vulnerabilities detected:\n\n"
            f"{cve_list}\n\n"
            f"Review in DockPeek Security dashboard."
        )

        success = self._send_notification(
            title=title,
            message=message,
            priority=self._config.priority_critical,
            tags=['rotating_light', 'skull', 'biohazard'],
            click_url=dockpeek_url
        )

        if success:
            self._mark_notified(cache_key)

        return success

    def notify_trivy_unhealthy(self) -> bool:
        """Send notification when Trivy server becomes unhealthy."""
        if not self.is_enabled:
            return False

        cache_key = "trivy_unhealthy"
        if not self._should_notify(cache_key):
            return False

        success = self._send_notification(
            title="[WARNING] Trivy Server Unhealthy",
            message=(
                "The Trivy vulnerability scanner is not responding.\n\n"
                "Vulnerability scanning is temporarily unavailable.\n"
                "Check the Trivy container status."
            ),
            priority='high',
            tags=['warning', 'construction']
        )

        if success:
            self._mark_notified(cache_key)

        return success

    def get_status(self) -> Dict[str, Any]:
        """Get notification system status."""
        with self._lock:
            return {
                'enabled': self.is_enabled,
                'server_url': self._config.server_url if self.is_enabled else None,
                'topic': self._config.topic if self.is_enabled else None,
                'cooldown_minutes': self._config.cooldown_minutes,
                'pending_cooldowns': len(self._last_notifications),
                'thresholds': {
                    'critical': self._config.min_critical_threshold,
                    'high': self._config.min_high_threshold
                }
            }


# Singleton instance
ntfy_notifier = NtfyNotifier()
