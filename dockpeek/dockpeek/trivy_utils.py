"""
Trivy vulnerability scanning integration for Dockpeek Security.

Provides:
- TrivyClient: HTTP client for Trivy server communication
- TrivyCache: File-based cache for scan results (multi-worker safe)
- Data classes: Vulnerability, VulnerabilitySummary, ScanResult
"""

import os
import re
import logging
import json
import subprocess
import requests
import docker
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from threading import Lock, Thread
from queue import Queue, Empty
from typing import Optional, List, Dict, Any, Set

from .shared_cache import FileBasedCache

logger = logging.getLogger(__name__)

# File-based cache location for multi-worker compatibility
TRIVY_CACHE_FILE = os.environ.get(
    'DOCKPEEK_TRIVY_CACHE',
    '/tmp/dockpeek_trivy_cache.json'
)

# Global Docker client for trivy exec
_docker_client = None


def get_docker_client():
    """Get or create a Docker client for executing trivy commands."""
    global _docker_client
    if _docker_client is None:
        try:
            _docker_client = docker.from_env()
        except Exception as e:
            logger.warning(f"Failed to create Docker client: {e}")
            return None
    return _docker_client

# Pattern for validating Docker image names
# Matches: registry/namespace/image:tag or image:tag
# Allows: alphanumeric, dots, hyphens, underscores, slashes, colons
IMAGE_NAME_PATTERN = re.compile(
    r'^[a-zA-Z0-9][a-zA-Z0-9._/-]*(?::[a-zA-Z0-9._-]+)?$'
)

# Characters that could be used for shell injection
DANGEROUS_CHARS = frozenset(['$', '`', '|', ';', '&', '>', '<', '\\', '\n', '\r', '\0'])


def validate_image_name(image_name: str) -> bool:
    """
    Validate Docker image name to prevent command injection.

    Args:
        image_name: Docker image name to validate

    Returns:
        True if image name is safe, False otherwise
    """
    if not image_name:
        return False

    # Length check (reasonable max for Docker image names)
    if len(image_name) > 256:
        logger.warning(f"Image name too long: {len(image_name)} chars")
        return False

    # Pattern check
    if not IMAGE_NAME_PATTERN.match(image_name):
        logger.warning(f"Image name failed pattern validation: {image_name}")
        return False

    # Dangerous character check
    if any(c in image_name for c in DANGEROUS_CHARS):
        logger.warning(f"Image name contains dangerous characters: {image_name}")
        return False

    return True


@dataclass
class Vulnerability:
    """Individual vulnerability data from Trivy scan."""
    cve_id: str
    severity: str
    title: str
    description: str
    pkg_name: str
    installed_version: str
    fixed_version: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'vulnerability_id': self.cve_id,
            'cve_id': self.cve_id,
            'severity': self.severity,
            'title': self.title,
            'description': self.description,
            'pkg_name': self.pkg_name,
            'installed_version': self.installed_version,
            'fixed_version': self.fixed_version,
            'cvss_score': self.cvss_score,
            'cvss_vector': self.cvss_vector
        }


@dataclass
class VulnerabilitySummary:
    """Counts of vulnerabilities by severity."""
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    unknown: int = 0

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.unknown

    def to_dict(self) -> Dict[str, int]:
        return {
            'critical': self.critical,
            'high': self.high,
            'medium': self.medium,
            'low': self.low,
            'unknown': self.unknown,
            'total': self.total
        }


@dataclass
class ScanResult:
    """Complete scan result for an image."""
    image: str
    image_digest: str
    scan_timestamp: datetime
    scan_duration: float
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    summary: VulnerabilitySummary = field(default_factory=VulnerabilitySummary)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'image': self.image,
            'image_digest': self.image_digest,
            'scan_timestamp': self.scan_timestamp.isoformat(),
            'scan_duration': self.scan_duration,
            'summary': self.summary.to_dict(),
            'vulnerability_count': len(self.vulnerabilities),
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
            'error': self.error
        }


def _serialize_scan_result(result: 'ScanResult') -> Dict[str, Any]:
    """Convert ScanResult to JSON-serializable dict."""
    if result is None:
        return None
    return {
        'image': result.image,
        'image_digest': result.image_digest,
        'scan_timestamp': result.scan_timestamp.isoformat(),
        'scan_duration': result.scan_duration,
        'vulnerabilities': [v.to_dict() for v in result.vulnerabilities],
        'summary': result.summary.to_dict(),
        'error': result.error
    }


def _deserialize_scan_result(data: Dict[str, Any]) -> 'ScanResult':
    """Convert dict back to ScanResult."""
    if data is None:
        return None

    vulns = [
        Vulnerability(
            cve_id=v.get('cve_id') or v.get('vulnerability_id', 'UNKNOWN'),
            severity=v.get('severity', 'UNKNOWN'),
            title=v.get('title', ''),
            description=v.get('description', ''),
            pkg_name=v.get('pkg_name', ''),
            installed_version=v.get('installed_version', ''),
            fixed_version=v.get('fixed_version'),
            cvss_score=v.get('cvss_score'),
            cvss_vector=v.get('cvss_vector')
        )
        for v in data.get('vulnerabilities', [])
    ]

    summary_data = data.get('summary', {})
    summary = VulnerabilitySummary(
        critical=summary_data.get('critical', 0),
        high=summary_data.get('high', 0),
        medium=summary_data.get('medium', 0),
        low=summary_data.get('low', 0),
        unknown=summary_data.get('unknown', 0)
    )

    return ScanResult(
        image=data['image'],
        image_digest=data['image_digest'],
        scan_timestamp=datetime.fromisoformat(data['scan_timestamp']),
        scan_duration=data['scan_duration'],
        vulnerabilities=vulns,
        summary=summary,
        error=data.get('error')
    )


class TrivyCache:
    """
    File-based cache for Trivy scan results, keyed by image digest.

    Uses shared file cache for multi-worker compatibility.
    All Gunicorn workers can read/write the same cache file.
    """

    def __init__(self, duration_seconds: int = 3600):
        self._duration = duration_seconds
        self._cache = FileBasedCache(
            cache_file=TRIVY_CACHE_FILE,
            duration_seconds=duration_seconds,
            serializer=_serialize_scan_result,
            deserializer=_deserialize_scan_result
        )

    def get(self, digest: str) -> tuple:
        """Get cached result by digest. Returns (result, is_valid) tuple."""
        return self._cache.get(digest)

    def set(self, digest: str, result: ScanResult) -> None:
        """Cache a scan result by digest."""
        self._cache.set(digest, result)

    def clear(self) -> None:
        """Clear all cached results."""
        self._cache.clear()

    def prune_expired(self) -> int:
        """Remove expired cache entries. Returns count of pruned entries."""
        return self._cache.prune_expired()

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        return self._cache.get_stats()


class TrivyClient:
    """HTTP client for Trivy server communication with background scanning."""

    def __init__(self):
        self._server_url = os.environ.get('TRIVY_SERVER_URL', '').rstrip('/')
        self._timeout = int(os.environ.get('TRIVY_SCAN_TIMEOUT', '120'))
        self._cache_duration = int(os.environ.get('TRIVY_CACHE_DURATION', '3600'))
        self._cache = TrivyCache(duration_seconds=self._cache_duration)
        self._last_health_check: Optional[datetime] = None
        self._is_healthy: bool = False
        self._health_check_interval = 30  # seconds
        self._health_lock = Lock()

        # Trivy container name for Docker exec scanning
        self._trivy_container = os.environ.get('TRIVY_CONTAINER_NAME', 'trivy-server')

        # Background scanning
        self._scan_queue: Queue = Queue()
        self._pending_scans: Set[str] = set()
        self._pending_lock = Lock()
        self._scanner_thread: Optional[Thread] = None
        self._scanner_running = False

    @property
    def is_enabled(self) -> bool:
        """Check if Trivy integration is enabled (URL configured)."""
        enabled_env = os.environ.get('TRIVY_ENABLED', 'true').lower()
        return enabled_env == 'true' and bool(self._server_url)

    @property
    def server_url(self) -> str:
        """Get configured Trivy server URL."""
        return self._server_url

    def health_check(self, force: bool = False) -> bool:
        """
        Check Trivy server health. Uses cached result unless forced.
        Returns True if server is healthy and responsive.
        """
        if not self.is_enabled:
            return False

        with self._health_lock:
            # Use cached health status if recent
            if not force and self._last_health_check:
                elapsed = (datetime.now() - self._last_health_check).total_seconds()
                if elapsed < self._health_check_interval:
                    return self._is_healthy

            try:
                # Trivy server exposes /healthz endpoint
                response = requests.get(
                    f"{self._server_url}/healthz",
                    timeout=5
                )
                self._is_healthy = response.status_code == 200
            except requests.RequestException as e:
                logger.warning(f"Trivy health check failed: {e}")
                self._is_healthy = False

            self._last_health_check = datetime.now()
            return self._is_healthy

    def get_image_digest(self, docker_client, image_name: str) -> Optional[str]:
        """
        Extract image digest from Docker for use as cache key.
        Returns sha256 digest or image ID as fallback.
        """
        try:
            image = docker_client.images.get(image_name)
            # RepoDigests contains the digest, e.g., "nginx@sha256:..."
            repo_digests = image.attrs.get('RepoDigests', [])
            if repo_digests:
                for digest in repo_digests:
                    if '@sha256:' in digest:
                        return digest.split('@')[1]
            # Fallback to image ID
            return image.id
        except Exception as e:
            logger.debug(f"Could not get image digest for {image_name}: {e}")
            return None

    def scan_image(self, image_name: str, docker_client=None) -> Optional[ScanResult]:
        """
        Scan an image for vulnerabilities using Trivy server.

        Args:
            image_name: Docker image name (e.g., "nginx:latest")
            docker_client: Optional Docker client for digest extraction

        Returns:
            ScanResult with vulnerabilities, or None if scan failed
        """
        if not self.is_enabled:
            logger.debug("Trivy integration not enabled, skipping scan")
            return None

        if not self.health_check():
            logger.warning("Trivy server unavailable, skipping scan")
            return None

        # Validate image name to prevent command injection
        if not validate_image_name(image_name):
            logger.error(f"Invalid image name rejected: {image_name[:100]}")
            return None

        # Check cache by digest if we have docker client
        image_digest = None
        if docker_client:
            image_digest = self.get_image_digest(docker_client, image_name)
            if image_digest:
                cached, is_valid = self._cache.get(image_digest)
                if is_valid and cached:
                    logger.debug(f"Using cached scan for {image_name}")
                    return cached

        # Perform scan using Trivy via Docker exec into trivy container
        start_time = datetime.now()
        try:
            logger.info(f"Scanning image: {image_name}")

            # Get Docker client for exec
            client = get_docker_client()
            if not client:
                logger.error("Docker client unavailable for Trivy exec")
                return None

            # Find the Trivy container
            try:
                trivy_container = client.containers.get(self._trivy_container)
            except docker.errors.NotFound:
                logger.error(f"Trivy container '{self._trivy_container}' not found")
                return None
            except Exception as e:
                logger.error(f"Error finding Trivy container: {e}")
                return None

            # Build trivy command - scan the image via the trivy server
            # Use localhost since we're exec'ing into the trivy container where server is running
            # --timeout prevents hanging on unreachable registries
            cmd = f'trivy image --server http://localhost:4954 --format json --quiet --timeout {self._timeout}s "{image_name}"'

            # Execute the command in the Trivy container with a timeout.
            # exec_run has no built-in timeout, so we run it in a thread.
            try:
                exec_result_holder = [None]
                exec_error_holder = [None]

                def _run_exec():
                    try:
                        exec_result_holder[0] = trivy_container.exec_run(
                            cmd=['sh', '-c', cmd],
                            demux=True
                        )
                    except Exception as exc:
                        exec_error_holder[0] = exc

                exec_thread = Thread(target=_run_exec, daemon=True)
                exec_thread.start()
                exec_thread.join(timeout=self._timeout + 30)  # Extra 30s beyond trivy's own timeout

                if exec_thread.is_alive():
                    logger.error(f"Trivy scan timed out for {image_name} after {self._timeout + 30}s")
                    return None

                if exec_error_holder[0]:
                    raise exec_error_holder[0]

                exec_result = exec_result_holder[0]
                if exec_result is None:
                    logger.error(f"Trivy scan returned no result for {image_name}")
                    return None

                exit_code = exec_result.exit_code
                stdout, stderr = exec_result.output

                if exit_code != 0:
                    error_msg = stderr.decode('utf-8') if stderr else 'Unknown error'
                    logger.error(f"Trivy scan failed for {image_name}: {error_msg[:500]}")
                    return None

                output = stdout.decode('utf-8') if stdout else ''

            except Exception as e:
                logger.error(f"Docker exec failed for {image_name}: {e}")
                return None

            trivy_response = json.loads(output) if output else {}

            scan_duration = (datetime.now() - start_time).total_seconds()
            scan_result = self._normalize_response(
                trivy_response,
                image_name,
                image_digest or f"unknown:{image_name}",
                scan_duration
            )

            logger.info(
                f"Scan completed for {image_name}: "
                f"{scan_result.summary.critical} critical, {scan_result.summary.high} high, "
                f"{scan_result.summary.medium} medium, {scan_result.summary.low} low "
                f"({scan_duration:.1f}s)"
            )

            # Cache by digest if available
            if image_digest:
                self._cache.set(image_digest, scan_result)

            # Send ntfy notification for critical/high vulnerabilities
            try:
                from .notifications import ntfy_notifier
                if ntfy_notifier.is_enabled:
                    ntfy_notifier.notify_scan_complete(
                        image=image_name,
                        container=image_name.split(':')[0].split('/')[-1],  # Extract container name from image
                        server='docker',
                        critical=scan_result.summary.critical,
                        high=scan_result.summary.high,
                        medium=scan_result.summary.medium,
                        low=scan_result.summary.low
                    )
            except Exception as e:
                logger.debug(f"Failed to send notification: {e}")

            return scan_result

        except json.JSONDecodeError as e:
            logger.error(f"Trivy scan JSON parse failed for {image_name}: {e}")
            return None
        except Exception as e:
            logger.error(f"Trivy scan failed for {image_name}: {e}")
            return None

    def _normalize_response(
        self,
        trivy_response: Dict[str, Any],
        image_name: str,
        image_digest: str,
        scan_duration: float
    ) -> ScanResult:
        """Convert Trivy API response to normalized ScanResult."""
        vulnerabilities = []
        summary = VulnerabilitySummary()

        # Trivy response structure: {"Results": [{"Vulnerabilities": [...]}]}
        results = trivy_response.get('Results', [])
        for result in results:
            vulns = result.get('Vulnerabilities', []) or []
            for v in vulns:
                severity = v.get('Severity', 'UNKNOWN').upper()

                # Extract CVSS score from nested structure
                # Trivy provides CVSS in format: {"CVSS": {"nvd": {"V3Score": 7.5, "V3Vector": "..."}}}
                cvss_score = None
                cvss_vector = None
                cvss_data = v.get('CVSS', {})
                # Try NVD first, then other vendors
                for vendor in ['nvd', 'redhat', 'ghsa', 'amazon', 'oracle']:
                    vendor_cvss = cvss_data.get(vendor, {})
                    if vendor_cvss:
                        cvss_score = vendor_cvss.get('V3Score') or vendor_cvss.get('V2Score')
                        cvss_vector = vendor_cvss.get('V3Vector') or vendor_cvss.get('V2Vector')
                        if cvss_score:
                            break

                vuln = Vulnerability(
                    cve_id=v.get('VulnerabilityID', 'UNKNOWN'),
                    severity=severity,
                    title=v.get('Title', ''),
                    description=v.get('Description', ''),
                    pkg_name=v.get('PkgName', ''),
                    installed_version=v.get('InstalledVersion', ''),
                    fixed_version=v.get('FixedVersion'),
                    cvss_score=cvss_score,
                    cvss_vector=cvss_vector
                )
                vulnerabilities.append(vuln)

                # Update summary counts
                if severity == 'CRITICAL':
                    summary.critical += 1
                elif severity == 'HIGH':
                    summary.high += 1
                elif severity == 'MEDIUM':
                    summary.medium += 1
                elif severity == 'LOW':
                    summary.low += 1
                else:
                    summary.unknown += 1

        return ScanResult(
            image=image_name,
            image_digest=image_digest,
            scan_timestamp=datetime.now(),
            scan_duration=scan_duration,
            vulnerabilities=vulnerabilities,
            summary=summary
        )

    def get_cached_result(self, image_digest: str) -> Optional[ScanResult]:
        """Get cached scan result by image digest."""
        result, is_valid = self._cache.get(image_digest)
        return result if is_valid else None

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        return self._cache.get_stats()

    def clear_cache(self) -> None:
        """Clear all cached scan results."""
        self._cache.clear()
        logger.info("Trivy scan cache cleared")

    def _start_scanner_thread(self) -> None:
        """Start the background scanner thread if not already running."""
        if self._scanner_thread is not None and self._scanner_thread.is_alive():
            return

        self._scanner_running = True
        self._scanner_thread = Thread(target=self._scanner_loop, daemon=True)
        self._scanner_thread.start()
        logger.info("Background vulnerability scanner started")

    def _scanner_loop(self) -> None:
        """Background thread loop that processes scan queue."""
        while self._scanner_running:
            try:
                # Wait for an item with timeout to allow checking _scanner_running
                item = self._scan_queue.get(timeout=1.0)
                image_name, docker_client_info = item

                # Remove from pending set
                with self._pending_lock:
                    self._pending_scans.discard(image_name)

                # Perform the scan
                try:
                    self.scan_image(image_name, docker_client_info)
                except Exception as e:
                    logger.error(f"Background scan failed for {image_name}: {e}")

                self._scan_queue.task_done()

            except Empty:
                continue
            except Exception as e:
                logger.error(f"Scanner thread error: {e}")

    def queue_scan(self, image_name: str, docker_client=None) -> bool:
        """
        Queue an image for background scanning.

        Returns True if queued, False if already pending or cached.
        """
        if not self.is_enabled:
            return False

        # Check if already cached
        if docker_client:
            image_digest = self.get_image_digest(docker_client, image_name)
            if image_digest:
                cached, is_valid = self._cache.get(image_digest)
                if is_valid and cached:
                    return False  # Already have valid cached result

        # Check if already pending
        with self._pending_lock:
            if image_name in self._pending_scans:
                return False
            self._pending_scans.add(image_name)

        # Start scanner thread if needed
        self._start_scanner_thread()

        # Queue the scan
        self._scan_queue.put((image_name, docker_client))
        logger.debug(f"Queued scan for {image_name}")
        return True

    def queue_auto_scan(self, containers: List[Dict[str, Any]], docker_clients: Dict[str, Any]) -> int:
        """
        Queue auto-scans for containers that haven't been scanned yet.

        Args:
            containers: List of container data dicts with 'image' and 'server' keys
            docker_clients: Dict of server_name -> docker client

        Returns:
            Number of scans queued
        """
        if not self.is_enabled or not self.health_check():
            return 0

        queued = 0
        seen_images: Set[str] = set()

        for container in containers:
            image_name = container.get('image', '')
            server = container.get('server', '')
            vuln_summary = container.get('vulnerability_summary')

            # Skip if already scanned or no image
            if not image_name or image_name in seen_images:
                continue

            # Skip if security scanning is disabled for this container
            if container.get('security_skip', False):
                continue

            # Skip if already has scan results or is skipped
            if vuln_summary and vuln_summary.get('scan_status') in ('scanned', 'skipped'):
                continue

            seen_images.add(image_name)
            docker_client = docker_clients.get(server)

            if self.queue_scan(image_name, docker_client):
                queued += 1

        if queued > 0:
            logger.info(f"Auto-scan queued {queued} images for vulnerability scanning")

        return queued

    def get_pending_count(self) -> int:
        """Get the number of pending scans."""
        with self._pending_lock:
            return len(self._pending_scans)

    def is_scan_pending(self, image_name: str) -> bool:
        """Check if a scan is pending for an image."""
        with self._pending_lock:
            return image_name in self._pending_scans


# Singleton instance
trivy_client = TrivyClient()
