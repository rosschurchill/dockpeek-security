"""
Prometheus metrics endpoint for DockPeek Security.

Exposes vulnerability counts and container health metrics for Grafana integration.
"""

import logging
from prometheus_client import Gauge, Counter, Info, generate_latest, CONTENT_TYPE_LATEST
from flask import Blueprint, Response

logger = logging.getLogger(__name__)

metrics_bp = Blueprint('metrics', __name__)

# Vulnerability metrics
VULN_CRITICAL = Gauge(
    'dockpeek_vulnerabilities_critical_total',
    'Total critical vulnerabilities across all containers'
)
VULN_HIGH = Gauge(
    'dockpeek_vulnerabilities_high_total',
    'Total high severity vulnerabilities across all containers'
)
VULN_MEDIUM = Gauge(
    'dockpeek_vulnerabilities_medium_total',
    'Total medium severity vulnerabilities across all containers'
)
VULN_LOW = Gauge(
    'dockpeek_vulnerabilities_low_total',
    'Total low severity vulnerabilities across all containers'
)
VULN_TOTAL = Gauge(
    'dockpeek_vulnerabilities_total',
    'Total vulnerabilities across all containers'
)

# Per-container vulnerability metrics
CONTAINER_VULNS = Gauge(
    'dockpeek_container_vulnerabilities',
    'Vulnerabilities per container',
    ['container', 'server', 'image', 'severity']
)

# Container metrics
CONTAINERS_TOTAL = Gauge(
    'dockpeek_containers_total',
    'Total number of containers'
)
CONTAINERS_RUNNING = Gauge(
    'dockpeek_containers_running',
    'Number of running containers'
)
CONTAINERS_SCANNED = Gauge(
    'dockpeek_containers_scanned',
    'Number of containers with vulnerability scans'
)
CONTAINERS_UNSCANNED = Gauge(
    'dockpeek_containers_unscanned',
    'Number of containers without vulnerability scans'
)

# Scan metrics
SCANS_TOTAL = Counter(
    'dockpeek_scans_total',
    'Total number of vulnerability scans performed'
)
SCANS_PENDING = Gauge(
    'dockpeek_scans_pending',
    'Number of scans currently pending'
)

# Trivy health
TRIVY_HEALTHY = Gauge(
    'dockpeek_trivy_healthy',
    'Trivy server health status (1=healthy, 0=unhealthy)'
)

# App info
APP_INFO = Info(
    'dockpeek',
    'DockPeek application information'
)


def update_metrics():
    """
    Update all Prometheus metrics with current data.
    Called before serving /metrics endpoint.
    """
    from .docker_utils import discover_docker_clients
    from .trivy_utils import trivy_client

    try:
        servers = discover_docker_clients()
        active_servers = [s for s in servers if s['status'] == 'active']

        total_containers = 0
        running_containers = 0
        scanned_containers = 0
        unscanned_containers = 0

        total_critical = 0
        total_high = 0
        total_medium = 0
        total_low = 0
        total_vulns = 0

        # Clear per-container metrics first
        CONTAINER_VULNS._metrics.clear()

        for server in active_servers:
            try:
                client = server['client']
                containers = client.containers.list(all=True)

                for container in containers:
                    total_containers += 1

                    # Check running status
                    if container.status == 'running':
                        running_containers += 1

                    # Get image and check for vulnerabilities
                    image_name = container.attrs.get('Config', {}).get('Image', '')
                    if not image_name:
                        unscanned_containers += 1
                        continue

                    # Get vulnerability data
                    image_digest = trivy_client.get_image_digest(client, image_name)
                    if image_digest:
                        cached = trivy_client.get_cached_result(image_digest)
                        if cached:
                            scanned_containers += 1

                            # Update totals
                            total_critical += cached.summary.critical
                            total_high += cached.summary.high
                            total_medium += cached.summary.medium
                            total_low += cached.summary.low
                            total_vulns += cached.summary.total

                            # Per-container metrics
                            labels = {
                                'container': container.name,
                                'server': server['name'],
                                'image': image_name[:100]  # Truncate long image names
                            }

                            CONTAINER_VULNS.labels(**labels, severity='critical').set(cached.summary.critical)
                            CONTAINER_VULNS.labels(**labels, severity='high').set(cached.summary.high)
                            CONTAINER_VULNS.labels(**labels, severity='medium').set(cached.summary.medium)
                            CONTAINER_VULNS.labels(**labels, severity='low').set(cached.summary.low)
                        else:
                            unscanned_containers += 1
                    else:
                        unscanned_containers += 1

            except Exception as e:
                logger.error(f"Error collecting metrics from {server['name']}: {e}")

        # Update gauges
        VULN_CRITICAL.set(total_critical)
        VULN_HIGH.set(total_high)
        VULN_MEDIUM.set(total_medium)
        VULN_LOW.set(total_low)
        VULN_TOTAL.set(total_vulns)

        CONTAINERS_TOTAL.set(total_containers)
        CONTAINERS_RUNNING.set(running_containers)
        CONTAINERS_SCANNED.set(scanned_containers)
        CONTAINERS_UNSCANNED.set(unscanned_containers)

        # Trivy status
        if trivy_client.is_enabled:
            TRIVY_HEALTHY.set(1 if trivy_client.health_check() else 0)
            SCANS_PENDING.set(trivy_client.get_pending_count())
        else:
            TRIVY_HEALTHY.set(0)
            SCANS_PENDING.set(0)

    except Exception as e:
        logger.error(f"Error updating metrics: {e}")


def init_app_info(version: str):
    """Initialize application info metric."""
    APP_INFO.info({
        'version': version,
        'name': 'dockpeek-security'
    })


@metrics_bp.route('/metrics')
def metrics():
    """
    Prometheus metrics endpoint.

    Returns metrics in Prometheus text format.
    No authentication required for metrics scraping.
    """
    update_metrics()
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)
