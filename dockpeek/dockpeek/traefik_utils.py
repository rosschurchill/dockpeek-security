"""
Traefik API integration for Dockpeek.

Fetches all HTTP routers from Traefik API to display routes
that may not be configured via Docker labels.
"""

import os
import re
import logging
import requests
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from threading import Lock

logger = logging.getLogger(__name__)


class TraefikClient:
    """Client for Traefik API to fetch router information."""

    def __init__(self):
        self._api_url = os.environ.get('TRAEFIK_API_URL', '').rstrip('/')
        self._username = os.environ.get('TRAEFIK_API_USERNAME', '')
        self._password = os.environ.get('TRAEFIK_API_PASSWORD', '')
        self._timeout = int(os.environ.get('TRAEFIK_API_TIMEOUT', '5'))
        self._cache: Optional[Dict] = None
        self._cache_time: Optional[datetime] = None
        self._cache_duration = 30  # seconds
        self._lock = Lock()

    @property
    def _auth(self):
        """Get auth tuple if credentials are configured."""
        if self._username and self._password:
            return (self._username, self._password)
        return None

    @property
    def is_enabled(self) -> bool:
        """Check if Traefik API integration is enabled."""
        return bool(self._api_url)

    @property
    def api_url(self) -> str:
        return self._api_url

    def get_all_routers(self) -> List[Dict[str, Any]]:
        """
        Fetch all HTTP routers from Traefik API.
        Returns list of router objects with name, rule, service, etc.
        """
        if not self.is_enabled:
            return []

        # Check cache
        with self._lock:
            if self._cache is not None and self._cache_time:
                if datetime.now() - self._cache_time < timedelta(seconds=self._cache_duration):
                    return self._cache

        try:
            response = requests.get(
                f"{self._api_url}/api/http/routers",
                timeout=self._timeout,
                auth=self._auth
            )
            response.raise_for_status()
            routers = response.json()

            # Cache the result
            with self._lock:
                self._cache = routers
                self._cache_time = datetime.now()

            return routers

        except requests.RequestException as e:
            logger.warning(f"Failed to fetch Traefik routers: {e}")
            return []

    def get_routes_by_service(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get all routes organized by service name.
        Returns dict mapping service name to list of routes.
        """
        routers = self.get_all_routers()
        routes_by_service: Dict[str, List[Dict]] = {}

        for router in routers:
            service_name = router.get('service', '')
            if not service_name:
                continue

            # Parse the rule to extract host
            rule = router.get('rule', '')
            hosts = re.findall(r'Host\(`([^`]+)`\)', rule)

            # Determine protocol from TLS and entrypoints
            is_tls = router.get('tls') is not None
            entrypoints = router.get('entryPoints', [])
            is_https = is_tls or any(
                any(k in ep.lower() for k in ('https', '443', 'secure', 'ssl', 'tls'))
                for ep in entrypoints
            )
            protocol = 'https' if is_https else 'http'

            # Extract path prefix if present
            path_match = re.search(r'PathPrefix\(`([^`]+)`\)', rule)
            path_prefix = path_match.group(1) if path_match else ''

            for host in hosts:
                url = f"{protocol}://{host}{path_prefix}"
                route_info = {
                    'router': router.get('name', ''),
                    'url': url,
                    'rule': rule,
                    'host': host,
                    'service': service_name,
                    'entrypoints': entrypoints,
                    'tls': is_tls,
                    'provider': router.get('provider', 'unknown')
                }

                # Normalize service name for matching
                # Traefik service names often have suffixes like @docker, @file
                base_service = service_name.split('@')[0]

                if base_service not in routes_by_service:
                    routes_by_service[base_service] = []
                routes_by_service[base_service].append(route_info)

        return routes_by_service

    def get_routes_for_container(self, container_name: str, stack_name: str = '') -> List[Dict[str, Any]]:
        """
        Get Traefik routes that might be associated with a container.
        Matches by container name or stack-service naming convention.
        """
        routes_by_service = self.get_routes_by_service()
        matching_routes = []

        # Try different naming patterns
        patterns_to_try = [
            container_name,
            container_name.lower(),
            container_name.replace('-', '_'),
            container_name.replace('_', '-'),
        ]

        # Add stack-based patterns if stack is known
        if stack_name:
            patterns_to_try.extend([
                f"{stack_name}-{container_name}",
                f"{stack_name}_{container_name}",
                f"{stack_name}-{container_name}".lower(),
            ])

        for service_name, routes in routes_by_service.items():
            service_lower = service_name.lower()
            for pattern in patterns_to_try:
                if pattern.lower() in service_lower or service_lower in pattern.lower():
                    matching_routes.extend(routes)
                    break

        # Deduplicate by URL
        seen_urls = set()
        unique_routes = []
        for route in matching_routes:
            if route['url'] not in seen_urls:
                seen_urls.add(route['url'])
                unique_routes.append(route)

        return unique_routes

    def get_all_routes_flat(self) -> List[Dict[str, Any]]:
        """Get all routes as a flat list for display."""
        routers = self.get_all_routers()
        routes = []

        for router in routers:
            rule = router.get('rule', '')
            hosts = re.findall(r'Host\(`([^`]+)`\)', rule)

            is_tls = router.get('tls') is not None
            entrypoints = router.get('entryPoints', [])
            is_https = is_tls or any(
                any(k in ep.lower() for k in ('https', '443', 'secure', 'ssl', 'tls'))
                for ep in entrypoints
            )
            protocol = 'https' if is_https else 'http'

            path_match = re.search(r'PathPrefix\(`([^`]+)`\)', rule)
            path_prefix = path_match.group(1) if path_match else ''

            for host in hosts:
                url = f"{protocol}://{host}{path_prefix}"
                routes.append({
                    'router': router.get('name', ''),
                    'url': url,
                    'host': host,
                    'service': router.get('service', ''),
                    'provider': router.get('provider', 'unknown'),
                    'status': router.get('status', 'unknown')
                })

        return routes

    def clear_cache(self):
        """Clear the router cache."""
        with self._lock:
            self._cache = None
            self._cache_time = None


# Singleton instance
traefik_client = TraefikClient()
