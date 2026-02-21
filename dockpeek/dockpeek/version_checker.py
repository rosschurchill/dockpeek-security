"""
Version checker for Docker images.

Queries registries to find newer version tags available for pinned images.
Supports Docker Hub, ghcr.io, lscr.io, and other registries.

Uses file-based cache for multi-worker compatibility (Gunicorn).
"""

import os
import re
import json
import logging
import requests
import fcntl
from dataclasses import dataclass, asdict
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime, timedelta
from threading import Lock
from pathlib import Path

logger = logging.getLogger(__name__)

# File-based cache location for multi-worker compatibility
VERSION_CACHE_FILE = os.environ.get(
    'DOCKPEEK_VERSION_CACHE',
    '/tmp/dockpeek_version_cache.json'
)


@dataclass
class VersionInfo:
    """Information about an available version."""
    tag: str
    version: Tuple
    is_newer: bool
    is_stable: bool = True
    digest: Optional[str] = None
    created: Optional[datetime] = None


class VersionParser:
    """Parse and compare semantic versions from Docker tags."""

    # Pattern to extract version numbers from tags
    VERSION_PATTERN = re.compile(
        r'^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?(?:-(.+))?$'
    )

    # Platform-specific suffixes to filter out (prefer clean tags)
    PLATFORM_SUFFIXES = (
        '-windowsservercore', '-nanoserver', '-windows',
        '-linux', '-alpine', '-slim', '-buster', '-bullseye', '-bookworm',
        '-arm64', '-amd64', '-armhf', '-arm32v7', '-arm64v8',
        '-ltsc2019', '-ltsc2022', '-1809'
    )

    # Unstable/dev version indicators
    UNSTABLE_INDICATORS = (
        'develop', 'dev', 'beta', 'alpha', 'rc', 'nightly',
        'unstable', 'test', 'snapshot', 'canary', 'preview',
        'pre', 'edge', 'experimental', 'trunk', 'master', 'main',
        'next', 'tip', 'draft', 'staging', 'ci', 'build', 'hotfix',
    )

    @classmethod
    def is_platform_specific(cls, tag: str) -> bool:
        """Check if a tag has platform-specific suffixes."""
        tag_lower = tag.lower()
        return any(suffix in tag_lower for suffix in cls.PLATFORM_SUFFIXES)

    @classmethod
    def is_unstable(cls, tag: str) -> bool:
        """Check if a tag is a dev/unstable/beta version.

        Uses word-boundary matching to avoid false positives like
        'main' matching 'maintenance' or 'test' matching 'latest'.
        """
        tag_lower = tag.lower()
        # Split tag into components by common separators
        # e.g., "1.0.0-beta.1" -> ["1", "0", "0", "beta", "1"]
        parts = re.split(r'[-._]', tag_lower)
        for indicator in cls.UNSTABLE_INDICATORS:
            if indicator in parts:
                return True
        return False

    @classmethod
    def is_stable(cls, tag: str) -> bool:
        """Check if a tag is a stable release (not dev/beta/etc)."""
        return not cls.is_unstable(tag) and not cls.is_platform_specific(tag)

    @classmethod
    def is_date_based_version(cls, major: int, minor: int, patch: int) -> bool:
        """
        Check if version looks like a date-based version (YYYY.MM.DD).
        Date-based versions have major >= 2019 and minor/patch in valid date ranges.
        """
        return (
            2019 <= major <= 2099 and
            1 <= minor <= 12 and
            1 <= patch <= 31
        )

    @classmethod
    def parse(cls, tag: str) -> Optional[Tuple]:
        """
        Parse a version tag into comparable tuple.
        Returns None if not a valid version.

        Examples:
            "1.41.3" -> (False, 1, 41, 3, 0, "")
            "v3.5.0" -> (False, 3, 5, 0, 0, "")
            "2.15.0-ls123" -> (False, 2, 15, 0, 0, "ls123")
            "2021.12.16" -> (True, 2021, 12, 16, 0, "")  # Date-based
            "latest" -> None
            "168" -> None (single number is not a valid version)

        The first element of the tuple indicates if it's a date-based version.
        """
        if tag in ('latest', 'stable', 'edge', 'dev', 'nightly', 'master', 'main'):
            return None

        match = cls.VERSION_PATTERN.match(tag)
        if not match:
            return None

        groups = match.groups()

        # Require at least major.minor (not just a single number)
        # Single numbers like "168" are usually build numbers, not versions
        if groups[1] is None:
            return None

        major = int(groups[0]) if groups[0] else 0
        minor = int(groups[1]) if groups[1] else 0
        patch = int(groups[2]) if groups[2] else 0
        build = int(groups[3]) if groups[3] else 0
        suffix = groups[4] or ""

        # Check if this is a date-based version (YYYY.MM.DD format)
        is_date_based = cls.is_date_based_version(major, minor, patch)

        return (is_date_based, major, minor, patch, build, suffix)

    @classmethod
    def compare(cls, v1: Tuple, v2: Tuple) -> int:
        """
        Compare two version tuples.
        Returns: -1 if v1 < v2, 0 if equal, 1 if v1 > v2

        Tuple format: (is_date_based, major, minor, patch, build, suffix)

        Special handling: If one version is date-based (YYYY.MM.DD) and the other
        is semantic (X.Y.Z where X < 100), the semantic version is considered newer.
        This handles projects that migrated from date-based to semantic versioning.
        """
        v1_is_date = v1[0]
        v2_is_date = v2[0]

        # If one is date-based and the other isn't, semantic version is newer
        # (Projects migrate FROM date-based TO semantic, not vice versa)
        if v1_is_date and not v2_is_date:
            return -1  # v1 (date-based) is older than v2 (semantic)
        elif not v1_is_date and v2_is_date:
            return 1   # v1 (semantic) is newer than v2 (date-based)

        # Both are same type, compare numeric parts (skip index 0 which is is_date_based)
        for i in range(1, 5):
            if v1[i] < v2[i]:
                return -1
            elif v1[i] > v2[i]:
                return 1

        # If numeric parts equal, version without suffix is newer
        # e.g., 1.0.0 > 1.0.0-beta
        if v1[5] and not v2[5]:
            return -1
        elif not v1[5] and v2[5]:
            return 1

        return 0

    @classmethod
    def is_newer(cls, current: str, candidate: str) -> bool:
        """Check if candidate version is newer than current."""
        v1 = cls.parse(current)
        v2 = cls.parse(candidate)

        if v1 is None or v2 is None:
            return False

        return cls.compare(v1, v2) < 0


class RegistryClient:
    """Client for querying Docker registries."""

    def __init__(self):
        self._timeout = 10
        self._session = requests.Session()
        self._token_cache: Dict[str, Tuple[str, datetime]] = {}
        self._token_lock = Lock()

    def _get_docker_hub_token(self, repository: str) -> Optional[str]:
        """Get auth token for Docker Hub."""
        cache_key = f"dockerhub:{repository}"

        with self._token_lock:
            if cache_key in self._token_cache:
                token, expires = self._token_cache[cache_key]
                if datetime.now() < expires:
                    return token

        try:
            # Docker Hub auth endpoint
            auth_url = f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repository}:pull"
            response = self._session.get(auth_url, timeout=self._timeout)
            response.raise_for_status()
            token = response.json().get('token')

            with self._token_lock:
                # Token valid for 5 minutes
                self._token_cache[cache_key] = (token, datetime.now() + timedelta(minutes=5))

            return token
        except Exception as e:
            logger.debug(f"Failed to get Docker Hub token: {e}")
            return None

    def get_tags(self, image: str) -> List[str]:
        """
        Get all available tags for an image.
        Supports Docker Hub, ghcr.io, lscr.io, gcr.io, quay.io.
        """
        # Parse image name to determine registry
        registry, repository, _ = self._parse_image(image)

        try:
            if registry == 'docker.io':
                return self._get_docker_hub_tags(repository)
            elif registry == 'ghcr.io':
                return self._get_ghcr_tags(repository)
            elif registry == 'lscr.io':
                return self._get_lscr_tags(repository)
            elif registry == 'gcr.io':
                return self._get_gcr_tags(repository)
            elif registry == 'quay.io':
                return self._get_quay_tags(repository)
            else:
                return self._get_generic_tags(registry, repository)
        except Exception as e:
            logger.warning(f"Failed to get tags for {image}: {e}")
            return []

    def _parse_image(self, image: str) -> Tuple[str, str, str]:
        """
        Parse image name into (registry, repository, tag).

        Examples:
            "nginx:latest" -> ("docker.io", "library/nginx", "latest")
            "linuxserver/plex:1.41.3" -> ("docker.io", "linuxserver/plex", "1.41.3")
            "ghcr.io/user/repo:v1" -> ("ghcr.io", "user/repo", "v1")
        """
        # Split tag
        if ':' in image and '/' in image.split(':')[-1]:
            # Port in registry, no tag
            tag = 'latest'
            name = image
        elif ':' in image:
            name, tag = image.rsplit(':', 1)
        else:
            name, tag = image, 'latest'

        # Determine registry
        parts = name.split('/')

        if len(parts) == 1:
            # Official image: nginx -> docker.io/library/nginx
            return ('docker.io', f'library/{parts[0]}', tag)
        elif '.' in parts[0] or ':' in parts[0]:
            # Has registry: ghcr.io/user/repo or localhost:5000/repo
            registry = parts[0]
            repository = '/'.join(parts[1:])
            return (registry, repository, tag)
        else:
            # Docker Hub user image: linuxserver/plex
            return ('docker.io', name, tag)

    def _get_docker_hub_tags(self, repository: str) -> List[str]:
        """Get tags from Docker Hub."""
        token = self._get_docker_hub_token(repository)
        if not token:
            return []

        headers = {'Authorization': f'Bearer {token}'}
        url = f"https://registry-1.docker.io/v2/{repository}/tags/list"

        response = self._session.get(url, headers=headers, timeout=self._timeout)
        response.raise_for_status()

        return response.json().get('tags', [])

    def _get_ghcr_token(self, repository: str) -> Optional[str]:
        """Get anonymous auth token for GitHub Container Registry."""
        cache_key = f"ghcr:{repository}"

        with self._token_lock:
            if cache_key in self._token_cache:
                token, expires = self._token_cache[cache_key]
                if datetime.now() < expires:
                    return token

        try:
            # ghcr.io token endpoint
            auth_url = f"https://ghcr.io/token?scope=repository:{repository}:pull"
            response = self._session.get(auth_url, timeout=self._timeout)
            response.raise_for_status()
            token = response.json().get('token')

            with self._token_lock:
                # Token valid for 5 minutes
                self._token_cache[cache_key] = (token, datetime.now() + timedelta(minutes=5))

            return token
        except Exception as e:
            logger.debug(f"Failed to get ghcr.io token: {e}")
            return None

    def _get_ghcr_tags(self, repository: str) -> List[str]:
        """Get tags from GitHub Container Registry with pagination support."""
        token = self._get_ghcr_token(repository)
        if not token:
            return []

        headers = {'Authorization': f'Bearer {token}'}
        all_tags = []
        base_url = "https://ghcr.io"
        url = f"{base_url}/v2/{repository}/tags/list?n=1000"  # Request more tags

        try:
            # Handle pagination - ghcr.io uses Link header for next page
            page = 0
            while url and page < 10:  # Safety limit: max 10 pages
                response = self._session.get(url, headers=headers, timeout=self._timeout)
                response.raise_for_status()
                data = response.json()
                all_tags.extend(data.get('tags', []))
                page += 1

                # Check for next page in Link header
                link_header = response.headers.get('Link', '')
                url = None
                if 'rel="next"' in link_header:
                    # Extract URL from Link header: <url>; rel="next"
                    for part in link_header.split(','):
                        if 'rel="next"' in part:
                            rel_url = part.split(';')[0].strip().strip('<>')
                            # Handle relative URLs from ghcr.io
                            if rel_url.startswith('/'):
                                url = base_url + rel_url
                            else:
                                url = rel_url
                            break

            return all_tags
        except Exception as e:
            logger.debug(f"Failed to get ghcr.io tags for {repository}: {e}")
            return []

    def _get_lscr_tags(self, repository: str) -> List[str]:
        """Get tags from LinuxServer Container Registry.

        lscr.io mirrors to ghcr.io. The repository already includes
        the full path (e.g., 'linuxserver/sonarr'), so we pass it directly.
        """
        return self._get_ghcr_tags(repository)

    def _get_gcr_tags(self, repository: str) -> List[str]:
        """Get tags from Google Container Registry."""
        url = f"https://gcr.io/v2/{repository}/tags/list"

        try:
            response = self._session.get(url, timeout=self._timeout)
            response.raise_for_status()
            return response.json().get('tags', [])
        except Exception:
            return []

    def _get_quay_tags(self, repository: str) -> List[str]:
        """Get tags from Quay.io."""
        url = f"https://quay.io/api/v1/repository/{repository}/tag/"

        try:
            response = self._session.get(url, timeout=self._timeout)
            response.raise_for_status()
            data = response.json()
            return [t['name'] for t in data.get('tags', [])]
        except Exception:
            return []

    def _get_generic_tags(self, registry: str, repository: str) -> List[str]:
        """Get tags from a generic Docker registry."""
        url = f"https://{registry}/v2/{repository}/tags/list"

        try:
            response = self._session.get(url, timeout=self._timeout)
            response.raise_for_status()
            return response.json().get('tags', [])
        except Exception:
            return []


class NewVersionChecker:
    """Check for newer versions of Docker images.

    Uses file-based cache for multi-worker compatibility (Gunicorn workers
    don't share memory, so we need a shared cache file).
    """

    def __init__(self):
        self._registry = RegistryClient()
        self._cache_duration = 3600  # 1 hour - persist version checks longer
        self._lock = Lock()
        self._cache_file = Path(VERSION_CACHE_FILE)
        # In-memory cache as a fast read-through cache
        self._memory_cache: Dict[str, Tuple[Any, datetime]] = {}

    def _read_file_cache(self) -> Dict[str, Any]:
        """Read the shared cache file with file locking."""
        if not self._cache_file.exists():
            return {}
        try:
            with open(self._cache_file, 'r') as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_SH)
                try:
                    return json.load(f)
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except (json.JSONDecodeError, IOError) as e:
            logger.debug(f"Failed to read cache file: {e}")
            return {}

    def _write_file_cache(self, cache: Dict[str, Any]) -> None:
        """Write to the shared cache file with file locking."""
        try:
            # Ensure directory exists
            self._cache_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self._cache_file, 'w') as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    json.dump(cache, f)
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except IOError as e:
            logger.warning(f"Failed to write cache file: {e}")

    def _get_from_cache(self, image: str) -> Optional[Tuple[Optional[dict], datetime]]:
        """Get an entry from the shared file cache."""
        cache = self._read_file_cache()
        if image in cache:
            entry = cache[image]
            timestamp = datetime.fromisoformat(entry['timestamp'])
            if datetime.now() - timestamp < timedelta(seconds=self._cache_duration):
                return (entry.get('result'), timestamp)
        return None

    def _set_in_cache(self, image: str, result: Optional['VersionInfo']) -> None:
        """Set an entry in the shared file cache."""
        cache = self._read_file_cache()

        # Convert VersionInfo to dict for JSON serialization
        result_dict = None
        if result:
            result_dict = {
                'tag': result.tag,
                'version': list(result.version),  # Tuple to list for JSON
                'is_newer': result.is_newer,
                'is_stable': result.is_stable,
            }

        cache[image] = {
            'result': result_dict,
            'timestamp': datetime.now().isoformat()
        }
        self._write_file_cache(cache)

    def get_cached_version(self, image: str) -> Optional[VersionInfo]:
        """
        Get cached version info WITHOUT making network requests.
        Returns None if not in cache. Use this for fast page loads.

        Reads from shared file cache for multi-worker compatibility.
        """
        cached = self._get_from_cache(image)
        if cached:
            result_dict, _ = cached
            if result_dict:
                return VersionInfo(
                    tag=result_dict['tag'],
                    version=tuple(result_dict['version']),
                    is_newer=result_dict['is_newer'],
                    is_stable=result_dict.get('is_stable', True)
                )
        return None

    def check_for_newer_version(self, image: str) -> Optional[VersionInfo]:
        """
        Check if a newer version is available for the given image.

        Args:
            image: Full image name with tag (e.g., "linuxserver/plex:1.41.3")

        Returns:
            VersionInfo if newer version found, None otherwise
        """
        # Check file-based cache first
        cached_version = self.get_cached_version(image)
        if cached_version is not None:
            return cached_version

        # Also check for cached None result (no newer version)
        cached = self._get_from_cache(image)
        if cached is not None:
            # Cache entry exists (even if result is None)
            return cached[0] if cached[0] else None

        # Parse current version
        registry, repository, current_tag = self._registry._parse_image(image)
        current_version = VersionParser.parse(current_tag)

        if current_version is None:
            # Can't parse current version, skip
            logger.debug(f"Cannot parse version from tag: {current_tag}")
            return None

        # Get all tags
        if registry == 'docker.io':
            full_image = repository
        else:
            full_image = f"{registry}/{repository}"

        tags = self._registry.get_tags(full_image)

        if not tags:
            logger.debug(f"No tags found for {full_image}")
            return None

        # Find newer versions (prefer stable, non-platform-specific tags)
        newer_versions = []
        is_current_unstable = VersionParser.is_unstable(current_tag)
        is_current_platform_specific = VersionParser.is_platform_specific(current_tag)

        for tag in tags:
            tag_version = VersionParser.parse(tag)
            if tag_version and VersionParser.compare(current_version, tag_version) < 0:
                is_tag_unstable = VersionParser.is_unstable(tag)
                is_tag_platform_specific = VersionParser.is_platform_specific(tag)

                # Skip unstable tags unless current is also unstable
                if is_tag_unstable and not is_current_unstable:
                    continue

                # Skip platform-specific tags unless current is also platform-specific
                if is_tag_platform_specific and not is_current_platform_specific:
                    continue

                # Skip tags with suspicious compound version suffixes
                # e.g., "5.14-2.0.0.5344-ls5" has suffix "2.0.0.5344-ls5" which contains
                # what looks like another version number embedded in it
                suffix = tag_version[5]  # suffix is 6th element of tuple
                if suffix and re.search(r'\d+\.\d+\.\d+', suffix):
                    continue

                # Skip tags that have fewer explicit version segments than current
                # Count dots in version portion to determine segments: "4.0.11" has 2 dots (3 parts)
                # "5.14" has 1 dot (2 parts) - skip it if current has 3 parts
                # This filters old LinuxServer tags like "5.14" (RSS version, not app version)
                def count_version_segments(tag_str):
                    # Extract version portion before any suffix
                    ver_part = tag_str.lstrip('v').split('-')[0]
                    return ver_part.count('.') + 1

                current_segments = count_version_segments(current_tag)
                tag_segments = count_version_segments(tag)
                if tag_segments < current_segments:
                    continue

                newer_versions.append((tag, tag_version, is_tag_platform_specific, is_tag_unstable))

        if not newer_versions:
            # Cache negative result in shared file cache
            self._set_in_cache(image, None)
            return None

        # Sort: prefer stable, then non-platform-specific, then by version (newest first)
        # Sort key: (is_unstable, is_platform_specific, is_date_based, -version_tuple)
        # Date-based versions sort after semantic versions (they're older)
        # Version tuple format: (is_date_based, major, minor, patch, build, suffix)
        newer_versions.sort(key=lambda x: (x[3], x[2], x[1][0], tuple(-v if isinstance(v, int) else 0 for v in x[1][1:5])))
        newest_tag, newest_version, _, _ = newer_versions[0]

        result = VersionInfo(
            tag=newest_tag,
            version=newest_version,
            is_newer=True
        )

        # Cache result in shared file cache
        self._set_in_cache(image, result)

        logger.info(f"Newer version available for {image}: {newest_tag}")
        return result

    def get_available_versions(self, image: str, limit: int = 10) -> List[VersionInfo]:
        """
        Get list of available versions for an image.

        Args:
            image: Full image name with tag
            limit: Maximum number of versions to return

        Returns:
            List of VersionInfo sorted newest first
        """
        registry, repository, current_tag = self._registry._parse_image(image)
        current_version = VersionParser.parse(current_tag)

        if registry == 'docker.io':
            full_image = repository
        else:
            full_image = f"{registry}/{repository}"

        tags = self._registry.get_tags(full_image)

        versions = []
        for tag in tags:
            tag_version = VersionParser.parse(tag)
            if tag_version:
                is_newer = current_version and VersionParser.compare(current_version, tag_version) < 0
                is_stable = VersionParser.is_stable(tag)
                versions.append(VersionInfo(
                    tag=tag,
                    version=tag_version,
                    is_newer=is_newer,
                    is_stable=is_stable
                ))

        # Sort: stable first, then semantic versions before date-based, then by version (newest first)
        # Version tuple format: (is_date_based, major, minor, patch, build, suffix)
        versions.sort(key=lambda x: (not x.is_stable, x.version[0], tuple(-v if isinstance(v, int) else 0 for v in x.version[1:5])))

        return versions[:limit]

    def clear_cache(self):
        """Clear the version cache (both file and memory)."""
        try:
            if self._cache_file.exists():
                self._cache_file.unlink()
        except IOError as e:
            logger.warning(f"Failed to clear cache file: {e}")

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        cache = self._read_file_cache()
        return {
            'entries': len(cache),
            'cache_duration_seconds': self._cache_duration,
            'cache_file': str(self._cache_file)
        }


# Singleton instance
version_checker = NewVersionChecker()
