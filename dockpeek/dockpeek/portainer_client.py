"""
Portainer API client for stack-aware container updates.

Provides stack lookup and redeployment via the Portainer REST API.
Configured entirely via environment variables — no config files required.

Environment variables:
  PORTAINER_URL          Base URL, e.g. https://10.0.0.200:9443
  PORTAINER_API_KEY      ptr_* token from Portainer
  PORTAINER_ENDPOINT_ID  Docker endpoint ID (default: 2)
  PORTAINER_VERIFY_SSL   Whether to verify TLS cert (default: false)
"""

import os
import re
import time
import logging
import threading
from typing import Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


class PortainerClient:
    def __init__(self):
        self.url = os.environ.get("PORTAINER_URL", "").rstrip("/")
        self.api_key = os.environ.get("PORTAINER_API_KEY", "")
        self.endpoint_id = int(os.environ.get("PORTAINER_ENDPOINT_ID", "2"))
        self.verify_ssl = os.environ.get("PORTAINER_VERIFY_SSL", "false").lower() in ("true", "1", "yes")

        self._session = requests.Session()
        self._session.headers["X-API-Key"] = self.api_key
        self._session.verify = self.verify_ssl

        # Cache: container_name -> {"stack_id": int, "stack_name": str, "service_name": str, "ts": float}
        self._stack_cache: dict = {}
        self._cache_lock = threading.Lock()
        self._cache_ttl = 300  # 5 minutes

    @classmethod
    def is_configured(cls) -> bool:
        """Return True only when both URL and API key are set."""
        return bool(os.environ.get("PORTAINER_URL")) and bool(os.environ.get("PORTAINER_API_KEY"))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get(self, path: str, params: dict = None) -> requests.Response:
        url = f"{self.url}{path}"
        resp = self._session.get(url, params=params, timeout=15)
        resp.raise_for_status()
        return resp

    def _put(self, path: str, params: dict = None, json: dict = None) -> requests.Response:
        url = f"{self.url}{path}"
        resp = self._session.put(url, params=params, json=json, timeout=60)
        resp.raise_for_status()
        return resp

    # ------------------------------------------------------------------
    # Stack / container lookup
    # ------------------------------------------------------------------

    def get_container_stack(self, container_name: str) -> Optional[dict]:
        """Find which Portainer stack a container belongs to.

        Calls GET /api/stacks, then for each stack fetches its compose file
        and checks whether any service declares container_name matching the
        given name.  Results are cached for _cache_ttl seconds.

        Returns {"stack_id": int, "stack_name": str, "service_name": str}
        or None if the container is not managed by any stack.
        """
        now = time.monotonic()

        with self._cache_lock:
            entry = self._stack_cache.get(container_name)
            if entry and (now - entry["ts"]) < self._cache_ttl:
                return {k: v for k, v in entry.items() if k != "ts"}

        # Cache miss — rebuild the full mapping from the API.
        try:
            mapping = self._build_stack_mapping()
        except Exception as exc:
            logger.warning("Portainer: failed to build stack mapping: %s", exc)
            return None

        hit = mapping.get(container_name)

        with self._cache_lock:
            # Store everything we resolved so subsequent lookups are fast.
            for cname, info in mapping.items():
                self._stack_cache[cname] = {**info, "ts": now}

        return hit

    def _build_stack_mapping(self) -> dict:
        """Return {container_name: {stack_id, stack_name, service_name}} for all stacks."""
        resp = self._get("/api/stacks", params={"endpointId": self.endpoint_id})
        stacks = resp.json()

        mapping: dict = {}

        for stack in stacks:
            stack_id = stack["Id"]
            stack_name = stack.get("Name", str(stack_id))

            try:
                compose_content = self._get_stack_compose(stack_id)
            except Exception as exc:
                logger.debug("Portainer: could not fetch compose for stack %s: %s", stack_name, exc)
                continue

            services = self._parse_container_names(compose_content)
            for service_name, cname in services.items():
                mapping[cname] = {
                    "stack_id": stack_id,
                    "stack_name": stack_name,
                    "service_name": service_name,
                }

        return mapping

    def _get_stack_compose(self, stack_id: int) -> str:
        """Fetch the raw compose YAML string for a stack."""
        resp = self._get(
            f"/api/stacks/{stack_id}/file",
            params={"endpointId": self.endpoint_id},
        )
        return resp.json().get("StackFileContent", "")

    def find_service_for_container(self, stack_id: int, container_name: str) -> Optional[str]:
        """Parse a stack's compose YAML to find the service that declares container_name.

        Returns the service name string, or None if not found.
        """
        try:
            compose_content = self._get_stack_compose(stack_id)
        except Exception as exc:
            logger.warning("Portainer: could not fetch compose for stack %d: %s", stack_id, exc)
            return None

        services = self._parse_container_names(compose_content)
        for service_name, cname in services.items():
            if cname == container_name:
                return service_name

        return None

    # ------------------------------------------------------------------
    # Compose YAML parsing (no PyYAML dependency)
    # ------------------------------------------------------------------

    def _parse_container_names(self, compose_content: str) -> dict:
        """Scan compose YAML line-by-line to build {service_name: container_name}.

        Only services that explicitly declare a container_name field are
        included.  Services without container_name are skipped because we
        cannot reliably match them without full YAML parsing.
        """
        result: dict = {}
        current_service: Optional[str] = None
        in_services_block = False

        service_re = re.compile(r"^  ([a-zA-Z0-9_\-\.]+)\s*:\s*$")
        container_name_re = re.compile(r"^\s+container_name\s*:\s*['\"]?([^'\"#\s]+)['\"]?")

        for line in compose_content.splitlines():
            stripped = line.rstrip()

            if stripped == "services:":
                in_services_block = True
                current_service = None
                continue

            # A top-level key other than services ends that block.
            if in_services_block and stripped and not stripped.startswith(" "):
                in_services_block = False
                current_service = None
                continue

            if not in_services_block:
                continue

            svc_match = service_re.match(stripped)
            if svc_match:
                current_service = svc_match.group(1)
                continue

            if current_service:
                cn_match = container_name_re.match(stripped)
                if cn_match:
                    result[current_service] = cn_match.group(1)

        return result

    # ------------------------------------------------------------------
    # Stack redeployment
    # ------------------------------------------------------------------

    def redeploy_stack(
        self,
        stack_id: int,
        image_updates: Optional[dict] = None,
        pull_image: bool = True,
    ) -> dict:
        """Redeploy a Portainer stack, optionally updating service images first.

        Args:
            stack_id:      Portainer stack ID.
            image_updates: Optional mapping of {service_name: "new_image:tag"}.
                           The compose YAML is patched in-place before redeploying.
            pull_image:    Whether Portainer should pull from the registry (default True).
                           Pass False when the image was pre-loaded via docker load.

        Returns:
            {"success": True, "stack_name": str}
            or {"success": False, "error": str}
        """
        try:
            # Fetch current stack metadata (we need the name and env vars).
            stacks_resp = self._get("/api/stacks", params={"endpointId": self.endpoint_id})
            stack_meta = next(
                (s for s in stacks_resp.json() if s["Id"] == stack_id), None
            )
            if stack_meta is None:
                return {"success": False, "error": f"Stack {stack_id} not found"}

            stack_name = stack_meta.get("Name", str(stack_id))
            env_vars = stack_meta.get("Env") or []

            # Fetch current compose content.
            compose_content = self._get_stack_compose(stack_id)

            # Patch image tags when requested.
            if image_updates:
                compose_content = self._apply_image_updates(compose_content, image_updates)

            payload = {
                "stackFileContent": compose_content,
                "env": env_vars,
                "prune": False,
                "pullImage": pull_image,
            }

            self._put(
                f"/api/stacks/{stack_id}",
                params={"endpointId": self.endpoint_id},
                json=payload,
            )

            logger.info("Portainer: redeployed stack %s (id=%d)", stack_name, stack_id)
            return {"success": True, "stack_name": stack_name}

        except requests.HTTPError as exc:
            error = f"HTTP {exc.response.status_code}: {exc.response.text[:200]}"
            logger.error("Portainer: redeploy failed for stack %d: %s", stack_id, error)
            return {"success": False, "error": error}
        except Exception as exc:
            logger.error("Portainer: redeploy failed for stack %d: %s", stack_id, exc)
            return {"success": False, "error": str(exc)}

    def _apply_image_updates(self, compose_content: str, image_updates: dict) -> str:
        """Return compose_content with image lines replaced for named services.

        Uses a simple state-machine line scan rather than full YAML parsing.
        Replaces the first `image:` line found inside each targeted service block.
        """
        lines = compose_content.splitlines(keepends=True)
        updated_lines = []

        current_service: Optional[str] = None
        in_services_block = False
        replaced: set = set()

        service_re = re.compile(r"^  ([a-zA-Z0-9_\-\.]+)\s*:\s*$")
        image_re = re.compile(r"^(\s+image\s*:\s*)(.+)$")

        for line in lines:
            stripped = line.rstrip()

            if stripped == "services:":
                in_services_block = True
                current_service = None
                updated_lines.append(line)
                continue

            if in_services_block and stripped and not stripped.startswith(" "):
                in_services_block = False
                current_service = None
                updated_lines.append(line)
                continue

            if in_services_block:
                svc_match = service_re.match(stripped)
                if svc_match:
                    current_service = svc_match.group(1)
                    updated_lines.append(line)
                    continue

                if (
                    current_service
                    and current_service in image_updates
                    and current_service not in replaced
                ):
                    img_match = image_re.match(line.rstrip("\n").rstrip("\r"))
                    if img_match:
                        new_image = image_updates[current_service]
                        indent_and_key = img_match.group(1)
                        # Preserve the original line ending.
                        ending = "\n" if line.endswith("\n") else ""
                        line = f"{indent_and_key}{new_image}{ending}"
                        replaced.add(current_service)
                        logger.debug(
                            "Portainer: patched image for service '%s' → %s",
                            current_service,
                            new_image,
                        )

            updated_lines.append(line)

        missing = set(image_updates) - replaced
        if missing:
            logger.warning(
                "Portainer: could not find image lines for services: %s",
                ", ".join(sorted(missing)),
            )

        return "".join(updated_lines)

    def check_connection(self) -> bool:
        """Test connectivity to the Portainer API. Returns True on success."""
        try:
            resp = self._session.get(f"{self.url}/api/status", timeout=10)
            return resp.status_code == 200
        except Exception:
            return False

    def invalidate_cache(self, container_name: str = None) -> None:
        """Evict one or all entries from the stack lookup cache."""
        with self._cache_lock:
            if container_name:
                self._stack_cache.pop(container_name, None)
            else:
                self._stack_cache.clear()
