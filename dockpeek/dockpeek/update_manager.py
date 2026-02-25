from .update import update_checker
from .portainer_client import PortainerClient
import logging
import time
import re
import os
import fcntl
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
import docker

logger = logging.getLogger(__name__)

# Directory for lock files
LOCK_DIR = "/tmp/dockpeek_locks"
os.makedirs(LOCK_DIR, exist_ok=True)


class ContainerLock:
    """File-based lock that works across processes."""

    def __init__(self, container_name: str):
        safe_name = re.sub(r'[^a-zA-Z0-9_-]', '_', container_name)
        self.lock_file = os.path.join(LOCK_DIR, f"{safe_name}.lock")
        self.fd = None

    def acquire(self, blocking=False) -> bool:
        """Try to acquire the lock. Returns True if successful."""
        try:
            self.fd = open(self.lock_file, 'w')
            flags = fcntl.LOCK_EX
            if not blocking:
                flags |= fcntl.LOCK_NB
            fcntl.flock(self.fd, flags)
            return True
        except (IOError, OSError):
            if self.fd:
                self.fd.close()
                self.fd = None
            return False

    def release(self):
        """Release the lock."""
        if self.fd:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
                self.fd.close()
            except:
                pass
            self.fd = None


class ContainerUpdateError(Exception):
    def __init__(self, html_message: str, log_message: str = None):
        clean_message = log_message or strip_html_tags(html_message)
        super().__init__(clean_message)
        self.html_message = html_message


def strip_html_tags(text: str) -> str:
    clean_text = re.sub(r'<[^>]+>', '', text)
    clean_text = clean_text.replace('\n', ' ')
    return clean_text


class ContainerConfigExtractor:
    def __init__(self, container):
        self.container = container
        self.attrs = container.attrs
        self.config = self.attrs.get('Config', {})
        self.host_config = self.attrs.get('HostConfig', {})
    
    # Compose labels that become stale after an image update.
    # com.docker.compose.image stores the resolved image reference (with digest)
    # which becomes stale after DockPeek pulls a new image version.
    # We strip it to prevent Compose from detecting a stale digest mismatch.
    # IMPORTANT: We keep config-hash intact so Docker Compose can still identify
    # and manage this container properly, preventing duplicate instance creation
    # (e.g., myapp-web-2 appearing alongside the updated myapp-web-1).
    STALE_COMPOSE_LABELS = (
        'com.docker.compose.image',
    )

    def extract(self, strip_stale_compose: bool = False) -> Dict[str, Any]:
        network_mode = self.host_config.get('NetworkMode')

        hostname = None
        if network_mode and not network_mode.startswith('container:'):
            hostname = self.config.get('Hostname')

        labels = self._clean_dict(self.config.get('Labels') or {})
        if strip_stale_compose and labels.get('com.docker.compose.project'):
            for key in self.STALE_COMPOSE_LABELS:
                labels.pop(key, None)
            logger.info(f"Stripped stale compose labels for compose-managed container")

        return {
            'name': self.container.name,
            'hostname': hostname,
            'user': self.config.get('User'),
            'working_dir': self.config.get('WorkingDir'),
            'labels': labels,
            'environment': self._clean_list(self.config.get('Env', []) or []),
            'command': self.config.get('Cmd'),
            'entrypoint': self.config.get('Entrypoint'),
            'volumes': self._clean_list(self.host_config.get('Binds') or []),
            'ports': self._clean_dict(self.host_config.get('PortBindings') or {}),
            'network_mode': network_mode,
            'restart_policy': self.host_config.get('RestartPolicy', {'Name': 'no'}),
            'privileged': self.host_config.get('Privileged', False),
            'cap_add': self.host_config.get('CapAdd'),
            'cap_drop': self.host_config.get('CapDrop'),
            'devices': self.host_config.get('Devices'),
            'security_opt': self.host_config.get('SecurityOpt'),
            'detach': True
        }
    
    @staticmethod
    def _clean_list(items: List) -> List:
        return [item for item in items if item is not None]
    
    @staticmethod
    def _clean_dict(items: Dict) -> Dict:
        return {k: v for k, v in items.items() if v is not None}


class ContainerUpdater:
    def __init__(self, client: docker.DockerClient, server_name: str, timeouts: Dict[str, int] = None):
        self.client = client
        self.server_name = server_name
        self.timeouts = timeouts or {
            'api': 300,
            'stop': 60,
        }
        self.original_timeout = None
        self.update_checker = update_checker
        self._portainer = PortainerClient() if PortainerClient.is_configured() else None
        
    def __enter__(self):
        self.original_timeout = getattr(self.client.api, 'timeout', None)
        try:
            self.client.api.timeout = self.timeouts['api']
        except AttributeError:
            logger.warning("Could not set client timeout")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.original_timeout is not None:
            try:
                self.client.api.timeout = self.original_timeout
            except AttributeError:
                pass
    
    def update_via_portainer(self, container_name: str, new_image: str = None) -> Dict[str, Any]:
        """Attempt a stack-aware update through Portainer.

        Returns a result dict with ``success`` (bool) and either ``message``
        or ``error``.  When the container is not part of any Portainer stack
        the error value starts with "Container not in a Portainer stack" so
        the caller knows to fall back to the raw Docker path.
        """
        stack_info = self._portainer.get_container_stack(container_name)
        if not stack_info:
            return {
                "success": False,
                "error": "Container not in a Portainer stack, falling back to Docker API",
            }

        stack_id = stack_info["stack_id"]
        stack_name = stack_info.get("stack_name", stack_id)
        service_name = stack_info.get("service_name")

        # If get_container_stack didn't resolve the service name, ask explicitly.
        if not service_name:
            service_name = self._portainer.find_service_for_container(stack_id, container_name)

        logger.info(
            "[%s] Portainer path: container='%s' stack='%s' (id=%s) service='%s'",
            self.server_name, container_name, stack_name, stack_id, service_name,
        )

        if new_image and service_name:
            result = self._portainer.redeploy_stack(
                stack_id, image_updates={service_name: new_image}
            )
        else:
            # No image change — just redeploy to restart on the current (possibly pulled) image.
            if new_image and not service_name:
                logger.warning(
                    "[%s] Portainer: service name unknown for '%s', redeploying without image update",
                    self.server_name, container_name,
                )
            result = self._portainer.redeploy_stack(stack_id)

        if result.get("success"):
            msg = f"Container '{container_name}' redeployed via Portainer stack '{stack_name}'."
            if new_image:
                msg = f"Container '{container_name}' updated to '{new_image}' via Portainer stack '{stack_name}'."
            logger.info("[%s] %s", self.server_name, msg)
            return {"status": "success", "message": msg}

        return {"success": False, "error": result.get("error", "Portainer redeploy failed")}

    def _get_dependent_containers(self, container):
        dependent = []
        try:
            all_containers = self.client.containers.list(all=True)
            for other in all_containers:
                if other.id == container.id:
                    continue
                network_mode = other.attrs.get('HostConfig', {}).get('NetworkMode', '')
                if network_mode in [f'container:{container.name}', f'container:{container.id}']:
                    dependent.append(other)
        except Exception as e:
            logger.warning(f"Could not check for dependent containers: {e}")
        return dependent
    
    def update(self, container_name: str, force: bool = False, new_image: str = None) -> Dict[str, Any]:
        # Acquire file-based lock to prevent concurrent updates across processes
        lock = ContainerLock(container_name)
        if not lock.acquire(blocking=False):
            logger.info(f"[{self.server_name}] Update already in progress for: {container_name}")
            return {"status": "in_progress", "message": f"Update already in progress for '{container_name}'."}

        try:
            return self._do_update(container_name, force, new_image)
        finally:
            lock.release()

    def _do_update(self, container_name: str, force: bool = False, new_image: str = None) -> Dict[str, Any]:
        logger.info(f"[{self.server_name}] Starting update for: {container_name} (force={force}, new_image={new_image})")

        # Check orchestration labels for update restrictions
        try:
            container_obj = self.client.containers.get(container_name)
            labels = container_obj.labels or {}
            update_action = labels.get('dockpeek.update.action', '').lower()
            if update_action in ('skip', 'pin'):
                msg = f"Container '{container_name}' has dockpeek.update.action={update_action} — update blocked"
                logger.warning(f"[{self.server_name}] {msg}")
                return {"status": "blocked", "message": msg}
        except docker.errors.NotFound:
            pass  # Container not found; normal flow will raise the proper error later

        # Try Portainer first when it is configured.  This handles compose-managed
        # containers correctly (preserves stack env, networking, and service config).
        if self._portainer:
            logger.info(f"[{self.server_name}] Portainer is configured — attempting stack-aware update")
            portainer_result = self.update_via_portainer(container_name, new_image)
            if portainer_result.get("success") or portainer_result.get("status") == "success":
                return portainer_result
            err = portainer_result.get("error", "")
            if "not in a Portainer stack" in err:
                logger.info(f"[{self.server_name}] {err} for '{container_name}'")
            else:
                logger.warning(f"[{self.server_name}] Portainer update failed for '{container_name}': {err} — falling back to Docker API")
        else:
            logger.info(f"[{self.server_name}] Portainer not configured — using Docker API directly")

        container = self._get_container(container_name)

        dependent_containers = self._get_dependent_containers(container)
        if dependent_containers:
            logger.info(f"[{self.server_name}] Found {len(dependent_containers)} dependent containers: {[c.name for c in dependent_containers]}")

        # If a new image is specified, use it for the update (version upgrade)
        if new_image:
            image_name = new_image
            container_image_id = container.attrs.get('Image', '')
            logger.info(f"[{self.server_name}] Upgrading to new version: {new_image}")
        else:
            image_name, container_image_id = self._get_image_info(container)

        self._pull_image(image_name)

        if not force and not self._has_updates(image_name, container_image_id):
            logger.info(f"[{self.server_name}] No updates for {image_name}")
            return {"status": "success", "message": f"Container {container_name} is already up to date."}

        config = ContainerConfigExtractor(container).extract(strip_stale_compose=True)
        original_networks = container.attrs.get('NetworkSettings', {}).get('Networks', {})
        backup_name = self._generate_backup_name(container_name)

        result = self._perform_update(container, backup_name, image_name, config, original_networks)

        if result["status"] == "success" and dependent_containers:
            failed_recreates = []
            new_container = self._get_container(container_name)
            new_container_id = new_container.id

            for dep_container in dependent_containers:
                logger.info(f"[{self.server_name}] Recreating dependent: {dep_container.name}")
                if not self._recreate_container(dep_container, new_container_id):
                    failed_recreates.append(dep_container.name)

            if failed_recreates:
                result["message"] += f" Warning: Failed to recreate dependent containers: {', '.join(failed_recreates)}"
            else:
                result["message"] += f" Successfully recreated {len(dependent_containers)} dependent container(s)."

        return result
    
    def _get_container(self, container_name: str):
        try:
            return self.client.containers.get(container_name)
        except docker.errors.NotFound:
            raise ContainerUpdateError(f"Container '{container_name}' not found.")
        except Exception as e:
            raise ContainerUpdateError(f"Error accessing container '{container_name}': {e}")
   
    def _get_image_info(self, container) -> Tuple[str, str]:
        image_name = container.attrs.get('Config', {}).get('Image')
        container_image_id = container.attrs.get('Image', '')

        if not image_name:
            raise ContainerUpdateError("Could not determine image name for the container.")

        base_name, current_tag = self.update_checker._parse_image_name(image_name)
        resolved_tag = self.update_checker._resolve_floating_tag(current_tag)

        if resolved_tag != current_tag:
            resolved_image_name = f"{base_name}:{resolved_tag}"
            logger.info(f"[{self.server_name}] Resolved floating tag: {current_tag} → {resolved_tag}")
            logger.info(f"[{self.server_name}] Will use image: {resolved_image_name}")
            return resolved_image_name, container_image_id

        logger.info(f"[{self.server_name}] Container image: {image_name}")
        logger.debug(f"[{self.server_name}] Current image ID: {container_image_id[:12]}...")

        return image_name, container_image_id
    
    def _pull_image(self, image_name: str):
        logger.info(f"[{self.server_name}] Pulling latest image: {image_name}")
        try:
            new_image = self.client.images.pull(image_name)
            logger.info(f"[{self.server_name}] Successfully pulled: {new_image.short_id}")
        except Exception as e:
            raise ContainerUpdateError(f"Failed to pull image '{image_name}': {e}")
    
    def _has_updates(self, image_name: str, container_image_id: str) -> bool:
        try:
            local_image = self.client.images.get(image_name)
            return container_image_id != local_image.id
        except Exception:
            return True
    
    def _generate_backup_name(self, container_name: str) -> str:
        timestamp = int(time.time())
        backup_name = f"{container_name}-backup-{timestamp}"
        
        counter = 1
        while True:
            try:
                self.client.containers.get(backup_name)
                backup_name = f"{container_name}-backup-{timestamp}-{counter}"
                counter += 1
            except docker.errors.NotFound:
                break
        
        return backup_name
    
    def _recreate_container(self, container, new_network_container_id=None) -> bool:
        logger.info(f"[{self.server_name}] Recreating dependent container: {container.name}")
        try:
            current_image = container.image.tags[0] if container.image.tags else container.attrs.get('Config', {}).get('Image', '')
            config = ContainerConfigExtractor(container).extract()
            networks = container.attrs.get('NetworkSettings', {}).get('Networks', {})

            if new_network_container_id and config.get('network_mode', '').startswith('container:'):
                old_network_mode = config['network_mode']
                config['network_mode'] = f'container:{new_network_container_id}'
                logger.info(f"[{self.server_name}] Updated network_mode from '{old_network_mode}' to '{config['network_mode']}'")

            temp_name = f"{container.name}-temp-{int(time.time())}"

            self._stop_container(container)
            container.rename(temp_name)

            try:
                new_container = self.client.containers.create(current_image, **config)
                if networks:
                    self._connect_networks(new_container, networks)
                new_container.start()

                time.sleep(2)
                new_container.reload()
                if new_container.status != 'running':
                    raise Exception(f"Container failed to start (status: {new_container.status})")

                temp_container = self.client.containers.get(temp_name)
                temp_container.remove(force=True)

                logger.info(f"[{self.server_name}] Successfully recreated: {container.name}")
                return True

            except Exception as e:
                logger.error(f"[{self.server_name}] Recreate failed, restoring: {e}")
                try:
                    new_container.remove(force=True)
                except:
                    pass
                temp_container = self.client.containers.get(temp_name)
                temp_container.rename(container.name)
                temp_container.start()
                return False

        except Exception as e:
            logger.error(f"[{self.server_name}] Failed to recreate {container.name}: {e}")
            return False
    
    def _perform_update(self, container, backup_name: str, image_name: str,
                        config: Dict[str, Any], networks: Dict[str, Any]) -> Dict[str, Any]:
        # Preserve image name (not just ID) for proper rollback
        old_image = None
        if container.image:
            if container.image.tags:
                old_image = container.image.tags[0]  # Use the tag name
            else:
                old_image = container.image.id  # Fallback to ID if no tags
        original_name = container.name
        container_id = container.id

        try:
            self._stop_container(container)

            # Remove the old container to release ports
            logger.info(f"[{self.server_name}] Removing old container to release ports")

            # Try to remove, handle "already in progress" gracefully
            try:
                container.remove(force=True)
            except docker.errors.APIError as e:
                if "already in progress" in str(e):
                    logger.info(f"[{self.server_name}] Container removal already in progress, waiting...")
                else:
                    raise

            # Wait for container removal to complete fully
            self._wait_for_removal(container_id)

            # Create and start the new container
            new_container = self._create_and_start(image_name, config, networks)

            success_msg = f"Container '{original_name}' updated successfully to latest image."
            logger.info(f"[{self.server_name}] Successfully updated: {original_name}")
            return {"status": "success", "message": success_msg}

        except Exception as e:
            # Before invoking recovery, check if the container actually exists and is running
            # The update may have succeeded even if we caught an exception
            try:
                existing = self.client.containers.get(original_name)
                existing.reload()
                if existing.status == 'running':
                    # Container exists and is running - update likely succeeded
                    logger.warning(f"[{self.server_name}] Exception occurred but container is running: {e}")
                    return {"status": "success", "message": f"Container '{original_name}' updated successfully."}
            except docker.errors.NotFound:
                pass  # Container doesn't exist, proceed with recovery

            # Container doesn't exist or isn't running - try to restore
            self._handle_update_failure(e, old_image, config, networks, original_name)

    def _wait_for_removal(self, container_id: str, timeout: int = 15):
        """Wait for a container to be fully removed."""
        for attempt in range(timeout):
            time.sleep(1)
            try:
                self.client.containers.get(container_id)
                logger.debug(f"[{self.server_name}] Waiting for container removal... (attempt {attempt+1})")
            except docker.errors.NotFound:
                logger.info(f"[{self.server_name}] Container removed successfully")
                return
        raise ContainerUpdateError(f"Container removal timed out after {timeout} seconds")
    
    def _stop_container(self, container):
        logger.info(f"[{self.server_name}] Stopping: {container.name}")
        try:
            container.stop(timeout=self.timeouts['stop'])
            logger.info(f"[{self.server_name}] Container stopped")
        except Exception as e:
            logger.warning(f"[{self.server_name}] Graceful stop failed: {e}")
            try:
                container.kill()
                logger.info(f"[{self.server_name}] Container killed")
            except Exception as kill_error:
                logger.error(f"[{self.server_name}] Kill failed: {kill_error}")
                raise ContainerUpdateError(f"Failed to stop container: {e}")
    
    def _rename_to_backup(self, container, backup_name: str):
        logger.info(f"[{self.server_name}] Renaming to: {backup_name}")
        try:
            container.rename(backup_name)
            return container
        except Exception as e:
            try:
                container.start()
            except:
                pass
            raise ContainerUpdateError(f"Failed to rename container: {e}")
    
    def _create_and_start(self, image_name: str, config: Dict[str, Any], networks: Dict[str, Any]):
        logger.info(f"[{self.server_name}] Creating new container: {config['name']}")
        
        clean_config = {k: v for k, v in config.items() if v is not None}
        for key in ['environment', 'volumes', 'cap_add', 'cap_drop', 'devices', 'security_opt']:
            if key in clean_config and not clean_config[key]:
                del clean_config[key]
        
        try:
            new_container = self.client.containers.create(image_name, **clean_config)
        except Exception as e:
            logger.error(f"Failed to create with config: {clean_config}")
            raise ContainerUpdateError(f"Failed to create new container: {e}")
        
        if networks:
            self._connect_networks(new_container, networks)
        
        logger.info(f"[{self.server_name}] Starting new container")
        new_container.start()
        
        logger.info(f"[{self.server_name}] Verifying container started...")
        time.sleep(2)
        try:
            new_container.reload()
            if new_container.status != 'running':
                raise ContainerUpdateError(f"Container failed to start properly (status: {new_container.status})")
        except Exception as e:
            if isinstance(e, ContainerUpdateError):
                raise
            logger.warning(f"[{self.server_name}] Could not verify status: {e}")

        
        logger.info(f"[{self.server_name}] Container running successfully")
        return new_container
    
    def _connect_networks(self, container, networks: Dict[str, Any]):
        network_mode = container.attrs.get('HostConfig', {}).get('NetworkMode', '')
        
        if network_mode and network_mode.startswith('container:'):
            logger.info(f"Using network mode '{network_mode}', skipping network connections")
            return
        
        logger.info(f"[{self.server_name}] Connecting to networks")
        for network_name, network_config in networks.items():
            if network_name == 'bridge':
                continue
            
            try:
                network = self.client.networks.get(network_name)
                connect_config = {}
                if network_config.get('IPAddress'):
                    connect_config['ipv4_address'] = network_config['IPAddress']
                if network_config.get('Aliases'):
                    connect_config['aliases'] = network_config['Aliases']
                
                network.connect(container, **connect_config)
                logger.info(f"Connected to network: {network_name}")
            except Exception as e:
                logger.warning(f"Failed to connect to {network_name}: {e}")
    
    def _cleanup_backup(self, backup_container, backup_name: str):
        if not backup_container:
            return
        
        try:
            logger.info(f"[{self.server_name}] Removing backup: {backup_name}")
            backup_container.remove(force=True)
            logger.info(f"[{self.server_name}] Backup removed")
        except Exception as e:
            logger.warning(f"[{self.server_name}] Could not remove backup {backup_name}: {e}")
    
    def _handle_failure(self, error: Exception, backup_container, backup_name: str, 
                       new_container, original_name: str):
        logger.error(f"[{self.server_name}] Update failed: {error}")
        
        if new_container:
            try:
                new_container.remove(force=True)
                logger.info(f"[{self.server_name}] Cleaned up failed container")
            except Exception as cleanup_error:
                logger.warning(f"[{self.server_name}] Failed to cleanup: {cleanup_error}")
        
        if backup_container:
            try:
                logger.info(f"[{self.server_name}] Restoring original container")
                
                try:
                    temp = self.client.containers.get(original_name)
                    temp.remove(force=True)
                except docker.errors.NotFound:
                    pass
                
                backup_container.rename(original_name)
                backup_container.start()
                logger.info(f"[{self.server_name}] Original container restored")
                
            except Exception as restore_error:
                logger.error(f"[{self.server_name}] Failed to restore: {restore_error}")
                raise ContainerUpdateError(
                    f"Update failed: {error}. CRITICAL: Failed to restore original container: {restore_error}. "
                    f"Manual intervention required for '{backup_name}'"
                )
        
        raise ContainerUpdateError(f"Update failed: {error}. Original container restored.")

    def _handle_update_failure(self, error: Exception, old_image: str,
                               config: Dict[str, Any], networks: Dict[str, Any],
                               original_name: str):
        """Handle update failure by recreating container from old image."""
        logger.error(f"[{self.server_name}] Update failed: {error}")

        # Try to clean up any partial container with the original name
        try:
            existing = self.client.containers.get(original_name)
            if existing.status != 'running':
                logger.info(f"[{self.server_name}] Removing non-running container for recovery")
                existing.remove(force=True)
                self._wait_for_removal(existing.id, timeout=10)
        except docker.errors.NotFound:
            pass  # No container to clean up
        except Exception as cleanup_error:
            logger.warning(f"[{self.server_name}] Cleanup failed: {cleanup_error}")

        # Try to restore from the old image
        if old_image:
            try:
                logger.info(f"[{self.server_name}] Restoring container from old image: {old_image}")

                # Recreate the container using the old image
                restored = self.client.containers.create(old_image, **config)

                if networks:
                    self._connect_networks(restored, networks)

                restored.start()
                logger.info(f"[{self.server_name}] Original container restored from old image")
                raise ContainerUpdateError(f"Update failed: {error}. Original container restored.")

            except ContainerUpdateError:
                raise
            except Exception as restore_error:
                logger.error(f"[{self.server_name}] Failed to restore: {restore_error}")
                raise ContainerUpdateError(
                    f"Update failed: {error}. CRITICAL: Failed to restore original container: {restore_error}. "
                    f"Manual intervention required for '{original_name}'"
                )

        raise ContainerUpdateError(f"Update failed: {error}. Could not restore original container.")


def update_container(client: docker.DockerClient, server_name: str,
                     container_name: str, force: bool = False, new_image: str = None) -> Dict[str, Any]:
    with ContainerUpdater(client, server_name) as updater:
        return updater.update(container_name, force, new_image)