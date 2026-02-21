import os
import re
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from urllib.parse import urlparse
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import docker
from docker.client import DockerClient
from flask import request, has_request_context
from threading import Lock
import time

logger = logging.getLogger(__name__)


class HostStatus(Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"


@dataclass
class DockerHostConfig:
    name: str
    url: str
    order: int
    public_hostname: Optional[str] = None
    is_docker_host: bool = True


@dataclass
class DockerHost:
    name: str
    client: Optional[DockerClient]
    url: str
    public_hostname: Optional[str]
    status: HostStatus
    is_docker_host: bool
    order: int
    
    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "client": self.client,
            "url": self.url,
            "public_hostname": self.public_hostname,
            "status": self.status.value,
            "is_docker_host": self.is_docker_host,
            "order": self.order
        }


class HostnameExtractor:
    LOCALHOST_ADDRESSES = {"127.0.0.1", "0.0.0.0", "localhost"}
    
    @classmethod
    def extract_from_url(cls, url: str, is_docker_host: bool) -> Optional[str]:
        if not url or url.startswith("unix://"):
            return None
        
        if url.startswith("tcp://"):
            hostname = cls._extract_via_urlparse(url)
            if hostname:
                return hostname
        
        return cls._extract_via_regex(url, is_docker_host)
    
    @classmethod
    def _extract_via_urlparse(cls, url: str) -> Optional[str]:
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            if hostname and cls._is_usable_hostname(hostname, True):
                return hostname
        except Exception as e:
            logger.debug(f"Failed to parse URL {url}: {e}")
        return None
    
    @classmethod
    def _extract_via_regex(cls, url: str, is_docker_host: bool) -> Optional[str]:
        try:
            match = re.search(r"(?:tcp://)?([^:]+)(?::\d+)?", url)
            if match:
                hostname = match.group(1)
                if cls._is_usable_hostname(hostname, is_docker_host):
                    return hostname
        except Exception as e:
            logger.debug(f"Failed to extract hostname from {url}: {e}")
        return None
    
    @classmethod
    def _is_usable_hostname(cls, hostname: str, is_docker_host: bool) -> bool:
        if hostname in cls.LOCALHOST_ADDRESSES:
            return False
        if is_docker_host and cls._is_internal_name(hostname):
            return False
        return True
    
    @classmethod
    def _is_internal_name(cls, hostname: str) -> bool:
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', hostname):
            return False
        if '.' in hostname:
            return False
        return True


class LinkHostnameResolver:
    @staticmethod
    def resolve(public_hostname: Optional[str], host_ip: Optional[str], 
                is_docker_host: bool, request_hostname: Optional[str] = None) -> str:
        if public_hostname:
            return public_hostname
        
        if host_ip and host_ip not in ['0.0.0.0', '127.0.0.1']:
            return host_ip
        
        if request_hostname:
            return request_hostname
        
        return "localhost"


class DockerClientFactory:
    def __init__(self, timeout: float = None, long_timeout: float = 60.0):
        from config import Config
        self.timeout = timeout if timeout is not None else Config.DOCKER_CONNECTION_TIMEOUT
        self.long_timeout = long_timeout
        
    def create_client(self, url: str, use_long_timeout: bool = False) -> DockerClient:
        timeout = self.long_timeout if use_long_timeout else self.timeout
        
        return DockerClient(
            base_url=url, 
            timeout=timeout,
            max_pool_size=20
        )

    
    def create_default_client(self) -> DockerClient:
        return docker.from_env(timeout=self.timeout)
    
    def test_connection(self, client: DockerClient) -> bool:
        try:
            client.ping()
            return True
        except Exception as e:
            logger.debug(f"Connection test failed: {e}")
            return False

    def get_host_name_from_api(self, client: DockerClient) -> Optional[str]:
        try:
            info = client.info()
            return info.get('Name')
        except Exception as e:
            logger.debug(f"Failed to get host name from Docker API: {e}")
            return None

class EnvironmentConfigParser:
    HOST_PATTERN = re.compile(r"^DOCKER_HOST_(\d+)_URL$")
    
    @classmethod
    def parse(cls) -> List[DockerHostConfig]:
        configs = []
        
        main_host = cls._parse_main_host()
        if main_host:
            configs.append(main_host)
        
        numbered_hosts = cls._parse_numbered_hosts()
        configs.extend(numbered_hosts)
        
        return configs
    
    @classmethod
    def _parse_main_host(cls) -> Optional[DockerHostConfig]:
        if "DOCKER_HOST" not in os.environ:
            return None
        
        host_url = os.environ["DOCKER_HOST"]
        host_name = os.environ.get("DOCKER_HOST_NAME", "").strip() or "default"
        public_hostname = (
            os.environ.get("DOCKER_HOST_PUBLIC_HOSTNAME") or 
            HostnameExtractor.extract_from_url(host_url, True)
        )
        
        return DockerHostConfig(
            name=host_name,
            url=host_url,
            order=0,
            public_hostname=public_hostname,
            is_docker_host=True
        )
    
    @classmethod
    def _parse_numbered_hosts(cls) -> List[DockerHostConfig]:
        configs = []
        host_vars = {k: v for k, v in os.environ.items() if cls.HOST_PATTERN.match(k)}
        
        for key, url in sorted(host_vars.items()):
            match = cls.HOST_PATTERN.match(key)
            if not match:
                continue
            
            num = match.group(1)
            name = os.environ.get(f"DOCKER_HOST_{num}_NAME", "").strip() or f"server{num}"
            public_hostname = (
                os.environ.get(f"DOCKER_HOST_{num}_PUBLIC_HOSTNAME") or
                HostnameExtractor.extract_from_url(url, False)
            )
            
            configs.append(DockerHostConfig(
                name=name,
                url=url,
                order=int(num),
                public_hostname=public_hostname,
                is_docker_host=False
            ))
        
        return configs


class DockerClientDiscovery:
    def __init__(self, client_factory: Optional[DockerClientFactory] = None, 
             discovery_timeout: float = 10.0):
        self.client_factory = client_factory or DockerClientFactory()
        self.discovery_timeout = discovery_timeout
        self._lock = Lock()
        self._cache = None
        self._cache_time = 0
        self._cache_ttl = 30
    
    def discover(self, use_cache: bool = True) -> List[DockerHost]:
        if use_cache:
            with self._lock:
                if self._cache and (time.time() - self._cache_time) < self._cache_ttl:
                    return self._cache
        
        hosts = self._perform_discovery()
        
        if use_cache:
            with self._lock:
                self._cache = hosts
                self._cache_time = time.time()
        
        return hosts
    
    def _perform_discovery(self) -> List[DockerHost]:
        configs = EnvironmentConfigParser.parse()
    
        if not configs:
            return [self._create_fallback_host()]
    
        hosts = []
        with ThreadPoolExecutor(max_workers=len(configs)) as executor:
            future_to_host = {executor.submit(self._create_host_from_config, config): config for config in configs}
            for future in as_completed(future_to_host):
                config = future_to_host[future]
                try:
                    host_result = future.result(timeout=self.discovery_timeout)
                    hosts.append(host_result)
                except TimeoutError:
                    logger.error(f"Timeout discovering host {config.name} after {self.discovery_timeout}s")
                    hosts.append(self._create_inactive_host(config))
                except Exception as e:
                    logger.error(f"Error processing host {config.name}: {e}")
                    hosts.append(self._create_inactive_host(config))
    
        hosts.sort(key=lambda h: h.order)
        return hosts
    
    
    def _create_host_from_config(self, config: DockerHostConfig) -> DockerHost:
        try:
            client = self.client_factory.create_client(config.url)

            if self.client_factory.test_connection(client):
                host_name = config.name
                if host_name in [f"server{config.order}", "default"] and config.order > 0:
                    api_name = self.client_factory.get_host_name_from_api(client)
                    if api_name:
                        host_name = api_name

                logger.debug(f"Connected to Docker host '{host_name}' at {config.url}")
                return DockerHost(
                    name=host_name,
                    client=client,
                    url=config.url,
                    public_hostname=config.public_hostname,
                    status=HostStatus.ACTIVE,
                    is_docker_host=config.is_docker_host,
                    order=config.order
                )
            else:
                logger.warning(f"Could not connect to Docker host '{config.name}' at {config.url}")
                return self._create_inactive_host(config)
        except Exception as e:
            logger.debug(f"Failed to create client for '{config.name}': {e}")
            return self._create_inactive_host(config)
    
    def _create_inactive_host(self, config: DockerHostConfig) -> DockerHost:
        return DockerHost(
            name=config.name,
            client=None,
            url=config.url,
            public_hostname=config.public_hostname,
            status=HostStatus.INACTIVE,
            is_docker_host=config.is_docker_host,
            order=config.order
        )
    
    def _create_fallback_host(self) -> DockerHost:
        fallback_name = os.environ.get("DOCKER_HOST_NAME", "").strip()
        public_hostname = os.environ.get("DOCKER_HOST_PUBLIC_HOSTNAME", "")
        url = "unix:///var/run/docker.sock"

        try:
            client = self.client_factory.create_default_client()

            if self.client_factory.test_connection(client):
                if not fallback_name:
                    api_name = self.client_factory.get_host_name_from_api(client)
                    fallback_name = api_name or "default"

                logger.debug(f"Connected to default Docker socket")
                return DockerHost(
                    name=fallback_name,
                    client=client,
                    url=url,
                    public_hostname=public_hostname,
                    status=HostStatus.ACTIVE,
                    is_docker_host=True,
                    order=0
                )
        except Exception as e:
            logger.warning(f"Could not connect to default Docker socket: {e}")

        return DockerHost(
            name=fallback_name or "default",
            client=None,
            url=url,
            public_hostname=public_hostname,
            status=HostStatus.INACTIVE,
            is_docker_host=True,
            order=0
        )
    
    def invalidate_cache(self):
        with self._lock:
            self._cache = None
            self._cache_time = 0


class ContainerStatusExtractor:
    @staticmethod
    def get_status_with_exit_code(container, timeout: float = 5.0) -> Tuple[str, Optional[int]]:
        try:
            import signal
            
            def timeout_handler(signum, frame):
                raise TimeoutError("Container attrs fetch timeout")
            
            if hasattr(signal, 'SIGALRM'):
                old_handler = signal.signal(signal.SIGALRM, timeout_handler)
                signal.alarm(int(timeout))
            
            try:
                base_status = container.status
                state = container.attrs.get('State', {})
                exit_code = state.get('ExitCode')
                
                if base_status in ['exited', 'dead']:
                    return base_status, exit_code
                
                if base_status in ['paused', 'restarting', 'removing', 'created']:
                    return base_status, None
                
                if base_status == 'running':
                    health = state.get('Health', {})
                    if health:
                        health_status = health.get('Status', '')
                        if health_status == 'healthy':
                            return 'healthy', None
                        if health_status == 'unhealthy':
                            return 'unhealthy', exit_code
                        if health_status == 'starting':
                            return 'starting', None
                    return 'running', None
                
                return base_status, None
            finally:
                if hasattr(signal, 'SIGALRM'):
                    signal.alarm(0)
                    signal.signal(signal.SIGALRM, old_handler)
                    
        except TimeoutError:
            logger.warning(f"Timeout getting status for container {getattr(container, 'name', 'unknown')}")
            return 'timeout', None
        except Exception as e:
            logger.warning(f"Error getting status for container {getattr(container, 'name', 'unknown')}: {e}")
            try:
                return container.status, None
            except:
                return 'error', None


_discovery_instance = DockerClientDiscovery()

def discover_docker_clients() -> List[Dict]:
    hosts = _discovery_instance.discover(use_cache=True)
    return [host.to_dict() for host in hosts]


def invalidate_docker_clients_cache():
    _discovery_instance.invalidate_cache()


def get_container_status_with_exit_code(container) -> Tuple[str, Optional[int]]:
    return ContainerStatusExtractor.get_status_with_exit_code(container)

def create_streaming_client(server_url: str) -> DockerClient:
    factory = DockerClientFactory(long_timeout=60)
    return factory.create_client(server_url, use_long_timeout=True)

def _get_link_hostname(public_hostname: Optional[str], host_ip: Optional[str], 
                       is_docker_host: bool, request_hostname: Optional[str] = None) -> str:
    return LinkHostnameResolver.resolve(public_hostname, host_ip, is_docker_host, request_hostname)
