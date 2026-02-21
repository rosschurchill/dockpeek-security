import re
import logging
from flask import current_app, request, has_request_context
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from .docker_utils import discover_docker_clients, get_container_status_with_exit_code, _get_link_hostname
from .update import update_checker
from .trivy_utils import trivy_client
from .version_checker import version_checker

logger = logging.getLogger(__name__)


def get_version_info(image: str) -> dict:
    """Get cached version info for an image. Never blocks for network requests."""
    try:
        # Only return cached data - never make network requests during page load
        result = version_checker.get_cached_version(image)
        if result and result.is_newer:
            return {
                'newer_version_available': True,
                'latest_version': result.tag
            }
        return {
            'newer_version_available': False,
            'latest_version': None
        }
    except Exception as e:
        logger.debug(f"Version check failed for {image}: {e}")
        return {
            'newer_version_available': False,
            'latest_version': None
        }


def parse_comma_separated(value):
    if not value:
        return []
    try:
        return [item.strip() for item in value.split(',') if item.strip()]
    except:
        return []


def extract_traefik_routes(labels, traefik_enabled):
    if not traefik_enabled or labels.get('traefik.enable', '').lower() == 'false':
        return []
    
    routes = []
    for key, value in labels.items():
        if key.startswith('traefik.http.routers.') and key.endswith('.rule'):
            router_name = key.split('.')[3]
            host_matches = re.findall(r'Host\(`([^`]+)`\)', value)
            
            for host_ in host_matches:
                tls_key = f'traefik.http.routers.{router_name}.tls'
                is_tls = labels.get(tls_key, '').lower() == 'true'
                
                entrypoints_key = f'traefik.http.routers.{router_name}.entrypoints'
                entrypoints = labels.get(entrypoints_key, '')
                
                is_https_entrypoint = False
                if entrypoints:
                    entrypoint_list = [ep.strip().lower() for ep in entrypoints.split(',')]
                    is_https_entrypoint = any(
                        any(key in ep for key in ("https", "443", "secure", "ssl", "tls"))
                        for ep in entrypoint_list
                    )
                
                protocol = 'https' if is_tls or is_https_entrypoint else 'http'
                url = f"{protocol}://{host_}"
                
                path_match = re.search(r'PathPrefix\(`([^`]+)`\)', value)
                if path_match:
                    url += path_match.group(1)
                
                routes.append({
                    'router': router_name,
                    'url': url,
                    'rule': value,
                    'host': host_
                })
    
    return routes


def should_use_https(port_str, container_port, https_ports_list):
    return (
        container_port == "443/tcp" or
        port_str == "443" or
        port_str.endswith("443") or
        port_str in https_ports_list
    )


def create_port_link(port, https_ports_list, link_hostname, container_port=""):
    is_https = should_use_https(port, container_port, https_ports_list)
    protocol = "https" if is_https else "http"
    
    if port == "443":
        return f"{protocol}://{link_hostname}"
    else:
        return f"{protocol}://{link_hostname}:{port}"


def build_port_map(published_ports, custom_ports_list, https_ports_list, public_hostname, host_ip, is_docker_host, request_hostname=None):
    port_map = []

    for container_port, host_port, protocol in published_ports:
        link_hostname = _get_link_hostname(public_hostname, host_ip, is_docker_host, request_hostname)
        link = create_port_link(host_port, https_ports_list, link_hostname, container_port)

        port_map.append({
            'container_port': container_port,
            'host_port': host_port,
            'link': link,
            'is_custom': False
        })

    if custom_ports_list:
        link_hostname = _get_link_hostname(public_hostname, None, is_docker_host, request_hostname)
        for port in custom_ports_list:
            link = create_port_link(port, https_ports_list, link_hostname)
            port_map.append({
                'container_port': '',
                'host_port': port,
                'link': link,
                'is_custom': True
            })

    return port_map


def extract_swarm_service_ports(service_attrs):
    published_ports = []
    endpoint = service_attrs.get('Endpoint', {})
    ports = endpoint.get('Ports', [])
    
    for p in ports:
        host_port = str(p.get('PublishedPort'))
        container_port = str(p.get('TargetPort'))
        protocol = p.get('Protocol', 'tcp')
        published_ports.append((f"{container_port}/{protocol}", host_port, protocol))
    
    return published_ports


def extract_container_ports(container_attrs):
    published_ports = []
    ports = container_attrs['NetworkSettings']['Ports']
    
    if ports:
        for container_port, mappings in ports.items():
            if mappings:
                m = mappings[0]
                host_port = m['HostPort']
                host_ip = m.get('HostIp', '0.0.0.0')
                published_ports.append((container_port, host_port, host_ip))
    
    return published_ports


def extract_orchestration_labels(labels: dict) -> dict:
    """Extract dockpeek.* orchestration labels from container labels."""
    if not labels:
        return {}
    return {
        'role': labels.get('dockpeek.role'),
        'anchor': labels.get('dockpeek.anchor'),
        'anchor_type': labels.get('dockpeek.anchor-type'),
        'stack_override': labels.get('dockpeek.stack'),
        'hidden': labels.get('dockpeek.hide', '').lower() == 'true',
        'update_action': labels.get('dockpeek.update.action'),
        'update_order': labels.get('dockpeek.update.order'),
        'stop_before_anchor': labels.get('dockpeek.update.stop-before-anchor', '').lower() == 'true',
    }


def extract_labels_data(labels, tags_enable):
    stack_name = labels.get('com.docker.compose.project', '') or labels.get('com.docker.stack.namespace', '')
    source_url = labels.get('org.opencontainers.image.source') or labels.get('org.opencontainers.image.url', '')
    custom_url = labels.get('dockpeek.link', '')
    custom_ports = labels.get('dockpeek.ports', '') or labels.get('dockpeek.port', '')
    custom_tags = labels.get('dockpeek.tags', '') or labels.get('dockpeek.tag', '')
    https_ports = labels.get('dockpeek.https', '')
    port_range_grouping = labels.get('dockpeek.port-range-grouping', '')
    security_skip = labels.get('dockpeek.security.skip', '').lower() == 'true'

    tags = []
    if tags_enable and custom_tags:
        tags = parse_comma_separated(custom_tags)

    return {
        'stack_name': stack_name,
        'source_url': source_url,
        'custom_url': custom_url,
        'custom_ports_list': parse_comma_separated(custom_ports),
        'https_ports_list': parse_comma_separated(https_ports),
        'port_range_grouping': port_range_grouping.lower() if port_range_grouping else None,
        'tags': tags,
        'security_skip': security_skip
    }


def get_or_check_update(cache_key, client, container_or_service, server_name, image_name, is_swarm):
    cached_update, is_cache_valid = update_checker.get_cached_result(cache_key)

    if cached_update is not None and is_cache_valid:
        return cached_update

    if is_swarm:
        return False
    else:
        return update_checker.check_local_image_updates(client, container_or_service, server_name)


def get_vulnerability_summary(client, image_name):
    """Get cached vulnerability summary for an image."""
    if not trivy_client.is_enabled:
        return None

    try:
        image_digest = trivy_client.get_image_digest(client, image_name)
        if image_digest:
            cached = trivy_client.get_cached_result(image_digest)
            if cached:
                if cached.error:
                    return {'scan_status': 'failed', 'error': cached.error}
                return {
                    'critical': cached.summary.critical,
                    'high': cached.summary.high,
                    'medium': cached.summary.medium,
                    'low': cached.summary.low,
                    'total': cached.summary.total,
                    'scan_timestamp': cached.scan_timestamp.isoformat(),
                    'scan_status': 'scanned'
                }
        return {'scan_status': 'not_scanned'}
    except Exception as e:
        logger.debug(f"Error getting vulnerability summary for {image_name}: {e}")
        return {'scan_status': 'error'}


def extract_network_info(container_attrs):
    """Extract network names and IP addresses from container attributes."""
    networks = container_attrs.get('NetworkSettings', {}).get('Networks', {})
    network_names = []
    ip_addresses = {}

    for network_name, network_config in networks.items():
        network_names.append(network_name)
        ip = network_config.get('IPAddress', '')
        if ip:
            ip_addresses[network_name] = ip

    return network_names, ip_addresses


def process_swarm_service(service, tasks_by_service, client, server_name, public_hostname, is_docker_host, traefik_enabled, tags_enable, port_range_grouping_enabled, request_hostname=None):
    try:
        s_attrs = service.attrs
        spec = s_attrs.get('Spec', {})
        labels = spec.get('Labels', {}) or {}
        image_name = spec.get('TaskTemplate', {}).get('ContainerSpec', {}).get('Image', 'unknown')

        labels_data = extract_labels_data(labels, tags_enable)
        traefik_routes = extract_traefik_routes(labels, traefik_enabled)
        published_ports = extract_swarm_service_ports(s_attrs)
        port_map = build_port_map(
            published_ports,
            labels_data['custom_ports_list'],
            labels_data['https_ports_list'],
            public_hostname,
            None,
            is_docker_host,
            request_hostname
        )

        # Determine if port range grouping should be enabled for this container
        container_port_range_grouping = labels_data['port_range_grouping']
        if container_port_range_grouping is None:
            # Use global setting if not specified per container
            port_range_grouping = port_range_grouping_enabled
        else:
            # Use per-container setting
            port_range_grouping = container_port_range_grouping == 'true'

        service_tasks = tasks_by_service.get(service.id, [])
        running = sum(1 for t in service_tasks if t['Status']['State'] == 'running')
        total = len(service_tasks)
        status = f"running ({running}/{total})" if total else "no-tasks"

        cache_key = update_checker.get_cache_key(server_name, service.name, image_name)
        update_available = get_or_check_update(cache_key, client, service, server_name, image_name, True)

        container_info = {
            'server': server_name,
            'name': spec.get('Name', service.name),
            'container_id': service.id[:12],
            'status': status,
            'exit_code': None,
            'image': image_name,
            'stack': labels_data['stack_name'],
            'source_url': labels_data['source_url'],
            'custom_url': labels_data['custom_url'],
            'ports': port_map,
            'traefik_routes': traefik_routes,
            'tags': labels_data['tags'],
            'update_available': update_available,
            'port_range_grouping': port_range_grouping
        }

        return container_info
    except Exception:
        return {
            'server': server_name,
            'name': getattr(service, 'name', 'unknown'),
            'status': 'swarm-error',
            'image': 'error-loading',
            'ports': []
        }

def process_container(container, client, server_name, public_hostname, is_docker_host, traefik_enabled, tags_enable, port_range_grouping_enabled, request_hostname=None):
    try:
        original_image = container.attrs.get('Config', {}).get('Image', '')
        if original_image:
            image_name = original_image
        else:
            if hasattr(container, 'image') and container.image:
                if hasattr(container.image, 'tags') and container.image.tags:
                    image_name = container.image.tags[0]
                else:
                    image_name = container.image.id[:12] if hasattr(container.image, 'id') else "unknown"

        container_status, exit_code = get_container_status_with_exit_code(container)
        start_time = container.attrs.get('State', {}).get('StartedAt', '')

        labels = container.attrs.get('Config', {}).get('Labels', {}) or {}
        labels_data = extract_labels_data(labels, tags_enable)
        orchestration = extract_orchestration_labels(labels)
        traefik_routes = extract_traefik_routes(labels, traefik_enabled)

        published_ports_data = extract_container_ports(container.attrs)
        published_ports = [(cp, hp, None) for cp, hp, hi in published_ports_data]
        host_ips = {cp: hi for cp, hp, hi in published_ports_data}

        port_map = []
        for container_port, host_port, _ in published_ports:
            host_ip = host_ips.get(container_port, '0.0.0.0')
            link_hostname = _get_link_hostname(public_hostname, host_ip, is_docker_host, request_hostname)
            link = create_port_link(host_port, labels_data['https_ports_list'], link_hostname, container_port)
            port_map.append({
                'container_port': container_port,
                'host_port': host_port,
                'link': link,
                'is_custom': False
            })

        if labels_data['custom_ports_list']:
            link_hostname = _get_link_hostname(public_hostname, None, is_docker_host, request_hostname)
            for port in labels_data['custom_ports_list']:
                link = create_port_link(port, labels_data['https_ports_list'], link_hostname)
                port_map.append({
                    'container_port': '',
                    'host_port': port,
                    'link': link,
                    'is_custom': True
                })

        # Determine if port range grouping should be enabled for this container
        container_port_range_grouping = labels_data['port_range_grouping']
        if container_port_range_grouping is None:
            # Use global setting if not specified per container
            port_range_grouping = port_range_grouping_enabled
        else:
            # Use per-container setting
            port_range_grouping = container_port_range_grouping == 'true'

        cache_key = update_checker.get_cache_key(server_name, container.name, image_name)
        update_available = get_or_check_update(cache_key, client, container, server_name, image_name, False)

        # Get vulnerability summary from cache (unless security scanning is skipped)
        security_skip = labels_data.get('security_skip', False)
        if security_skip:
            vulnerability_summary = {'scan_status': 'skipped'}
        else:
            vulnerability_summary = get_vulnerability_summary(client, image_name)

        # Extract network information
        networks, ip_addresses = extract_network_info(container.attrs)

        # Get cached version info (1 hour cache)
        version_info = get_version_info(image_name)

        # Apply stack override from orchestration labels
        stack = orchestration.get('stack_override') or labels_data['stack_name']

        container_info = {
            'server': server_name,
            'name': container.name,
            'container_id': container.id[:12],
            'status': container_status,
            'started_at': start_time,
            'exit_code': exit_code,
            'image': image_name,
            'stack': stack,
            'source_url': labels_data['source_url'],
            'custom_url': labels_data['custom_url'],
            'ports': port_map,
            'traefik_routes': traefik_routes,
            'tags': labels_data['tags'],
            'update_available': update_available,
            'port_range_grouping': port_range_grouping,
            'vulnerability_summary': vulnerability_summary,
            'networks': networks,
            'ip_addresses': ip_addresses,
            'security_skip': security_skip,
            'newer_version_available': version_info['newer_version_available'],
            'latest_version': version_info['latest_version'],
            'orchestration': orchestration
        }

        return container_info
    except Exception as e:
        logger.warning(f"Error processing container {getattr(container, 'name', 'unknown')}: {e}")
        return {
            'server': server_name,
            'name': getattr(container, 'name', 'unknown'),
            'status': 'error',
            'image': 'error-loading',
            'ports': []
        }
    
def process_single_host_data(host, traefik_enabled, tags_enable, port_range_grouping_enabled, request_hostname=None):
    if host['status'] == 'inactive':
        return []

    container_data = []

    try:
        server_name = host["name"]
        client = host["client"]
        public_hostname = host["public_hostname"]
        is_docker_host = host["is_docker_host"]

        try:
            info = client.info()
            is_swarm = info.get('Swarm', {}).get('LocalNodeState', '').lower() == 'active'
        except Exception:
            is_swarm = False

        if is_swarm:
            try:
                services = client.services.list()
                tasks = client.api.tasks()

                tasks_by_service = {}
                for t in tasks:
                    sid = t['ServiceID']
                    tasks_by_service.setdefault(sid, []).append(t)

                for service in services:
                    container_info = process_swarm_service(
                        service, tasks_by_service, client, server_name,
                        public_hostname, is_docker_host, traefik_enabled, tags_enable, port_range_grouping_enabled,
                        request_hostname
                    )
                    container_data.append(container_info)
            except Exception as swarm_error:
                logger.error(f"Swarm error on {server_name}: {swarm_error}")
                container_data.append({
                    'server': server_name,
                    'name': 'unknown',
                    'status': 'swarm-error',
                    'image': 'error-loading',
                    'ports': []
                })
            return container_data

        try:
            containers = client.containers.list(all=True)
        except Exception as list_error:
            logger.error(f"Failed to list containers on {server_name}: {list_error}")
            return [{
                'server': server_name,
                'name': 'error',
                'status': 'list-error',
                'image': 'error-loading',
                'ports': []
            }]

        for container in containers:
            try:
                container_info = process_container(
                    container, client, server_name, public_hostname,
                    is_docker_host, traefik_enabled, tags_enable, port_range_grouping_enabled,
                    request_hostname
                )
                # Skip containers marked as hidden via orchestration labels
                if container_info.get('orchestration', {}).get('hidden'):
                    continue
                container_data.append(container_info)
            except Exception as container_error:
                logger.warning(f"Error processing container {getattr(container, 'name', 'unknown')} on {server_name}: {container_error}")
                container_data.append({
                    'server': server_name,
                    'name': getattr(container, 'name', 'unknown'),
                    'container_id': container.id[:12],
                    'status': 'processing-error',
                    'image': 'error-loading',
                    'ports': []
                })

        # Second pass: populate dependents list on anchor containers
        for anchor_info in container_data:
            if anchor_info.get('orchestration', {}).get('role') == 'anchor':
                anchor_name = anchor_info['name']
                dependents = [
                    c['name'] for c in container_data
                    if c.get('orchestration', {}).get('anchor') == anchor_name
                ]
                anchor_info['orchestration']['dependents'] = dependents

    except Exception as e:
        logger.error(f"Error processing host {host.get('name', 'unknown')}: {e}")
        return [{
            'server': host.get('name', 'unknown'),
            'name': 'error',
            'status': 'host-error',
            'image': 'error-loading',
            'ports': []
        }]

    return container_data

def get_all_data():
    servers = discover_docker_clients()

    TRAEFIK_ENABLE = current_app.config['TRAEFIK_ENABLE']
    TAGS_ENABLE = current_app.config['TAGS_ENABLE']
    PORT_RANGE_GROUPING = current_app.config['PORT_RANGE_GROUPING']
    PORT_RANGE_THRESHOLD = current_app.config['PORT_RANGE_THRESHOLD']

    request_hostname = None
    if has_request_context():
        try:
            request_hostname = request.host.split(":")[0]
        except Exception:
            pass

    if not servers:
        return {"servers": [], "containers": [], "swarm_servers": []}

    all_container_data = []
    swarm_servers = []
    server_list_for_json = [{"name": s["name"], "status": s["status"], "order": s["order"], "url": s["url"]} for s in servers]

    HOST_PROCESSING_TIMEOUT = 30.0

    with ThreadPoolExecutor(max_workers=len(servers)) as executor:
        future_to_host = {
            executor.submit(process_single_host_data, host, TRAEFIK_ENABLE, TAGS_ENABLE, PORT_RANGE_GROUPING, request_hostname): host 
            for host in servers
        }

        for future in future_to_host:
            host = future_to_host[future]
            try:
                host_containers = future.result(timeout=HOST_PROCESSING_TIMEOUT)
                all_container_data.extend(host_containers)

                if host['status'] != 'inactive':
                    try:
                        client = host["client"]
                        info = client.info()
                        is_swarm = info.get('Swarm', {}).get('LocalNodeState', '').lower() == 'active'
                        if is_swarm:
                            swarm_servers.append(host["name"])
                    except:
                        pass

            except FuturesTimeoutError:
                logger.error(f"Timeout processing host {host['name']} after {HOST_PROCESSING_TIMEOUT}s")
                for s in server_list_for_json:
                    if s["name"] == host["name"]:
                        s["status"] = "inactive"
                        break
                all_container_data.append({
                    'server': host["name"],
                    'name': 'timeout',
                    'status': 'host-timeout',
                    'image': 'timeout-error',
                    'ports': []
                })
            except Exception as e:
                logger.error(f"Error processing host {host['name']}: {e}")
                for s in server_list_for_json:
                    if s["name"] == host["name"]:
                        s["status"] = "inactive"
                        break

    # Auto-scan unscanned containers in the background
    if trivy_client.is_enabled:
        docker_clients = {s["name"]: s.get("client") for s in servers if s.get("client")}
        trivy_client.queue_auto_scan(all_container_data, docker_clients)

    return {
        "servers": server_list_for_json,
        "containers": all_container_data,
        "traefik_enabled": TRAEFIK_ENABLE,
        "port_range_grouping_enabled": PORT_RANGE_GROUPING,
        "port_range_threshold": PORT_RANGE_THRESHOLD,
        "swarm_servers": swarm_servers,
        "trivy_enabled": trivy_client.is_enabled,
        "trivy_healthy": trivy_client.health_check() if trivy_client.is_enabled else False,
        "trivy_pending": trivy_client.get_pending_count() if trivy_client.is_enabled else 0
    }