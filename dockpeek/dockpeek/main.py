import json
from datetime import datetime
from functools import wraps

import docker
from flask import Blueprint, render_template, jsonify, request, current_app, make_response, Response
from flask_login import login_required, current_user

from .get_data import get_all_data
from .update_manager import update_container
from .docker_utils import discover_docker_clients, create_streaming_client, DockerClientFactory, get_container_status_with_exit_code
from .update import update_checker
from .logs_manager import get_container_logs, stream_container_logs, get_service_logs, stream_service_logs
from .trivy_utils import trivy_client
from .scan_history import scan_history_db
from .traefik_utils import traefik_client
from .version_checker import version_checker

# Optional ntfy notifications (graceful fallback if not configured)
try:
    from .notifications import ntfy_notifier
except ImportError:
    ntfy_notifier = None


main_bp = Blueprint('main', __name__)


def conditional_login_required(f):
    """Decorator that requires auth unless DISABLE_AUTH is set.

    Auth order:
    1. DISABLE_AUTH config flag — bypass everything.
    2. X-API-Key header — stateless token auth for MCP / programmatic access.
    3. Session-based Flask-Login auth.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_app.config.get('DISABLE_AUTH', False):
            return f(*args, **kwargs)

        # Check API key auth first (stateless, for MCP/programmatic access)
        api_key = request.headers.get('X-API-Key')
        if api_key:
            from .api_keys import api_key_db
            key_info = api_key_db.validate_key(api_key)
            if key_info:
                request.api_key_info = key_info
                return f(*args, **kwargs)
            return jsonify({"error": "Invalid or expired API key"}), 401

        # Fall back to session-based auth
        if not current_user.is_authenticated:
            return current_app.login_manager.unauthorized()
        return f(*args, **kwargs)
    return decorated_function

@main_bp.route("/")
@conditional_login_required
def index():
    version = current_app.config['APP_VERSION']
    return render_template("index.html", version=version)

@main_bp.route("/health")
def health():
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": current_app.config['APP_VERSION']
    }), 200

@main_bp.route("/config/registry-templates")
def get_registry_templates():
    """Expose CUSTOM_REGISTRY_TEMPLATES from config for frontend use."""
    from flask import current_app, jsonify
    return jsonify(current_app.config.get("CUSTOM_REGISTRY_TEMPLATES", {}))

@main_bp.route("/data")
@conditional_login_required
def data():
    response = jsonify(get_all_data())
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@main_bp.route("/check-updates", methods=["POST"])
@conditional_login_required
def check_updates():
    update_checker.start_check()
    request_data = request.get_json() or {}
    server_filter = request_data.get('server_filter', 'all')
    
    servers = discover_docker_clients()
    active_servers = [s for s in servers if s['status'] == 'active']
    
    if server_filter != 'all':
        active_servers = [s for s in active_servers if s['name'] == server_filter]
    
    updates = {}
    was_cancelled = False
    total_containers = 0
    processed_containers = 0
    
    for server in active_servers:
        try:
            containers = server['client'].containers.list(all=True)
            total_containers += len(containers)
        except Exception:
            pass    
    for server in active_servers:
        if update_checker.is_cancelled:
            was_cancelled = True
            break
            
        try:
            containers = server['client'].containers.list(all=True)
            for container in containers:
                if update_checker.is_cancelled:
                    was_cancelled = True
                    break
                
                processed_containers += 1
                key = f"{server['name']}:{container.name}"
                try:
                    update_available = update_checker.check_image_updates(
                        server['client'], container, server['name']
                    )
                    updates[key] = update_available
                except Exception as e:
                    updates[key] = False
                    current_app.logger.error(f"Error during update check for {key}: {e}")
                
                if update_checker.is_cancelled:
                    was_cancelled = True
                    break
                    
        except Exception as e:
            current_app.logger.error(f"Error accessing containers on {server['name']}: {e}")
        
        if was_cancelled:
            break

    return jsonify({
        "updates": updates, 
        "cancelled": was_cancelled,
        "progress": {
            "processed": processed_containers,
            "total": total_containers
        }
    })

@main_bp.route("/check-single-update", methods=["POST"])
@conditional_login_required
def check_single_update():
    update_checker.start_check()
    request_data = request.get_json() or {}
    server_name = request_data.get('server_name')
    container_name = request_data.get('container_name')
    
    if not server_name or not container_name:
        return jsonify({"error": "Missing server_name or container_name"}), 400
    
    if update_checker.is_cancelled:
        return jsonify({"cancelled": True}), 200
    
    servers = discover_docker_clients()
    server = next((s for s in servers if s['name'] == server_name and s['status'] == 'active'), None)
    
    if not server:
        return jsonify({"error": f"Server {server_name} not found or inactive"}), 404
    
    try:
        # Detect if this is a Swarm service
        is_swarm = False
        try:
            info = server['client'].info()
            is_swarm = info.get('Swarm', {}).get('LocalNodeState', '').lower() == 'active'
        except Exception:
            pass
        
        # Block update checks for Swarm
        if is_swarm:
            current_app.logger.info(
                f"[{server_name}] Container '{container_name}' is part of a Swarm service — update check skipped."
            )
            key = f"{server_name}:{container_name}"
            return jsonify({
                "key": key,
                "update_available": False,
                "server_name": server_name,
                "container_name": container_name,
                "cancelled": False
            }), 200
        
        container = server['client'].containers.get(container_name)
        
        if update_checker.is_cancelled:
            return jsonify({"cancelled": True}), 200
            
        update_available = update_checker.check_image_updates(
            server['client'], container, server_name
        )
        
        key = f"{server_name}:{container_name}" 
        return jsonify({
            "key": key,
            "update_available": update_available,
            "server_name": server_name,
            "container_name": container_name,
            "cancelled": update_checker.is_cancelled
        })
        
    except Exception as e:
        current_app.logger.error(f"Error checking update for {server_name}:{container_name}: {e}")
        return jsonify({"error": str(e)}), 500

@main_bp.route("/get-containers-list", methods=["POST"])  
@conditional_login_required
def get_containers_list():
    request_data = request.get_json() or {}
    server_filter = request_data.get('server_filter', 'all')
    
    servers = discover_docker_clients()
    active_servers = [s for s in servers if s['status'] == 'active']
    
    if server_filter != 'all':
        active_servers = [s for s in active_servers if s['name'] == server_filter]
    
    containers_list = []
    
    for server in active_servers:
        try:
            for container in server['client'].containers.list(all=True):
                containers_list.append({
                    "server_name": server['name'],
                    "container_name": container.name,
                    "key": f"{server['name']}:{container.name}",
                    "image": container.attrs.get('Config', {}).get('Image', ''),
                    "status": container.status
                })
        except Exception as e:
            current_app.logger.error(f"Error accessing containers on {server['name']}: {e}")
    
    return jsonify({
        "containers": containers_list,
        "total": len(containers_list)
    })

@main_bp.route("/update-check-status", methods=["GET"])
@conditional_login_required
def get_update_check_status():
    return jsonify({
        "is_cancelled": update_checker.is_cancelled,
        "cache_stats": update_checker.get_cache_stats()
    })

@main_bp.route("/cancel-updates", methods=["POST"])
@conditional_login_required
def cancel_updates():
    update_checker.cancel_check()
    current_app.logger.info("Cancellation request received.")
    return jsonify({"status": "cancellation_requested"})

@main_bp.route("/check-dependent-containers", methods=["POST"])
@conditional_login_required
def check_dependent_containers():
    data = request.get_json()
    server_name = data.get('server_name')
    container_name = data.get('container_name')

    if not server_name or not container_name:
        return jsonify({"error": "Missing server_name or container_name"}), 400

    servers = discover_docker_clients()
    server = next((s for s in servers if s['name'] == server_name and s['status'] == 'active'), None)
    
    if not server:
        return jsonify({"error": f"Server '{server_name}' not found or inactive"}), 404
    
    try:
        container = server['client'].containers.get(container_name)
        dependent = []
        all_containers = server['client'].containers.list(all=True)
        for other in all_containers:
            if other.id == container.id:
                continue
            network_mode = other.attrs.get('HostConfig', {}).get('NetworkMode', '')
            if network_mode in [f'container:{container.name}', f'container:{container.id}']:
                dependent.append(other.name)
        
        return jsonify({'dependent_containers': dependent}), 200
    except Exception as e:
        current_app.logger.error(f"Error checking dependent containers: {e}")
        return jsonify({'dependent_containers': [], 'error': str(e)}), 200
    
@main_bp.route("/update-container", methods=["POST"])
@conditional_login_required
def update_container_route():
    data = request.get_json()
    server_name = data.get('server_name')
    container_name = data.get('container_name')
    new_image = data.get('new_image')  # Optional: for version upgrades

    if not server_name or not container_name:
        return jsonify({"error": "Missing server_name or container_name"}), 400

    servers = discover_docker_clients()
    server = next((s for s in servers if s['name'] == server_name and s['status'] == 'active'), None)

    if not server:
        return jsonify({"error": f"Server '{server_name}' not found or inactive"}), 404

    try:
        result = update_container(server['client'], server_name, container_name, new_image=new_image)
        return jsonify(result), 200
    except Exception as e:
        if hasattr(e, 'html_message'):
            current_app.logger.error(f"Update error for {container_name}: {str(e)}")
            return jsonify({"error": e.html_message}), 500
        else:
            current_app.logger.error(f"Update error for {container_name}: {str(e)}")
            return jsonify({"error": str(e)}), 500


@main_bp.route("/api/repair-image-names", methods=["POST"])
@conditional_login_required
def repair_image_names():
    """Find and fix containers with SHA256 image names."""
    from .update_manager import ContainerConfigExtractor

    servers = discover_docker_clients()
    fixed = []
    errors = []

    for server in servers:
        if server['status'] != 'active':
            continue

        client = server['client']
        try:
            containers = client.containers.list(all=True)
            for container in containers:
                config_image = container.attrs.get('Config', {}).get('Image', '')

                # Check if image name is a SHA (starts with sha256: or is just hex)
                is_sha = config_image.startswith('sha256:') or (
                    len(config_image) == 12 and all(c in '0123456789abcdef' for c in config_image)
                )

                if is_sha and container.image and container.image.tags:
                    proper_name = container.image.tags[0]
                    current_app.logger.info(f"Repairing {container.name}: {config_image} -> {proper_name}")

                    try:
                        # Extract config and recreate with proper image name
                        extractor = ContainerConfigExtractor(container)
                        config = extractor.extract()

                        # Get networks
                        networks = {}
                        net_settings = container.attrs.get('NetworkSettings', {}).get('Networks', {})
                        for net_name, net_config in net_settings.items():
                            if net_name != 'bridge':
                                networks[net_name] = {'aliases': net_config.get('Aliases', [])}

                        # Stop and remove old container
                        container.stop(timeout=30)
                        container.remove(force=True)

                        # Wait for removal
                        import time
                        for _ in range(10):
                            time.sleep(0.5)
                            try:
                                client.containers.get(container.id)
                            except:
                                break

                        # Create new container with proper image name
                        new_container = client.containers.create(proper_name, **config)

                        # Connect networks
                        for net_name, net_opts in networks.items():
                            try:
                                network = client.networks.get(net_name)
                                network.connect(new_container, aliases=net_opts.get('aliases', []))
                            except Exception as e:
                                current_app.logger.warning(f"Failed to connect network {net_name}: {e}")

                        new_container.start()
                        fixed.append({
                            'container': container.name,
                            'old_image': config_image,
                            'new_image': proper_name
                        })

                    except Exception as e:
                        errors.append({
                            'container': container.name,
                            'error': str(e)
                        })

        except Exception as e:
            errors.append({'server': server['name'], 'error': str(e)})

    return jsonify({
        'fixed': fixed,
        'errors': errors,
        'message': f"Repaired {len(fixed)} containers"
    })


def parse_image_name(image_name):
    if ':' in image_name:
        base_name, tag = image_name.rsplit(':', 1)
    else:
        base_name, tag = image_name, 'latest'
    return base_name, tag

def get_image_creation_time(image):
    created_str = image.attrs.get('Created', '')
    if created_str:
        try:
            return datetime.fromisoformat(created_str.replace('Z', '+00:00'))
        except:
            pass
    return None

@main_bp.route("/get-prune-info", methods=["POST"])
@conditional_login_required
def get_prune_info():
    request_data = request.get_json() or {}
    server_name = request_data.get('server_name', 'all')
    
    servers = discover_docker_clients()
    active_servers = [s for s in servers if s['status'] == 'active']
    
    if server_name != 'all':
        active_servers = [s for s in active_servers if s['name'] == server_name]
    
    total_size = 0
    total_count = 0
    server_details = []
    
    for server in active_servers:
        try:
            all_images = server['client'].images.list()
            used_images = set()
            container_images_info = {}
            
            for container in server['client'].containers.list(all=True):
                image_id = container.image.id
                used_images.add(image_id)
                
                image_name = container.attrs.get('Config', {}).get('Image', '')
                if image_name:
                    base_name, tag = parse_image_name(image_name)
                    key = f"{base_name}:{tag}"
                    creation_time = get_image_creation_time(container.image)
                    
                    if key not in container_images_info or (creation_time and container_images_info[key]['created'] and creation_time > container_images_info[key]['created']):
                        container_images_info[key] = {
                            'id': image_id,
                            'created': creation_time
                        }
            
            unused_images = []
            unused_size = 0
            
            for image in all_images:
                if image.id not in used_images:
                    size = image.attrs.get('Size', 0)
                    
                    if image.tags:
                        tags = image.tags
                    else:
                        repo_tags = image.attrs.get('RepoTags', [])
                        if repo_tags and len(repo_tags) > 0:
                            tags = [repo_tags[0]]
                        else:
                            repo_digests = image.attrs.get('RepoDigests', [])
                            if repo_digests and len(repo_digests) > 0:
                                repo_name = repo_digests[0].split('@')[0]
                                tags = [f"{repo_name}:<none>"]
                            else:
                                tags = ["<none>:<none>"]
                    
                    pending_update = False
                    image_created = get_image_creation_time(image)
                    
                    for tag in tags:
                        if tag != "<none>:<none>":
                            if tag in container_images_info:
                                used_image_info = container_images_info[tag]
                                if image_created and used_image_info['created']:
                                    if image_created > used_image_info['created']:
                                        pending_update = True
                                        break
                    
                    unused_images.append({
                        'id': image.id,
                        'tags': tags,
                        'size': size,
                        'pending_update': pending_update
                    })
                    
                    if not pending_update:
                        unused_size += size
            
            if unused_images:
                count = sum(1 for img in unused_images if not img['pending_update'])
                total_count += count
                total_size += unused_size
                
                server_details.append({
                    'server': server['name'],
                    'count': count,
                    'size': unused_size,
                    'images': unused_images
                })
                
        except Exception as e:
            current_app.logger.error(f"Error getting prune info for {server['name']}: {e}")
    
    return jsonify({
        'total_count': total_count,
        'total_size': total_size,
        'servers': server_details
    })

@main_bp.route("/prune-images", methods=["POST"])
@conditional_login_required
def prune_images():
    request_data = request.get_json() or {}
    server_name = request_data.get('server_name', 'all')
    
    servers = discover_docker_clients()
    active_servers = [s for s in servers if s['status'] == 'active']
    
    if server_name != 'all':
        active_servers = [s for s in active_servers if s['name'] == server_name]
    
    total_size = 0
    total_count = 0
    server_results = []
    
    for server in active_servers:
        try:
            all_images = server['client'].images.list()
            used_images = set()
            container_images_info = {}
            
            for container in server['client'].containers.list(all=True):
                image_id = container.image.id
                used_images.add(image_id)
                
                image_name = container.attrs.get('Config', {}).get('Image', '')
                if image_name:
                    base_name, tag = parse_image_name(image_name)
                    key = f"{base_name}:{tag}"
                    creation_time = get_image_creation_time(container.image)
                    
                    if key not in container_images_info or (creation_time and container_images_info[key]['created'] and creation_time > container_images_info[key]['created']):
                        container_images_info[key] = {
                            'id': image_id,
                            'created': creation_time
                        }
            
            removed_count = 0
            removed_size = 0
            
            for image in all_images:
                if image.id not in used_images:
                    pending_update = False
                    image_created = get_image_creation_time(image)
                    
                    tags = image.tags if image.tags else []
                    for tag in tags:
                        if tag != "<none>:<none>":
                            if tag in container_images_info:
                                used_image_info = container_images_info[tag]
                                if image_created and used_image_info['created']:
                                    if image_created > used_image_info['created']:
                                        pending_update = True
                                        break
                    
                    if not pending_update:
                        try:
                            size = image.attrs.get('Size', 0)
                            long_client = docker.DockerClient(base_url=server['url'], timeout=60)
                            long_client.images.remove(image.id, force=True)
                            long_client.close()
                            removed_count += 1
                            removed_size += size
                        except Exception as e:
                            current_app.logger.warning(f"Could not remove image {image.id}: {e}")
            
            total_count += removed_count
            total_size += removed_size
            
            if removed_count > 0:
                server_results.append({
                    'server': server['name'],
                    'count': removed_count,
                    'size': removed_size
                })
                
            current_app.logger.info(f"Pruned {removed_count} images from {server['name']}, reclaimed {removed_size} bytes")
            
        except Exception as e:
            current_app.logger.error(f"Error pruning images on {server['name']}: {e}")
            return jsonify({"error": f"Failed to prune on {server['name']}: {str(e)}"}), 500
    
    return jsonify({
        'total_count': total_count,
        'total_size': total_size,
        'servers': server_results
    })

@main_bp.route("/get-container-logs", methods=["POST"])
@conditional_login_required
def get_logs():
    request_data = request.get_json() or {}
    server_name = request_data.get('server_name')
    container_name = request_data.get('container_name')
    tail = request_data.get('tail', 500)
    is_swarm = request_data.get('is_swarm', False)
    
    if not server_name or not container_name:
        return jsonify({"error": "Missing server_name or container_name"}), 400
    
    servers = discover_docker_clients()
    server = next((s for s in servers if s['name'] == server_name and s['status'] == 'active'), None)
    
    if not server:
        return jsonify({"error": f"Server {server_name} not found or inactive"}), 404
    
    if is_swarm:
        result = get_service_logs(
            server['client'], 
            container_name, 
            tail=tail,
            timestamps=True,
            follow=False
        )
    else:
        result = get_container_logs(
            server['client'], 
            container_name, 
            tail=tail,
            timestamps=True,
            follow=False
        )
    
    if result['success']:
        return jsonify(result), 200
    else:
        return jsonify(result), 500


@main_bp.route("/stream-container-logs", methods=["POST"])
@conditional_login_required
def stream_logs():
    import time
    import gevent
    from gevent.queue import Queue, Empty
    
    request_data = request.get_json() or {}
    server_name = request_data.get('server_name')
    container_name = request_data.get('container_name')
    tail = request_data.get('tail', 100)
    is_swarm = request_data.get('is_swarm', False)
    
    if not server_name or not container_name:
        return jsonify({"error": "Missing server_name or container_name"}), 400
    
    servers = discover_docker_clients()
    server = next((s for s in servers if s['name'] == server_name and s['status'] == 'active'), None)
    
    if not server:
        return jsonify({"error": f"Server {server_name} not found or inactive"}), 404
    
    stream_client = create_streaming_client(server['url'])
    logger = current_app.logger
    
    def generate():
        queue = Queue()
        stop_flag = [False]
        heartbeat_interval = 20
        last_yield = time.time()
        
        def log_reader():
            try:
                if is_swarm:
                    stream_func = stream_service_logs
                else:
                    stream_func = stream_container_logs
                
                for log_line in stream_func(stream_client, container_name, tail):
                    if stop_flag[0]:
                        break
                    queue.put(('log', log_line))
                    
                queue.put(('end', None))
            except Exception as e:
                queue.put(('error', str(e)))
        
        reader_greenlet = gevent.spawn(log_reader)
        
        try:
            while True:
                try:
                    msg_type, data = queue.get(timeout=1)
                    
                    if msg_type == 'log':
                        last_yield = time.time()
                        yield json.dumps({"line": data}) + "\n"
                    elif msg_type == 'end':
                        break
                    elif msg_type == 'error':
                        logger.error(f"Stream error: {data}")
                        yield json.dumps({"error": data}) + "\n"
                        break
                        
                except Empty:
                    current_time = time.time()
                    if current_time - last_yield >= heartbeat_interval:
                        last_yield = current_time
                        yield json.dumps({"heartbeat": True}) + "\n"
                        
        except GeneratorExit:
            logger.debug(f"Stream closed for {container_name}")
            stop_flag[0] = True
            raise
        finally:
            stop_flag[0] = True
            reader_greenlet.kill()
            try:
                stream_client.close()
            except:
                pass
    
    response = Response(
        generate(),
        mimetype='application/x-ndjson',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Connection': 'keep-alive'
        }
    )
    response.timeout = None
    return response

@main_bp.route("/export/json")
@conditional_login_required
def export_json():
    server_filter = request.args.get('server', 'all')
    data = get_all_data()
    
    filtered_containers = data.get("containers", [])
    if server_filter != 'all':
        filtered_containers = [c for c in filtered_containers if c.get("server") == server_filter]
        
    export_data = {
        "export_info": {
            "timestamp": datetime.now().isoformat(),
            "dockpeek_version": current_app.config['APP_VERSION'],
            "server_filter": server_filter,
            "total_containers": len(filtered_containers),
        },
        "containers": []
    }
    for c in filtered_containers:
        export_container = {k: v for k, v in c.items() if k in ['name', 'server', 'stack', 'image', 'status', 'exit_code', 'custom_url']}
        if c.get("ports"): 
            export_container["ports"] = c["ports"]
        if c.get("traefik_routes"): 
            export_container["traefik_routes"] = [
                {"router": r["router"], "url": r["url"]} 
                for r in c["traefik_routes"]
            ]
        export_data["containers"].append(export_container)

    formatted_json = json.dumps(export_data, indent=2, ensure_ascii=False)
    filename = f'dockpeek-export-{server_filter}-{datetime.now().strftime("%Y%m%d-%H%M%S")}.json'
    
    response = make_response(formatted_json)
    response.headers['Content-Disposition'] = f'attachment; filename={filename}'
    response.headers['Content-Type'] = 'application/json'
    return response

@main_bp.route("/status")
@conditional_login_required
def get_status():
    servers = discover_docker_clients()
    statuses = []

    for server in servers:
        if server['status'] != 'active':
            continue

        try:
            client = server['client']
            info = client.info()
            is_swarm = info.get('Swarm', {}).get('LocalNodeState', '').lower() == 'active'

            if is_swarm:
                services = client.services.list()
                tasks = client.api.tasks()
                tasks_by_service = {}
                for t in tasks:
                    sid = t['ServiceID']
                    tasks_by_service.setdefault(sid, []).append(t)

                for service in services:
                    service_tasks = tasks_by_service.get(service.id, [])
                    running = sum(1 for t in service_tasks if t['Status']['State'] == 'running')
                    total = len(service_tasks)
                    status = f"running ({running}/{total})" if total else "no-tasks"

                    statuses.append({
                        'server': server['name'],
                        'name': service.name,
                        'status': status,
                        'exit_code': None,
                        'started_at': None
                    })
            else:
                containers = client.containers.list(all=True)
                for container in containers:
                    container_status, exit_code = get_container_status_with_exit_code(container)
                    start_time = container.attrs.get('State', {}).get('StartedAt', '')

                    statuses.append({
                        'server': server['name'],
                        'name': container.name,
                        'status': container_status,
                        'exit_code': exit_code,
                        'started_at': start_time
                    })
        except Exception as e:
            current_app.logger.error(f"Error getting status from {server['name']}: {e}")

    response = jsonify({'statuses': statuses})
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


# =============================================================================
# Security / Vulnerability Scanning API Endpoints
# =============================================================================

@main_bp.route("/api/security/status")
@conditional_login_required
def security_status():
    """Get Trivy integration status and cache statistics."""
    return jsonify({
        'trivy_enabled': trivy_client.is_enabled,
        'trivy_healthy': trivy_client.health_check() if trivy_client.is_enabled else False,
        'trivy_server_url': trivy_client.server_url if trivy_client.is_enabled else None,
        'cache_stats': trivy_client.get_cache_stats() if trivy_client.is_enabled else None
    })


@main_bp.route("/api/scan/<path:image>", methods=["POST"])
@conditional_login_required
def scan_image(image):
    """
    Trigger vulnerability scan for a specific image.

    POST body (optional):
        - server_name: Docker server to use for image digest lookup
        - force: Boolean to bypass cache and force rescan
    """
    if not trivy_client.is_enabled:
        return jsonify({
            'error': 'Trivy integration not configured. Set TRIVY_SERVER_URL environment variable.',
            'trivy_enabled': False
        }), 503

    if not trivy_client.health_check():
        return jsonify({
            'error': 'Trivy server unavailable',
            'trivy_healthy': False
        }), 503

    # Get docker client for image digest extraction
    docker_client = None
    request_data = request.get_json() or {}
    server_name = request_data.get('server_name')
    force_scan = request_data.get('force', False)

    if force_scan:
        trivy_client.clear_cache()

    if server_name:
        servers = discover_docker_clients()
        server = next((s for s in servers if s['name'] == server_name and s['status'] == 'active'), None)
        if server:
            docker_client = server['client']

    result = trivy_client.scan_image(image, docker_client)

    if result is None:
        return jsonify({
            'status': 'error',
            'error': 'Scan failed - check logs for details',
            'image': image
        }), 500

    return jsonify({
        'status': 'success',
        'result': result.to_dict()
    })


@main_bp.route("/api/vulnerabilities/<path:image>")
@conditional_login_required
def get_vulnerabilities(image):
    """
    Get cached scan results for an image.

    Query params:
        - server_name: Docker server for image digest lookup
    """
    if not trivy_client.is_enabled:
        return jsonify({
            'error': 'Trivy integration not configured',
            'trivy_enabled': False
        }), 503

    server_name = request.args.get('server_name')

    # Try to get image digest for cache lookup
    docker_client = None
    if server_name:
        servers = discover_docker_clients()
        server = next((s for s in servers if s['name'] == server_name and s['status'] == 'active'), None)
        if server:
            docker_client = server['client']

    if docker_client:
        image_digest = trivy_client.get_image_digest(docker_client, image)
        if image_digest:
            cached = trivy_client.get_cached_result(image_digest)
            if cached:
                return jsonify({
                    'cached': True,
                    'result': cached.to_dict()
                })

    return jsonify({
        'cached': False,
        'image': image,
        'message': 'No cached results. Trigger a scan with POST /api/scan/<image>'
    }), 404


@main_bp.route("/api/security/summary")
@conditional_login_required
def security_summary():
    """
    Get overall security posture for all containers.
    Returns aggregated vulnerability counts and per-container summaries.
    """
    if not trivy_client.is_enabled:
        return jsonify({
            'trivy_enabled': False,
            'summary': None
        })

    servers = discover_docker_clients()
    active_servers = [s for s in servers if s['status'] == 'active']

    total_summary = {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'unknown': 0,
        'total': 0,
        'scanned_containers': 0,
        'unscanned_containers': 0
    }

    container_results = []

    for server in active_servers:
        try:
            containers = server['client'].containers.list(all=True)
            for container in containers:
                image_name = container.attrs.get('Config', {}).get('Image', '')
                if not image_name:
                    total_summary['unscanned_containers'] += 1
                    continue

                image_digest = trivy_client.get_image_digest(server['client'], image_name)
                if image_digest:
                    cached = trivy_client.get_cached_result(image_digest)
                    if cached:
                        total_summary['critical'] += cached.summary.critical
                        total_summary['high'] += cached.summary.high
                        total_summary['medium'] += cached.summary.medium
                        total_summary['low'] += cached.summary.low
                        total_summary['unknown'] += cached.summary.unknown
                        total_summary['total'] += cached.summary.total
                        total_summary['scanned_containers'] += 1
                        container_results.append({
                            'server': server['name'],
                            'container': container.name,
                            'image': image_name,
                            'summary': cached.summary.to_dict(),
                            'scan_timestamp': cached.scan_timestamp.isoformat()
                        })
                    else:
                        total_summary['unscanned_containers'] += 1
                else:
                    total_summary['unscanned_containers'] += 1

        except Exception as e:
            current_app.logger.error(f"Error getting security summary for {server['name']}: {e}")

    return jsonify({
        'trivy_enabled': True,
        'trivy_healthy': trivy_client.health_check(),
        'summary': total_summary,
        'containers': container_results
    })


@main_bp.route("/api/security/cache/clear", methods=["POST"])
@conditional_login_required
def clear_security_cache():
    """Clear the vulnerability scan cache."""
    if not trivy_client.is_enabled:
        return jsonify({'error': 'Trivy integration not configured'}), 503

    trivy_client.clear_cache()
    return jsonify({
        'status': 'cache_cleared',
        'cache_stats': trivy_client.get_cache_stats()
    })


@main_bp.route("/api/security/history/<path:image>")
@conditional_login_required
def get_scan_history(image):
    """
    Get scan history for an image.

    Query params:
        - server_name: Docker server for image digest lookup
        - limit: Maximum number of history entries (default 5)
    """
    if not scan_history_db.is_enabled:
        return jsonify({
            'enabled': False,
            'history': [],
            'message': 'Scan history not enabled'
        })

    server_name = request.args.get('server_name')
    limit = request.args.get('limit', 5, type=int)

    # Try to get image digest
    image_digest = None
    if server_name:
        servers = discover_docker_clients()
        server = next((s for s in servers if s['name'] == server_name and s['status'] == 'active'), None)
        if server:
            image_digest = trivy_client.get_image_digest(server['client'], image)

    if not image_digest:
        return jsonify({
            'enabled': True,
            'history': [],
            'message': 'Could not determine image digest'
        })

    history = scan_history_db.get_scan_history(image_digest, limit=limit)
    trend = scan_history_db.calculate_trend(image_digest)

    return jsonify({
        'enabled': True,
        'image': image,
        'image_digest': image_digest,
        'history': history,
        'trend': {
            'direction': trend.direction,
            'previous_total': trend.previous_total,
            'current_total': trend.current_total,
            'delta_critical': trend.delta_critical,
            'delta_high': trend.delta_high,
            'scan_count': trend.scan_count
        }
    })


@main_bp.route("/api/security/new-vulnerabilities")
@conditional_login_required
def get_new_vulnerabilities():
    """
    Get recently discovered vulnerabilities.

    Query params:
        - hours: Look back period in hours (default 24)
        - severity: Filter by severity (optional, e.g., 'CRITICAL')
    """
    if not scan_history_db.is_enabled:
        return jsonify({
            'enabled': False,
            'vulnerabilities': [],
            'message': 'Scan history not enabled'
        })

    hours = request.args.get('hours', 24, type=int)
    severity = request.args.get('severity')

    vulnerabilities = scan_history_db.get_new_vulnerabilities_since(hours=hours, severity=severity)

    return jsonify({
        'enabled': True,
        'hours': hours,
        'severity_filter': severity,
        'vulnerabilities': vulnerabilities,
        'count': len(vulnerabilities)
    })


@main_bp.route("/api/security/trends")
@conditional_login_required
def get_security_trends():
    """
    Get overall security trends across all containers.
    Returns aggregate trend information.
    """
    if not trivy_client.is_enabled:
        return jsonify({
            'trivy_enabled': False,
            'trends': None
        })

    servers = discover_docker_clients()
    active_servers = [s for s in servers if s['status'] == 'active']

    trends = {
        'improving': 0,
        'degrading': 0,
        'stable': 0,
        'unknown': 0,
        'total_new_vulns': 0
    }

    container_trends = []

    for server in active_servers:
        try:
            containers = server['client'].containers.list(all=True)
            for container in containers:
                image_name = container.attrs.get('Config', {}).get('Image', '')
                if not image_name:
                    continue

                image_digest = trivy_client.get_image_digest(server['client'], image_name)
                if image_digest and scan_history_db.is_enabled:
                    trend = scan_history_db.calculate_trend(image_digest)
                    if trend.direction in trends:
                        trends[trend.direction] += 1

                    if trend.direction != 'unknown':
                        container_trends.append({
                            'server': server['name'],
                            'container': container.name,
                            'image': image_name,
                            'trend': trend.direction,
                            'delta_critical': trend.delta_critical,
                            'delta_high': trend.delta_high
                        })
                else:
                    trends['unknown'] += 1

        except Exception as e:
            current_app.logger.error(f"Error getting trends for {server['name']}: {e}")

    # Get new vulnerabilities count from last 24h
    if scan_history_db.is_enabled:
        new_vulns = scan_history_db.get_new_vulnerabilities_since(hours=24)
        trends['total_new_vulns'] = len(new_vulns)

    # Determine overall trend
    if trends['degrading'] > trends['improving']:
        overall = 'degrading'
    elif trends['improving'] > trends['degrading']:
        overall = 'improving'
    elif trends['stable'] > 0:
        overall = 'stable'
    else:
        overall = 'unknown'

    return jsonify({
        'trivy_enabled': True,
        'overall_trend': overall,
        'trends': trends,
        'container_trends': container_trends
    })


@main_bp.route("/api/security/stats")
@conditional_login_required
def get_security_stats():
    """Get database statistics for scan history."""
    stats = scan_history_db.get_stats()
    return jsonify(stats)


# =============================================================================
# Notification API Endpoints
# =============================================================================

@main_bp.route("/api/notifications/status")
@conditional_login_required
def notification_status():
    """Get ntfy notification system status."""
    if ntfy_notifier is None:
        return jsonify({
            'enabled': False,
            'error': 'Notifications module not available'
        })
    return jsonify(ntfy_notifier.get_status())


@main_bp.route("/api/notifications/test", methods=["POST"])
@conditional_login_required
def test_notification():
    """Send a test notification to verify ntfy integration."""
    if ntfy_notifier is None or not ntfy_notifier.is_enabled:
        return jsonify({
            'error': 'Notifications not enabled. Set NTFY_URL environment variable.',
            'enabled': False
        }), 503

    success = ntfy_notifier._send_notification(
        title="[TEST] DockPeek Security Alert",
        message=(
            "This is a test notification from DockPeek Security.\n\n"
            "If you see this, ntfy integration is working correctly."
        ),
        priority='default',
        tags=['white_check_mark', 'test_tube']
    )

    if success:
        return jsonify({
            'status': 'sent',
            'message': 'Test notification sent successfully'
        })
    else:
        return jsonify({
            'status': 'failed',
            'message': 'Failed to send test notification'
        }), 500


# =============================================================================
# Traefik API Endpoints
# =============================================================================

@main_bp.route("/api/traefik/routes")
@conditional_login_required
def get_traefik_routes():
    """
    Get all Traefik HTTP routes from the Traefik API.
    Returns routes from all providers (Docker, file, etc.).
    """
    if not traefik_client.is_enabled:
        return jsonify({
            'enabled': False,
            'routes': [],
            'message': 'Traefik API not configured. Set TRAEFIK_API_URL environment variable.'
        })

    routes = traefik_client.get_all_routes_flat()
    return jsonify({
        'enabled': True,
        'routes': routes,
        'count': len(routes)
    })


@main_bp.route("/api/traefik/status")
@conditional_login_required
def get_traefik_status():
    """Get Traefik API integration status."""
    return jsonify({
        'enabled': traefik_client.is_enabled,
        'api_url': traefik_client.api_url if traefik_client.is_enabled else None
    })


# =============================================================================
# Version Checker API Endpoints
# =============================================================================

@main_bp.route("/api/version/check/<path:image>")
@conditional_login_required
def check_image_version(image):
    """
    Check if a newer version is available for an image.

    Returns:
        - newer_available: bool
        - latest_version: string (tag) if newer available
        - current_version: string (tag)
    """
    try:
        result = version_checker.check_for_newer_version(image)

        if result:
            return jsonify({
                'image': image,
                'newer_available': True,
                'latest_version': result.tag,
                'current_version': image.split(':')[-1] if ':' in image else 'latest'
            })
        else:
            return jsonify({
                'image': image,
                'newer_available': False,
                'current_version': image.split(':')[-1] if ':' in image else 'latest'
            })

    except Exception as e:
        current_app.logger.error(f"Error checking version for {image}: {e}")
        return jsonify({
            'error': str(e),
            'image': image
        }), 500


@main_bp.route("/api/version/list/<path:image>")
@conditional_login_required
def list_image_versions(image):
    """
    Get list of available versions for an image.
    """
    try:
        limit = request.args.get('limit', 20, type=int)
        versions = version_checker.get_available_versions(image, limit=limit)

        return jsonify({
            'image': image,
            'versions': [
                {
                    'tag': v.tag,
                    'is_newer': v.is_newer,
                    'is_stable': v.is_stable
                }
                for v in versions
            ],
            'count': len(versions)
        })

    except Exception as e:
        current_app.logger.error(f"Error listing versions for {image}: {e}")
        return jsonify({
            'error': str(e),
            'image': image
        }), 500


@main_bp.route("/api/version/check-all", methods=["POST"])
@conditional_login_required
def check_all_versions():
    """
    Check for newer versions across all containers.
    Returns list of containers with newer versions available.
    """
    servers = discover_docker_clients()
    active_servers = [s for s in servers if s['status'] == 'active']

    updates_available = []
    checked = 0
    errors = 0

    for server in active_servers:
        try:
            containers = server['client'].containers.list(all=True)
            for container in containers:
                image_name = container.attrs.get('Config', {}).get('Image', '')
                if not image_name:
                    continue

                checked += 1
                try:
                    result = version_checker.check_for_newer_version(image_name)
                    if result:
                        updates_available.append({
                            'server': server['name'],
                            'container': container.name,
                            'image': image_name,
                            'current_version': image_name.split(':')[-1] if ':' in image_name else 'latest',
                            'latest_version': result.tag
                        })
                except Exception as e:
                    errors += 1
                    current_app.logger.debug(f"Version check failed for {image_name}: {e}")

        except Exception as e:
            current_app.logger.error(f"Error accessing containers on {server['name']}: {e}")

    return jsonify({
        'updates_available': updates_available,
        'count': len(updates_available),
        'checked': checked,
        'errors': errors
    })