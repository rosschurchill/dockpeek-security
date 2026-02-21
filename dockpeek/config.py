import os, json
from datetime import timedelta


def load_custom_registry_templates():
    try:
        raw = os.getenv("CUSTOM_REGISTRY_TEMPLATES", "{}")
        return json.loads(raw)
    except Exception:
        return {}
        
class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY")
    if not SECRET_KEY:
        raise RuntimeError("ERROR: SECRET_KEY environment variable is not set.")

    DISABLE_AUTH = os.environ.get("DISABLE_AUTH", "false").lower() == "true"

    if not DISABLE_AUTH:
        ADMIN_USERNAME = os.environ.get("USERNAME")
        ADMIN_PASSWORD = os.environ.get("PASSWORD")
        if not ADMIN_USERNAME or not ADMIN_PASSWORD:
            raise RuntimeError("USERNAME and PASSWORD environment variables must be set.")
    else:
        ADMIN_USERNAME = None
        ADMIN_PASSWORD = None
        
    TRAEFIK_ENABLE = os.environ.get("TRAEFIK_LABELS", "true").lower() == "true"
    TAGS_ENABLE = os.environ.get("TAGS", "true").lower() == "true"
    PORT_RANGE_GROUPING = os.environ.get("PORT_RANGE_GROUPING", "true").lower() == "true"
    PORT_RANGE_THRESHOLD = int(os.environ.get("PORT_RANGE_THRESHOLD", "5"))
    
    PERMANENT_SESSION_LIFETIME = timedelta(days=14)
    
    APP_VERSION = os.environ.get('VERSION', 'dev')
        
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")

    DOCKER_CONNECTION_TIMEOUT = float(os.environ.get("DOCKER_CONNECTION_TIMEOUT", "2"))

    PORT = int(os.environ.get("PORT", "8000"))

    CUSTOM_REGISTRY_TEMPLATES = load_custom_registry_templates()

    # Trivy vulnerability scanning configuration
    TRIVY_SERVER_URL = os.environ.get("TRIVY_SERVER_URL", "")
    TRIVY_ENABLED = os.environ.get("TRIVY_ENABLED", "true").lower() == "true" if os.environ.get("TRIVY_SERVER_URL") else False
    TRIVY_SCAN_TIMEOUT = int(os.environ.get("TRIVY_SCAN_TIMEOUT", "120"))
    TRIVY_CACHE_DURATION = int(os.environ.get("TRIVY_CACHE_DURATION", "3600"))

    # Traefik API configuration (for fetching routes from file provider, etc.)
    TRAEFIK_API_URL = os.environ.get("TRAEFIK_API_URL", "")

    # ntfy notification configuration
    NTFY_URL = os.environ.get("NTFY_URL", "")
    NTFY_TOPIC = os.environ.get("NTFY_TOPIC", "security-alerts")
    NTFY_ENABLED = os.environ.get("NTFY_ENABLED", "true").lower() == "true" if os.environ.get("NTFY_URL") else False
    NTFY_COOLDOWN_MINUTES = int(os.environ.get("NTFY_COOLDOWN_MINUTES", "60"))
    NTFY_MIN_CRITICAL = int(os.environ.get("NTFY_MIN_CRITICAL", "1"))
    NTFY_MIN_HIGH = int(os.environ.get("NTFY_MIN_HIGH", "10"))