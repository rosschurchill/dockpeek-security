import os
import logging
from flask import Flask
from config import Config
from .extensions import login_manager, cors
from . import dns_cache  # noqa: F401 — activates process-level DNS caching on import

_scheduler_started = False

def create_app(config_class=Config):
    global _scheduler_started

    log_level = getattr(logging, config_class.LOG_LEVEL.upper(), logging.INFO)
    logging.basicConfig(
        level=log_level,
        format='[%(levelname)s] - %(message)s'
    )

    if log_level > logging.DEBUG:
        logging.getLogger('werkzeug').setLevel(logging.WARNING)
        logging.getLogger('gunicorn').setLevel(logging.WARNING)
        logging.getLogger('gunicorn.access').setLevel(logging.WARNING)
        logging.getLogger('gunicorn.error').setLevel(logging.ERROR)

    app = Flask(__name__)
    app.config.from_object(config_class)

    login_manager.init_app(app)
    cors.init_app(app)

    if not app.config.get('DISABLE_AUTH', False):
        logging.debug("Authentication enabled")
    else:
        logging.info("Authentication disabled")

    from . import auth
    app.register_blueprint(auth.auth_bp)

    from . import main
    app.register_blueprint(main.main_bp)

    from . import api_keys
    app.register_blueprint(api_keys.api_keys_bp)

    # Register Prometheus metrics endpoint (no auth required for scraping)
    try:
        from .metrics import metrics_bp, init_app_info
        app.register_blueprint(metrics_bp)
        init_app_info(config_class.APP_VERSION)
        logging.info("Prometheus metrics enabled at /metrics")
    except ImportError as e:
        logging.warning(f"Prometheus metrics disabled: {e} (install prometheus_client to enable)")

    # Start background scheduler (only once per process)
    if not _scheduler_started:
        from .background_scheduler import scheduler
        scheduler.start(app)
        _scheduler_started = True

    return app