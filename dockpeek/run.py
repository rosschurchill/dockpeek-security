import os
from werkzeug.middleware.proxy_fix import ProxyFix
from dockpeek import create_app

app = create_app()

TRUST_PROXY_HEADERS = os.environ.get("TRUST_PROXY_HEADERS", "false").lower() == "true"
TRUSTED_PROXY_COUNT = int(os.environ.get("TRUSTED_PROXY_COUNT", "1"))

if TRUST_PROXY_HEADERS:
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=TRUSTED_PROXY_COUNT,
        x_proto=TRUSTED_PROXY_COUNT,
        x_host=TRUSTED_PROXY_COUNT,
        x_port=TRUSTED_PROXY_COUNT,
        x_prefix=TRUSTED_PROXY_COUNT
    )
else:
    pass

if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=PORT, debug=debug)