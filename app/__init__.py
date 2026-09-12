import os

from flask import Flask, send_from_directory

from app.auth import install_auth, warn_if_using_dev_defaults
from app.db import init_db

WEBUI_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "webui")


def create_app(config_object="config.Config"):
    app = Flask(__name__)
    app.config.from_object(config_object)

    init_db(app)
    install_auth(app)
    warn_if_using_dev_defaults(app)

    from app.routes import bp
    app.register_blueprint(bp)

    @app.get("/health")
    def health():
        return {"status": "armed", "service": "arachnode-ai-policy-engine"}

    @app.get("/")
    def console():
        """Serves the Arachnode AI Policy Console. Same origin as the
        API it calls — no CORS, no CSP cross-origin restrictions, no
        second server to stand up."""
        return send_from_directory(WEBUI_DIR, "index.html")

    return app
