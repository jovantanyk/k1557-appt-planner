"""Flask application factory and blueprint registration for kvk-appt."""

import logging
import mimetypes
import os
import sqlite3
from logging.handlers import RotatingFileHandler

from flask import Flask, request
from flask_wtf.csrf import CSRFProtect
from flask_babel import Babel, get_locale

from config import Config

from . import database
from .constants import DEFAULT_SLOT_COUNT
from .logic import generate_slot_labels
from .routes import admin_bp, api_bp, public_bp, superadmin_bp
from .services import fetch_player_info

# Ensure .js files are served with the correct MIME type
mimetypes.add_type("application/javascript", ".js")

SUPPORTED_LANGUAGES = [
    ("en", "English"),
    ("zh", "简体中文"),
    ("zh_Hant", "繁體中文"),
    ("fr", "Français"),
    ("pt", "Português"),
    ("pl", "Polski"),
    ("es", "Español"),
    ("de", "Deutsch"),
    ("it", "Italiano"),
    ("ko", "한국어"),
]
LANGUAGE_CODES = [code for code, _ in SUPPORTED_LANGUAGES]

babel = Babel()


def select_locale():
    """Use the language the visitor picked; otherwise match their browser; otherwise English."""
    lang = request.cookies.get("lang")
    if lang in LANGUAGE_CODES:
        return lang
    return request.accept_languages.best_match(LANGUAGE_CODES) or "en"

    
def create_app() -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__)
    app.config.from_object(Config)
    CSRFProtect(app)
    database.init_app(app)
    babel.init_app(app, locale_selector=select_locale) 

    # Setup Audit Logging
    log_dir = os.path.join(app.root_path, "..", "logs")
    os.makedirs(log_dir, exist_ok=True)

    audit_logger = logging.getLogger("audit")
    audit_logger.setLevel(logging.INFO)
    if not audit_logger.handlers:
        audit_handler = RotatingFileHandler(
            os.path.join(log_dir, "audit.log"), maxBytes=1000000, backupCount=5
        )
        audit_handler.setFormatter(
            logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        )
        audit_logger.addHandler(audit_handler)
    app.audit_logger = audit_logger

    # Register Route Blueprints
    app.register_blueprint(public_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(superadmin_bp)
    app.register_blueprint(api_bp)

    # Make the label generator available to all templates
    @app.context_processor
    def inject_global_config():
        slot_count = DEFAULT_SLOT_COUNT
        try:
            event_uid = (
                request.view_args.get("event_uid") if request.view_args else None
            )
            if event_uid:
                db = database.get_db()
                row = db.execute(
                    "SELECT slot_count FROM events WHERE uid = ?", (event_uid,)
                ).fetchone()
                if row and row[0] is not None:
                    slot_count = row[0]
        except (sqlite3.Error, RuntimeError) as e:
            logging.getLogger("audit").warning(
                f"Context processor slot lookup failed for event {event_uid}: {e}"
            )

        return {
            "slot_labels": generate_slot_labels(slot_count),
            "enable_screenshot_upload": Config.ENABLE_SCREENSHOT_UPLOAD,
            "ga_measurement_id": Config.GA_MEASUREMENT_ID,
            "current_locale": str(get_locale()),
            "supported_languages": SUPPORTED_LANGUAGES,
        }

    @app.after_request
    def add_security_headers(response):
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://www.googletagmanager.com; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "connect-src 'self' https://www.google-analytics.com;"
        )
        response.headers["Content-Security-Policy"] = csp
        return response

    return app


app = create_app()

__all__ = ["app", "create_app", "fetch_player_info"]
