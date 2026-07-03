"""
app.py
======
Flask entry point for the Secure Password Generator web app.

Routes
------
    GET  /                  - Renders the single-page UI.
    GET  /api/health        - Liveness probe; returns {"status": "ok"}.
    POST /api/generate      - Body: {length, count, categories, avoid_ambiguous}
                              Returns: {passwords: [...], stats: [...]}
    POST /api/strength      - Body: {password, categories}
                              Returns: a single stats object.
"""

from __future__ import annotations

import os
from flask import Flask, jsonify, render_template, request

from password_core import (
    CHAR_SETS,
    generate_password,
    password_stats,
    validate_inputs,
)


def create_app() -> Flask:
    """Application factory."""
    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.config["JSON_SORT_KEYS"] = False
    app.config["MAX_CONTENT_LENGTH"] = 64 * 1024  # 64 KB request cap

    # ------------------------------------------------------------------ Security headers
    @app.after_request
    def apply_security_headers(response):
        # Content Security Policy: self-hosted only by default. The
        # k-anonymity breach check (api.pwnedpasswords.com) is opt-in
        # via SPG_ENABLE_HIBP=1 so a public deployment can keep the
        # browser fully locked down.
        connect_src = "'self'"
        if os.environ.get("SPG_ENABLE_HIBP") == "1":
            connect_src += " https://api.pwnedpasswords.com"
        csp = (
            f"default-src 'self'; "
            f"script-src 'self'; "
            f"style-src 'self' 'unsafe-inline'; "
            f"img-src 'self' data:; "
            f"font-src 'self'; "
            f"connect-src {connect_src}; "
            f"object-src 'none'; "
            f"base-uri 'self'; "
            f"frame-ancestors 'none'"
        )
        response.headers["Content-Security-Policy"] = csp
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        return response

    # ------------------------------------------------------------------ Error handlers
    @app.errorhandler(400)
    def _bad_request(err):
        return jsonify({"error": err.description if hasattr(err, "description") else "Bad request"}), 400

    @app.errorhandler(404)
    def _not_found(err):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Not found"}), 404
        return jsonify({"error": "Not found"}), 404

    @app.errorhandler(405)
    def _method_not_allowed(err):
        return jsonify({"error": "Method not allowed"}), 405

    @app.errorhandler(500)
    def _server_error(err):
        return jsonify({"error": "Internal server error"}), 500

    # ------------------------------------------------------------------ Page
    @app.get("/")
    def index():
        return render_template(
            "index.html",
            app_title="Secure Password Generator",
            app_version=os.environ.get("APP_VERSION", "1.0.0"),
            categories=list(CHAR_SETS.keys()),
        )

    # ------------------------------------------------------------------ API
    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok"})

    @app.post("/api/generate")
    def api_generate():
        body = request.get_json(silent=True) or {}
        length = body.get("length")
        count = body.get("count", 1)
        categories = body.get("categories") or []
        avoid_ambiguous = bool(body.get("avoid_ambiguous", False))

        ok, length, count, err = validate_inputs(length, count, categories)
        if not ok:
            return jsonify({"error": err}), 400

        # length and count come back from validate_inputs as already-coerced
        # integers — no need to int(...) them again.
        passwords = [
            generate_password(length, categories, avoid_ambiguous=avoid_ambiguous)
            for _ in range(count)
        ]
        stats = [password_stats(p, categories) for p in passwords]
        return jsonify({"passwords": passwords, "stats": stats})

    @app.post("/api/strength")
    def api_strength():
        body = request.get_json(silent=True) or {}
        password = body.get("password", "")
        categories = body.get("categories") or list(CHAR_SETS.keys())

        if not isinstance(password, str) or not password:
            return jsonify({"error": "Password is required."}), 400

        stats = password_stats(password, categories)
        return jsonify(stats)

    return app


app = create_app()


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host=host, port=port, debug=debug)
