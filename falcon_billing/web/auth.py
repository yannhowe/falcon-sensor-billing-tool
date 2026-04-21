"""API key authentication middleware for the dashboard.

When DASHBOARD_API_KEY is set, all /api/* routes require
the key via X-API-Key header or ?api_key= query parameter.

When DASHBOARD_API_KEY is not set or DASHBOARD_NO_AUTH=1, auth is disabled.
"""

import hmac
import os
from functools import wraps

from flask import request, jsonify


def require_api_key(f):
    """Decorator that checks API key on protected routes."""

    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = os.environ.get("DASHBOARD_API_KEY", "").strip()
        no_auth = os.environ.get("DASHBOARD_NO_AUTH", "").strip()

        # Auth disabled if no key configured or explicitly disabled
        if not api_key or no_auth == "1":
            return f(*args, **kwargs)

        # Check header first, then query param
        provided_key = request.headers.get("X-API-Key", "").strip()
        if not provided_key:
            provided_key = request.args.get("api_key", "").strip()

        if hmac.compare_digest(provided_key, api_key):
            return f(*args, **kwargs)

        return jsonify({"error": "Unauthorized", "message": "Valid API key required"}), 401

    return decorated
