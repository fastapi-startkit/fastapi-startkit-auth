"""CORS configuration for SPA cookie authentication.

Published into the application as ``config/cors.py`` by::

    python artisan provider:publish -p auth

Cookie-authenticated cross-origin requests require ``allow_credentials=True``,
and browsers reject a wildcard ``*`` origin when credentials are enabled —
always list the exact first-party origins here, matching
``AuthConfig.spa["stateful_origins"]``.

Wire it into Starlette's CORS middleware::

    from starlette.middleware.cors import CORSMiddleware
    from config import cors

    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors.ALLOW_ORIGINS,
        allow_credentials=cors.ALLOW_CREDENTIALS,
        allow_methods=cors.ALLOW_METHODS,
        allow_headers=cors.ALLOW_HEADERS,
        expose_headers=cors.EXPOSE_HEADERS,
        max_age=cors.MAX_AGE,
    )
"""

# Exact first-party SPA origins (scheme + host + port). Never use "*" here:
# credentials would silently stop working in every browser.
ALLOW_ORIGINS = [
    "http://localhost:5173",
]

# Required so the browser sends the session cookie and accepts Set-Cookie.
ALLOW_CREDENTIALS = True

ALLOW_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]

# X-XSRF-TOKEN is the CSRF header the auth package's middleware verifies.
ALLOW_HEADERS = ["Authorization", "Content-Type", "X-XSRF-TOKEN", "X-Requested-With"]

EXPOSE_HEADERS: list[str] = []

MAX_AGE = 600
