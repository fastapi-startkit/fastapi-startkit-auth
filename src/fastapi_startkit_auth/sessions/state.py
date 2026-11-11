"""Request-state keys shared by the session middleware, guard, and facade.

The middleware loads the session record under ``SESSION_KEY`` before the app
runs and inspects the same keys afterwards to decide whether to set or delete
the cookie. ``LOADED_ID_KEY`` holds the session id that arrived on the request
(if any) so a changed id is detected; ``FORGET_KEY`` marks an explicit logout.
``PENDING_KEY`` holds a guest session that is only persisted once the response
starts, so a request that never needs it costs no store write.
``TOKEN_CLIENT_KEY`` marks a native token client that ``CsrfMiddleware``
exempted from the CSRF check, so session guards refuse to authenticate it.
"""

SESSION_KEY = "auth_session"
LOADED_ID_KEY = "auth_session_loaded_id"
FORGET_KEY = "auth_session_forget"
PENDING_KEY = "auth_session_pending"
TOKEN_CLIENT_KEY = "auth_token_client"
