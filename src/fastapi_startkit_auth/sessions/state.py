"""Request-state keys shared by the session middleware, guard, and facade.

The middleware loads the session record under ``SESSION_KEY`` before the app
runs and inspects the same keys afterwards to decide whether to set or delete
the cookie. ``LOADED_ID_KEY`` holds the session id that arrived on the request
(if any) so a changed id is detected; ``FORGET_KEY`` marks an explicit logout.
"""

SESSION_KEY = "auth_session"
LOADED_ID_KEY = "auth_session_loaded_id"
FORGET_KEY = "auth_session_forget"
