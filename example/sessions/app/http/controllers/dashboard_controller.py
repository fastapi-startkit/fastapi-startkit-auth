"""Dashboard controller: the session-protected page and the root redirect."""
from fastapi import Depends
from fastapi.responses import RedirectResponse, Response

from fastapi_startkit.inertia import Inertia

from fastapi_startkit_auth import Auth


def home(auth: Auth = Depends(Auth.scoped)) -> Response:
    """Send visitors to the dashboard or the login page by auth state."""
    return RedirectResponse("/dashboard" if auth.check() else "/login", status_code=303)


def index(auth: Auth = Depends(Auth.scoped)) -> Response:
    """Render the protected dashboard; guests are redirected to login."""
    user = auth.user()
    if user is None:
        return RedirectResponse("/login", status_code=303)
    return Inertia.render("Dashboard", {"user": {"id": user["id"], "email": user["email"]}})
