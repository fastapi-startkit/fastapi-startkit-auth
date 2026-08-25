"""Login/logout controller (module style, per the startkit routing docs)."""
from fastapi import Depends
from fastapi.responses import RedirectResponse, Response

from fastapi_startkit.inertia import Inertia

from fastapi_startkit_auth import Auth

from app.http.requests.login_request import LoginRequest

LOGIN_ERROR = "These credentials do not match our records."


def create(auth: Auth = Depends(Auth.scoped)) -> Response:
    """Show the login page."""
    if auth.check():
        return RedirectResponse("/dashboard", status_code=303)
    return Inertia.render("Login")


def store(credentials: LoginRequest, auth: Auth = Depends(Auth.scoped)) -> Response:
    """Attempt a login with the submitted credentials."""
    if auth.attempt(credentials.model_dump()):
        return RedirectResponse("/dashboard", status_code=303)
    # A failed login has no session to flash errors into, so render the page
    # directly; Inertia's useForm reads page.props.errors either way.
    return Inertia.render("Login", {"errors": {"email": LOGIN_ERROR}})


def destroy(auth: Auth = Depends(Auth.scoped)) -> Response:
    """Destroy the session and return to the login page."""
    auth.logout()
    return RedirectResponse("/login", status_code=303)
