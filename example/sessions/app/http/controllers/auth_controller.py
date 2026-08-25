from fastapi import Depends
from fastapi.responses import RedirectResponse, Response

from fastapi_startkit.inertia import Inertia

from fastapi_startkit_auth import Auth

from app.http.requests.login_request import LoginRequest

LOGIN_ERROR = "These credentials do not match our records."


async def create(auth: Auth = Depends(Auth.scoped)) -> Response:
    if auth.check():
        return RedirectResponse("/dashboard", status_code=303)
    return Inertia.render("Login")


async def store(credentials: LoginRequest, auth: Auth = Depends(Auth.scoped)) -> Response:
    if auth.attempt(credentials.model_dump()):
        return RedirectResponse("/dashboard", status_code=303)
    return Inertia.render("Login", {"errors": {"email": LOGIN_ERROR}})


async def destroy(auth: Auth = Depends(Auth.scoped)) -> Response:
    auth.logout()
    return RedirectResponse("/login", status_code=303)
