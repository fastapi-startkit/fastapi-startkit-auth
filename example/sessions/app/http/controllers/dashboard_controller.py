from fastapi import Depends
from fastapi.responses import RedirectResponse, Response

from fastapi_startkit.inertia import Inertia

from fastapi_startkit_auth import Auth


async def home(auth: Auth = Depends(Auth.scoped)) -> Response:
    return RedirectResponse("/dashboard" if auth.check() else "/login", status_code=303)


async def index(auth: Auth = Depends(Auth.scoped)) -> Response:
    user = auth.user()
    if user is None:
        return RedirectResponse("/login", status_code=303)
    return Inertia.render("Dashboard", {"user": {"id": user["id"], "email": user["email"]}})
