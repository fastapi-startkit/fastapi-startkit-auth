import asyncio

import httpx
import pytest
from fastapi import Body, Depends, FastAPI

from fastapi_startkit_auth import AsyncAuth, Auth, InvalidSession, Session
from fastapi_startkit_auth.dependencies import auth
from fastapi_startkit_auth.request_context import current_auth_request

from fastapi_startkit_auth.sessions.store import new_session_record

from conftest import BrowserTestClient as TestClient
from conftest import register_auth
from test_session_auth import COOKIE, session_config


@pytest.fixture
def facade_app():
    api = FastAPI()
    manager = register_auth(api, session_config(), session={})

    @api.post("/login")
    async def login(credentials: dict = Body(...)):
        if not await AsyncAuth.attempt(credentials):
            raise InvalidSession("Invalid credentials.")
        previous = Session.id()
        await Session.regenerate()
        return {"previous": previous, "id": Session.id()}

    @api.post("/logout")
    async def logout():
        await AsyncAuth.logout()
        return {"id": Session.id()}

    @api.post("/invalidate")
    async def invalidate():
        await Session.invalidate()
        return {"id": Session.id()}

    @api.post("/guest")
    async def guest():
        await Session.regenerate()
        return {"id": Session.id()}

    @api.get("/dashboard", dependencies=[Depends(auth)])
    async def dashboard():
        return {
            "user": await AsyncAuth.user(),
            "id": await AsyncAuth.id(),
            "check": await AsyncAuth.check(),
            "manager": current_auth_request().manager is manager,
        }

    @api.post("/validate")
    def validate(credentials: dict = Body(...)):
        user = Auth.validate(credentials)
        return {"id": user["id"] if user else None, "session": Session.id()}

    @api.get("/csrf-token")
    def csrf_token():
        return {"token": Session.token(), "id": Session.id()}

    @api.get("/error")
    async def error():
        await AsyncAuth.login(1)
        raise RuntimeError("handler failed")

    return api, manager


async def test_static_login_rotation_and_logout(facade_app):
    api, manager = facade_app
    client = TestClient(api, base_url="https://testserver")
    assert client.get("/dashboard").status_code == 401
    login = client.post("/login", json={"email": "ada@example.com", "password": "secret"})
    assert login.status_code == 200
    previous, current = login.json()["previous"], login.json()["id"]
    assert previous != current
    assert manager.session_store.find(previous) is None
    assert client.cookies.get(COOKIE) == current
    dashboard = client.get("/dashboard").json()
    assert dashboard["id"] == 1
    assert dashboard["user"]["email"] == "ada@example.com"
    assert dashboard["check"] is True
    assert dashboard["manager"] is True
    assert client.post("/logout").json() == {"id": None}
    assert manager.session_store.find(current) is None
    assert client.get("/dashboard").status_code == 401


def test_invalid_credentials_do_not_create_a_session(facade_app):
    api, _ = facade_app
    client = TestClient(api, base_url="https://testserver")
    response = client.post("/login", json={"email": "ada@example.com", "password": "wrong"})
    assert response.status_code == 401
    assert COOKIE not in client.cookies


async def test_guest_session_and_invalidation(facade_app):
    api, manager = facade_app
    client = TestClient(api, base_url="https://testserver")
    session_id = client.post("/guest").json()["id"]
    assert client.cookies.get(COOKIE) == session_id
    assert (manager.session_store.find(session_id)).user_id is None
    assert client.get("/dashboard").status_code == 401
    assert client.post("/invalidate").json() == {"id": None}
    assert manager.session_store.find(session_id) is None
    assert COOKIE not in client.cookies


def test_facades_reject_access_outside_a_request(facade_app):
    api, _ = facade_app
    client = TestClient(api)
    with pytest.raises(RuntimeError, match="handler failed"):
        client.get("/error")
    with pytest.raises(RuntimeError, match="active request"):
        Auth.login(1)
    with pytest.raises(RuntimeError, match="active request"):
        Session.id()
    with pytest.raises(RuntimeError, match="active request"):
        current_auth_request()


async def test_concurrent_requests_keep_separate_facade_contexts(facade_app):
    api, manager = facade_app
    ready = asyncio.Event()
    arrivals = 0

    @api.get("/concurrent", dependencies=[Depends(auth)])
    async def concurrent():
        nonlocal arrivals
        arrivals += 1
        if arrivals == 2:
            ready.set()
        await asyncio.wait_for(ready.wait(), timeout=2)
        return {"user_id": await AsyncAuth.id(), "session_id": Session.id()}

    first = new_session_record(user_id=1, guard="web", ttl=60)
    second = new_session_record(user_id=2, guard="web", ttl=60)
    manager.session_store.save(first)
    manager.session_store.save(second)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=api), base_url="https://testserver") as client:
        responses = await asyncio.gather(
            client.get("/concurrent", headers={"Cookie": f"{COOKIE}={first.id}"}),
            client.get("/concurrent", headers={"Cookie": f"{COOKIE}={second.id}"}),
        )
    assert [response.json() for response in responses] == [
        {"user_id": 1, "session_id": first.id},
        {"user_id": 2, "session_id": second.id},
    ]
    with pytest.raises(RuntimeError, match="active request"):
        current_auth_request()


def test_validate_checks_credentials_without_starting_a_session(facade_app):
    api, _ = facade_app
    client = TestClient(api, base_url="https://testserver")
    assert client.post("/validate", json={"email": "ada@example.com", "password": "secret"}).json() == {
        "id": 1,
        "session": None,
    }
    assert client.post("/validate", json={"email": "ada@example.com", "password": "wrong"}).json()["id"] is None
    assert client.post("/validate", json={"email": "nobody@example.com", "password": "x"}).json()["id"] is None
    assert COOKIE not in client.cookies


async def test_session_token_starts_a_guest_session_for_forms(facade_app):
    api, manager = facade_app
    client = TestClient(api, base_url="https://testserver")
    body = client.get("/csrf-token").json()
    assert (manager.session_store.find(body["id"])).csrf_token == body["token"]
    assert client.cookies.get(COOKIE) == body["id"]
    assert client.get("/csrf-token").json() == body
