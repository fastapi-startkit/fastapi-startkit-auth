import pytest
from fastapi import Body, Depends, FastAPI

from fastapi_startkit_auth import AsyncAuth, AsyncChainGuard, Auth, AuthConfig, ChainGuard, GuardDependency
from fastapi_startkit_auth.config import ChainGuard as ChainGuardConfig
from fastapi_startkit_auth.config import OAuth2Guard, SessionGuard

from conftest import BrowserTestClient as TestClient
from conftest import auth_manager, oauth2_config, register_auth
from test_async_auth import USER_PROVIDER, users  # noqa: F401
from test_session_auth import session_config

GUARDS = {
    "api": OAuth2Guard(provider="users"),
    "web": SessionGuard(provider="users"),
    "auth.api": ChainGuardConfig(guards=["api", "web"]),
}


@pytest.fixture
def guarded_app():
    api = FastAPI()
    manager = register_auth(api, session_config(guards=GUARDS, default_guard="api"), session={}, oauth2=oauth2_config())

    @api.post("/login")
    def login(payload: dict = Body(...), auth: Auth = Depends(Auth.scoped)):
        return {"ok": auth.attempt(payload, guard="web")}

    @api.get("/me")
    def me(user=Depends(Auth.guard("auth.api"))):
        return {"id": user["id"]}

    @api.get("/bearer-only")
    def bearer_only(user=Depends(Auth.guard("api"))):
        return {"id": user["id"]}

    @api.get("/default")
    def default(user=Depends(Auth.guard())):
        return {"id": user["id"]}

    return api, manager


def bearer(manager, user_id=1, client_id=None):
    issued = manager.token_service.issue(user_id=user_id, client_id=client_id, scopes=["*"])
    return {"Authorization": f"Bearer {issued.access_token}"}


def test_guard_on_the_class_is_a_dependency_keyed_by_name():
    assert isinstance(Auth.guard("auth.api"), GuardDependency)
    assert Auth.guard("auth.api") == AsyncAuth.guard("auth.api")
    assert hash(Auth.guard("auth.api")) == hash(Auth.guard("auth.api"))
    assert Auth.guard("api") != Auth.guard("auth.api")


def test_guard_on_an_instance_is_the_configured_guard():
    manager = auth_manager(session_config(guards=GUARDS, default_guard="api"), session={}, oauth2=oauth2_config())
    auth = Auth(manager, request=None)
    assert auth.guard("auth.api") is manager.guard("auth.api")
    assert isinstance(auth.guard("auth.api"), ChainGuard)


def test_valid_bearer_token_resolves_the_user(guarded_app):
    api, manager = guarded_app
    client = TestClient(api, base_url="https://testserver")
    response = client.get("/me", headers=bearer(manager, user_id=2))
    assert response.status_code == 200
    assert response.json() == {"id": 2}


def test_default_guard_dependency_uses_the_default_guard(guarded_app):
    api, manager = guarded_app
    client = TestClient(api, base_url="https://testserver")
    assert client.get("/default", headers=bearer(manager)).json() == {"id": 1}


def test_missing_credentials_are_rejected_with_401(guarded_app):
    api, _ = guarded_app
    response = TestClient(api, base_url="https://testserver").get("/me")
    assert response.status_code == 401


def test_invalid_bearer_token_is_rejected_with_401(guarded_app):
    api, _ = guarded_app
    response = TestClient(api, base_url="https://testserver").get("/me", headers={"Authorization": "Bearer nope"})
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_token"


def test_client_credentials_token_without_a_user_is_rejected(guarded_app):
    api, manager = guarded_app
    issued = manager.token_service.issue(user_id=None, client_id="machine", scopes=["*"])
    response = TestClient(api, base_url="https://testserver").get(
        "/bearer-only", headers={"Authorization": f"Bearer {issued.access_token}"}
    )
    assert response.status_code == 401


def test_chain_falls_back_to_the_session(guarded_app):
    api, _ = guarded_app
    client = TestClient(api, base_url="https://testserver")
    assert client.post("/login", json={"email": "grace@example.com", "password": "hopper"}).json() == {"ok": True}
    assert client.get("/me").json() == {"id": 2}
    assert client.get("/bearer-only").status_code == 401


def test_dependency_overrides_key_on_the_guard_name(guarded_app):
    api, _ = guarded_app
    api.dependency_overrides[Auth.guard("auth.api")] = lambda: {"id": 99}
    assert TestClient(api, base_url="https://testserver").get("/me").json() == {"id": 99}


def test_chain_guard_rejects_unknown_members():
    guards = {"api": OAuth2Guard(provider="users"), "auth.api": ChainGuardConfig(guards=["api", "missing"])}
    manager = auth_manager(session_config(guards=guards, default_guard="api"), session={}, oauth2=oauth2_config())
    with pytest.raises(ValueError, match="'missing'"):
        manager.guard("auth.api")


def test_chain_guard_rejects_nested_chains():
    guards = {
        "api": OAuth2Guard(provider="users"),
        "inner": ChainGuardConfig(guards=["api"]),
        "outer": ChainGuardConfig(guards=["inner"]),
    }
    manager = auth_manager(session_config(guards=guards, default_guard="api"), session={}, oauth2=oauth2_config())
    with pytest.raises(ValueError, match="cannot include the chain guard 'inner'"):
        manager.guard("outer")


def test_chain_guard_needs_a_member():
    guards = {"api": OAuth2Guard(provider="users"), "empty": ChainGuardConfig()}
    manager = auth_manager(session_config(guards=guards, default_guard="api"), session={}, oauth2=oauth2_config())
    with pytest.raises(ValueError, match="at least one member"):
        manager.guard("empty")


def test_async_members_build_an_async_chain_that_resolves_token_and_session(users):
    class Config(AuthConfig):
        bcrypt_rounds = 4
        default = {"guard": "api", "passwords": "users"}
        guards = GUARDS
        providers = {"users": USER_PROVIDER}

    api = FastAPI()
    manager = register_auth(api, Config, session={}, oauth2=oauth2_config())

    @api.post("/login-as/{user_id}")
    async def login_as(user_id: int, auth: AsyncAuth = Depends(AsyncAuth.scoped)):
        await auth.login(user_id, guard="web")
        return {"ok": True}

    @api.get("/me")
    async def me(user=Depends(AsyncAuth.guard("auth.api"))):
        return {"id": user.id}

    assert isinstance(manager.guard("auth.api"), AsyncChainGuard)
    client = TestClient(api, base_url="https://testserver")
    assert client.get("/me").status_code == 401
    assert client.get("/me", headers=bearer(manager)).json() == {"id": 1}
    client.post("/login-as/1")
    assert client.get("/me").json() == {"id": 1}
