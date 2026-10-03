import pytest
from fastapi.testclient import TestClient

from fastapi_startkit_auth import Application, AuthConfig, AuthProvider, GrantPolicy
from fastapi_startkit_auth.clients.models import Client
from fastapi_startkit_auth.exceptions import InvalidRequest, InvalidScope, InvalidTarget, InvalidToken
from fastapi_startkit_auth.manager import AuthManager
from fastapi_startkit_auth.providers.memory import InMemoryUserProvider
from fastapi_startkit_auth.security.hashing import BcryptHasher

MCP = "https://api.example.com/mcp"
VERIFIER = "verifier-verifier-verifier-verifier-1234567890"


def _config():
    hasher = BcryptHasher(rounds=4)
    users = InMemoryUserProvider(hasher=hasher, username_field="email")
    users.add({"id": 1, "email": "ada@example.com", "password": hasher.make("secret")})

    class Config(AuthConfig):
        key = "resource-test-secret-key-32-bytes-minimum!"
        bcrypt_rounds = 4
        issuer = "https://auth.example.com"
        resources = [MCP]
        scopes = {"read": "Read", "content:write": "Write content"}
        pkce_methods = ["S256"]
        default = {"guard": "api"}
        guards = {
            "api": {"driver": "passport", "provider": "users"},
            "mcp": {"driver": "passport", "provider": "users", "audience": MCP},
        }
        providers = {"users": {"driver": "instance", "instance": users}}

    return Config


@pytest.fixture
def manager():
    return AuthManager(_config())


@pytest.fixture
def spa():
    return Client(id="spa", name="spa", confidential=False, redirect_uris=["https://spa/cb"])


def _code(manager, client, s256, resource=MCP, scopes=("read",)):
    return manager.authorization_code_grant().issue_code(
        client=client,
        user_id=1,
        scopes=list(scopes),
        redirect_uri="https://spa/cb",
        code_challenge=s256(VERIFIER),
        code_challenge_method="S256",
        resource=resource,
    )


def _exchange(manager, client, code, resource=MCP):
    return manager.authorization_code_grant().handle(
        client=client, code=code, redirect_uri="https://spa/cb", code_verifier=VERIFIER, resource=resource
    )


def test_code_exchange_binds_the_token_to_the_resource(manager, spa, s256):
    issued = _exchange(manager, spa, _code(manager, spa, s256))

    claims = manager.guard("mcp").user_from_token(issued.access_token)
    assert claims.user["id"] == 1
    assert manager.token_service.introspect(issued.access_token)["aud"] == MCP
    assert manager.token_service.introspect(issued.access_token)["iss"] == "https://auth.example.com"


def test_resource_bound_token_is_rejected_by_a_guard_without_that_audience(manager, spa, s256):
    issued = _exchange(manager, spa, _code(manager, spa, s256))

    with pytest.raises(InvalidToken):
        manager.guard("api").user_from_token(issued.access_token)


def test_unbound_token_is_rejected_by_the_audience_guard(manager):
    issued = manager.token_service.issue(user_id=1, client_id="c1", scopes=["read"])

    assert manager.guard("api").user_from_token(issued.access_token).user["id"] == 1
    with pytest.raises(InvalidToken):
        manager.guard("mcp").user_from_token(issued.access_token)


def test_unknown_resource_is_refused(manager, spa, s256):
    with pytest.raises(InvalidTarget):
        _code(manager, spa, s256, resource="https://evil.example.com/mcp")


def test_exchange_with_a_different_resource_is_refused(manager, spa, s256):
    code = _code(manager, spa, s256)

    with pytest.raises(InvalidTarget):
        _exchange(manager, spa, code, resource="https://other.example.com")


def test_unknown_scope_is_refused(manager, spa, s256):
    with pytest.raises(InvalidScope):
        _code(manager, spa, s256, scopes=("read", "admin"))


def test_plain_pkce_is_refused_when_only_s256_is_allowed(manager, spa):
    with pytest.raises(InvalidRequest):
        manager.authorization_code_grant().issue_code(
            client=spa,
            user_id=1,
            scopes=["read"],
            redirect_uri="https://spa/cb",
            code_challenge=VERIFIER,
            code_challenge_method="plain",
        )


def test_refresh_keeps_the_audience(manager, spa, s256):
    issued = _exchange(manager, spa, _code(manager, spa, s256))

    rotated = manager.refresh_grant().handle(refresh_token=issued.refresh_token, scopes=None)

    assert manager.guard("mcp").user_from_token(rotated.access_token).user["id"] == 1


def test_refresh_for_a_different_resource_is_refused(manager, spa, s256):
    issued = _exchange(manager, spa, _code(manager, spa, s256))

    with pytest.raises(InvalidTarget):
        manager.refresh_grant().handle(refresh_token=issued.refresh_token, scopes=None, resource="https://other")


def test_client_credentials_binds_the_resource(manager):
    service = Client(id="svc", name="svc", confidential=True)

    issued = manager.client_credentials_grant().handle(client=service, scopes=["content:write"], resource=MCP)

    assert manager.token_service.introspect(issued.access_token)["aud"] == MCP


def test_password_grant_checks_the_scope_catalog(manager):
    with pytest.raises(InvalidScope):
        manager.password_grant().handle(username="ada@example.com", password="secret", scopes=["admin"], client_id=None)


def test_default_policy_allows_any_scope_and_no_resource():
    policy = GrantPolicy()

    policy.check_scopes(["anything"])
    policy.check_pkce_method("challenge", "plain")
    with pytest.raises(InvalidTarget):
        policy.check_resource(MCP)


def test_token_endpoint_accepts_the_resource_parameter():
    application = Application([(AuthProvider, _config())])
    client = TestClient(application.api)
    manager = application.api.state.auth_manager
    registered, secret = manager.client_repository.register(name="svc", grant_types=["client_credentials"])

    response = client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": registered.id,
            "client_secret": secret,
            "scope": "content:write",
            "resource": MCP,
        },
    )
    assert response.status_code == 200, response.text
    assert manager.token_service.introspect(response.json()["access_token"])["aud"] == MCP

    refused = client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": registered.id,
            "client_secret": secret,
            "resource": "https://evil.example.com",
        },
    )
    assert refused.status_code == 400
    assert refused.json()["error"] == "invalid_target"
