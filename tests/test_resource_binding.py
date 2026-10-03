import pytest
from fastapi.testclient import TestClient

from fastapi_startkit_auth import Application, AuthConfig, AuthProvider, GrantPolicy
from fastapi_startkit_auth.clients.models import Client
from fastapi_startkit_auth.exceptions import InvalidGrant, InvalidRequest, InvalidScope, InvalidTarget, InvalidToken
from fastapi_startkit_auth.grants.authorization_code import AuthorizationCodeGrant
from fastapi_startkit_auth.guards.guard import AsyncPassportGuard
from fastapi_startkit_auth.manager import AuthManager
from fastapi_startkit_auth.providers.memory import InMemoryUserProvider
from fastapi_startkit_auth.security.hashing import BcryptHasher
from fastapi_startkit_auth.security.jwt import JWTEncoder
from fastapi_startkit_auth.tokens.repository import InMemoryTokenRepository
from fastapi_startkit_auth.tokens.service import AsyncTokenService, TokenService

MCP = "https://api.example.com/mcp"
VERIFIER = "verifier-verifier-verifier-verifier-1234567890"


def _config(**overrides):
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

    for name, value in overrides.items():
        setattr(Config, name, value)
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
    policy.check_pkce(False, "challenge", "plain")
    policy.check_pkce(True, None, None)
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


def _users():
    hasher = BcryptHasher(rounds=4)
    users = InMemoryUserProvider(hasher=hasher, username_field="email")
    users.add({"id": 1, "email": "ada@example.com", "password": hasher.make("secret")})
    return users


def test_default_policy_accepts_lowercase_s256(s256):
    service = TokenService(encoder=JWTEncoder(secret=_config().key))
    grant = AuthorizationCodeGrant(service)
    spa = Client(id="spa", name="spa", confidential=False, redirect_uris=["https://spa/cb"])

    code = grant.issue_code(
        client=spa,
        user_id=1,
        scopes=["read"],
        redirect_uri="https://spa/cb",
        code_challenge=s256(VERIFIER),
        code_challenge_method="s256",
    )

    issued = grant.handle(client=spa, code=code, redirect_uri="https://spa/cb", code_verifier=VERIFIER)
    assert service.authenticate(issued.access_token)["sub"] == "1"


def test_s256_only_refuses_a_challenge_without_method(manager, spa, s256):
    with pytest.raises(InvalidRequest):
        manager.authorization_code_grant().issue_code(
            client=spa,
            user_id=1,
            scopes=["read"],
            redirect_uri="https://spa/cb",
            code_challenge=s256(VERIFIER),
            code_challenge_method=None,
        )


def test_require_pkce_applies_to_confidential_clients():
    confidential = Client(id="web", name="web", confidential=True, redirect_uris=["https://web/cb"])
    request = dict(
        client=confidential,
        user_id=1,
        scopes=["read"],
        redirect_uri="https://web/cb",
        code_challenge=None,
        code_challenge_method=None,
    )

    assert AuthManager(_config()).authorization_code_grant().issue_code(**request)
    with pytest.raises(InvalidRequest):
        AuthManager(_config(require_pkce=True)).authorization_code_grant().issue_code(**request)


def test_unbound_code_redeemed_with_a_resource_is_refused(manager, spa, s256):
    code = _code(manager, spa, s256, resource=None)

    with pytest.raises(InvalidTarget):
        _exchange(manager, spa, code, resource=MCP)


def test_another_clients_code_fails_as_invalid_grant_before_the_resource_check(manager, spa, s256):
    code = _code(manager, spa, s256)
    thief = Client(id="thief", name="thief", confidential=False, redirect_uris=["https://spa/cb"])

    with pytest.raises(InvalidGrant):
        _exchange(manager, thief, code, resource="https://other.example.com")


def test_guard_refuses_a_wrong_or_missing_issuer(manager):
    for issuer in ("https://evil.example.com", None):
        foreign = TokenService(
            encoder=JWTEncoder(secret=_config().key, issuer=issuer), repository=manager.token_repository
        )
        issued = foreign.issue(user_id=1, client_id="c1", scopes=["read"])
        with pytest.raises(InvalidToken):
            manager.guard("api").user_from_token(issued.access_token)


async def test_async_service_and_guard_enforce_the_audience():
    service = AsyncTokenService(
        encoder=JWTEncoder(secret=_config().key, issuer="https://auth.example.com"),
        repository=InMemoryTokenRepository(),
    )
    users = _users()
    mcp_guard = AsyncPassportGuard("mcp", service, users, audience=MCP)
    api_guard = AsyncPassportGuard("api", service, users)

    bound = await service.issue(user_id=1, client_id="c1", scopes=["read"], with_refresh=True, audience=MCP)
    plain = await service.issue(user_id=1, client_id="c1", scopes=["read"])

    assert (await mcp_guard.user_from_token(bound.access_token)).user["id"] == 1
    assert (await api_guard.user_from_token(plain.access_token)).user["id"] == 1
    with pytest.raises(InvalidToken):
        await api_guard.user_from_token(bound.access_token)
    with pytest.raises(InvalidToken):
        await mcp_guard.user_from_token(plain.access_token)

    with pytest.raises(InvalidTarget):
        await service.refresh(bound.refresh_token, resource="https://other.example.com")
    rotated = await service.refresh(bound.refresh_token, resource=MCP)
    assert (await mcp_guard.user_from_token(rotated.access_token)).user["id"] == 1
    assert (await service.introspect(rotated.access_token))["aud"] == MCP


def test_guard_audience_outside_resources_warns():
    with pytest.warns(UserWarning, match="audience"):
        AuthManager(_config(resources=[]))


def test_authorize_exchange_and_refresh_over_http(s256):
    application = Application([(AuthProvider, _config())])
    client = TestClient(application.api)
    manager = application.api.state.auth_manager
    spa, _ = manager.client_repository.register(name="spa", redirect_uris=["https://spa/cb"], confidential=False)
    login = client.post(
        "/oauth/token", data={"grant_type": "password", "username": "ada@example.com", "password": "secret"}
    )
    user_token = login.json()["access_token"]

    authorized = client.post(
        "/oauth/authorize",
        json={
            "client_id": spa.id,
            "redirect_uri": "https://spa/cb",
            "scope": "read",
            "code_challenge": s256(VERIFIER),
            "resource": MCP,
        },
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert authorized.status_code == 200, authorized.text

    issued = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": authorized.json()["code"],
            "client_id": spa.id,
            "redirect_uri": "https://spa/cb",
            "code_verifier": VERIFIER,
            "resource": MCP,
        },
    )
    assert issued.status_code == 200, issued.text
    assert manager.token_service.introspect(issued.json()["access_token"])["aud"] == MCP

    refreshed = client.post(
        "/oauth/token",
        data={"grant_type": "refresh_token", "refresh_token": issued.json()["refresh_token"], "resource": MCP},
    )
    assert refreshed.status_code == 200, refreshed.text
    assert manager.token_service.introspect(refreshed.json()["access_token"])["aud"] == MCP


def test_repeated_resource_is_refused():
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
            "resource": ["https://evil.example.com", MCP],
        },
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_target"


def test_empty_resource_is_treated_as_absent():
    application = Application([(AuthProvider, _config())])
    client = TestClient(application.api)
    registered, secret = application.api.state.auth_manager.client_repository.register(
        name="svc", grant_types=["client_credentials"]
    )

    response = client.post(
        "/oauth/token",
        data={"grant_type": "client_credentials", "client_id": registered.id, "client_secret": secret, "resource": ""},
    )
    assert response.status_code == 200, response.text
    assert "aud" not in application.api.state.auth_manager.token_service.introspect(response.json()["access_token"])


def test_client_allowed_scopes_are_enforced(manager, s256):
    limited = Client(id="lim", name="lim", confidential=False, redirect_uris=["https://spa/cb"], scopes=["read"])

    assert _exchange(manager, limited, _code(manager, limited, s256)).scopes == ["read"]
    with pytest.raises(InvalidScope):
        _code(manager, limited, s256, scopes=("read", "content:write"))
    with pytest.raises(InvalidScope):
        manager.client_credentials_grant().handle(
            client=Client(id="svc", name="svc", scopes=["read"]), scopes=["content:write"]
        )


def test_password_route_enforces_client_scopes():
    application = Application([(AuthProvider, _config())])
    client = TestClient(application.api)
    registered, secret = application.api.state.auth_manager.client_repository.register(
        name="cli", grant_types=["password"], scopes=["read"]
    )

    response = client.post(
        "/oauth/token",
        data={
            "grant_type": "password",
            "username": "ada@example.com",
            "password": "secret",
            "scope": "content:write",
            "client_id": registered.id,
            "client_secret": secret,
        },
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_scope"
