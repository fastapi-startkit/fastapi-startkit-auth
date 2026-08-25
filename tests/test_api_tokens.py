"""Phase 3 API token authentication: opaque ``id|secret`` tokens + TokenGuard.

Covers the repository contract against both bundled stores, the manager's
issue/verify/revoke/list lifecycle, the at-rest hashing and enumeration-safety
guarantees, and the guard wired end-to-end through ``current_user`` /
``optional_user`` / ability enforcement.
"""
import hashlib
import sqlite3
import time

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from fastapi_startkit_auth import (
    AuthConfig,
    InvalidToken,
    current_user,
    optional_user,
    register_auth,
    require_abilities,
    require_scopes,
)
from fastapi_startkit_auth.apitokens.manager import ApiTokenManager
from fastapi_startkit_auth.apitokens.repository import (
    ApiTokenRepository,
    InMemoryApiTokenRepository,
)
from fastapi_startkit_auth.apitokens.sql import SqlApiTokenRepository
from fastapi_startkit_auth.guards.token import TokenGuard
from fastapi_startkit_auth.providers.memory import InMemoryUserProvider
from fastapi_startkit_auth.security.hashing import BcryptHasher

USERS = (
    {"id": 1, "email": "ada@example.com", "password": "secret"},
    {"id": 2, "email": "grace@example.com", "password": "hopper"},
)


def sha256(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


# --- repository contract (both stores) --------------------------------


@pytest.fixture(params=["memory", "sql"])
def repo(request):
    if request.param == "memory":
        return InMemoryApiTokenRepository()
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    return SqlApiTokenRepository(conn)


def create_record(repo, user_id=1, expires_at=None, abilities=("*",), name=None):
    return repo.create(
        user_id=user_id,
        token_hash=sha256("s3cret"),
        name=name,
        abilities=list(abilities),
        expires_at=expires_at,
    )


def test_create_returns_populated_record(repo):
    record = create_record(repo, name="cli", abilities=("posts:read",))
    assert record.id
    assert record.user_id == 1
    assert record.token_hash == sha256("s3cret")
    assert record.name == "cli"
    assert record.abilities == ["posts:read"]
    assert record.last_used_at is None
    assert record.expires_at is None
    assert record.created_at <= time.time()


def test_create_generates_unique_ids(repo):
    ids = {create_record(repo).id for _ in range(20)}
    assert len(ids) == 20


def test_find_round_trips_the_record(repo):
    created = create_record(repo, name="cli", abilities=("a", "b"), expires_at=time.time() + 60)
    found = repo.find(created.id)
    assert found is not None
    assert found.id == created.id
    assert found.user_id == created.user_id
    assert found.token_hash == created.token_hash
    assert found.name == "cli"
    assert found.abilities == ["a", "b"]
    assert found.expires_at == pytest.approx(created.expires_at)


@pytest.mark.parametrize("user_id", [1, "uuid-42"])
def test_user_id_type_round_trips(repo, user_id):
    created = create_record(repo, user_id=user_id)
    assert repo.find(created.id).user_id == user_id


def test_find_unknown_id_returns_none(repo):
    assert repo.find("missing") is None


def test_find_expired_token_returns_none(repo):
    record = create_record(repo, expires_at=time.time() - 1)
    assert repo.find(record.id) is None


def test_touch_updates_last_used_at(repo):
    record = create_record(repo)
    repo.touch(record.id)
    assert repo.find(record.id).last_used_at == pytest.approx(time.time(), abs=5)


def test_revoke_deletes_the_record(repo):
    record = create_record(repo)
    assert repo.revoke(record.id) is True
    assert repo.find(record.id) is None
    assert repo.revoke(record.id) is False


def test_revoke_all_for_user_only_hits_that_user(repo):
    create_record(repo, user_id=1)
    create_record(repo, user_id=1)
    other = create_record(repo, user_id=2)
    assert repo.revoke_all_for_user(1) == 2
    assert repo.list_for_user(1) == []
    assert repo.find(other.id) is not None


def test_list_for_user_excludes_expired_and_other_users(repo):
    live = create_record(repo, user_id=1)
    create_record(repo, user_id=1, expires_at=time.time() - 1)
    create_record(repo, user_id=2)
    listed = repo.list_for_user(1)
    assert [rec.id for rec in listed] == [live.id]


def test_purge_expired_drops_only_dead_tokens(repo):
    live = create_record(repo)
    dead = create_record(repo, expires_at=time.time() - 1)
    repo.purge_expired()
    assert repo.find(live.id) is not None
    assert repo.find(dead.id) is None


def test_both_implementations_satisfy_the_protocol(repo):
    assert isinstance(repo, ApiTokenRepository)


# --- manager: issue / verify / revoke / list --------------------------


@pytest.fixture
def tokens():
    return ApiTokenManager(InMemoryApiTokenRepository())


def test_plaintext_is_id_pipe_secret(tokens):
    issued = tokens.create(user_id=1, name="cli")
    token_id, sep, secret = issued.plain_text.partition("|")
    assert sep == "|"
    assert token_id == issued.record.id
    assert len(secret) >= 40


def test_only_the_hash_is_stored_at_rest(tokens):
    issued = tokens.create(user_id=1)
    secret = issued.plain_text.partition("|")[2]
    stored = tokens.repository.find(issued.record.id)
    assert stored.token_hash == sha256(secret)
    assert secret not in stored.token_hash


def test_sql_store_never_sees_the_plaintext():
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    tokens = ApiTokenManager(SqlApiTokenRepository(conn))
    issued = tokens.create(user_id=1, name="cli")
    secret = issued.plain_text.partition("|")[2]
    for row in conn.execute("SELECT * FROM personal_api_tokens").fetchall():
        for column in row:
            assert secret not in str(column)


def test_repr_never_leaks_the_secret(tokens):
    issued = tokens.create(user_id=1, name="cli")
    secret = issued.plain_text.partition("|")[2]
    rendered = repr(issued)
    assert secret not in rendered
    assert issued.plain_text not in rendered
    # Still useful for debugging: the public id half stays visible.
    assert issued.record.id in rendered
    assert "***redacted***" in rendered


def test_verify_returns_the_record_and_touches_it(tokens):
    issued = tokens.create(user_id=1, abilities=["posts:read"])
    record = tokens.verify(issued.plain_text)
    assert record.id == issued.record.id
    assert record.abilities == ["posts:read"]
    assert tokens.repository.find(record.id).last_used_at is not None


def test_abilities_default_to_wildcard(tokens):
    issued = tokens.create(user_id=1)
    assert issued.record.abilities == ["*"]


def test_verify_rejects_wrong_secret(tokens):
    issued = tokens.create(user_id=1)
    with pytest.raises(InvalidToken):
        tokens.verify(f"{issued.record.id}|wrong-secret")


def test_verify_rejects_unknown_id(tokens):
    tokens.create(user_id=1)
    with pytest.raises(InvalidToken):
        tokens.verify("unknown|some-secret")


@pytest.mark.parametrize("malformed", ["", "|", "no-pipe", "id|", "|secret"])
def test_verify_rejects_malformed_tokens(tokens, malformed):
    with pytest.raises(InvalidToken):
        tokens.verify(malformed)


def test_verify_rejects_expired_tokens(tokens):
    issued = tokens.create(user_id=1, expires_at=time.time() - 1)
    with pytest.raises(InvalidToken):
        tokens.verify(issued.plain_text)


def test_verify_rejects_revoked_tokens(tokens):
    issued = tokens.create(user_id=1)
    assert tokens.revoke(issued.record.id) is True
    with pytest.raises(InvalidToken):
        tokens.verify(issued.plain_text)


def test_all_failures_share_one_generic_message(tokens):
    issued = tokens.create(user_id=1)
    expired = tokens.create(user_id=1, expires_at=time.time() - 1)
    failures = [
        f"{issued.record.id}|wrong-secret",   # bad secret, live id
        "unknown|some-secret",                # unknown id
        expired.plain_text,                   # expired
        "malformed-token",                    # no separator
    ]
    messages = set()
    for attempt in failures:
        with pytest.raises(InvalidToken) as excinfo:
            tokens.verify(attempt)
        messages.add(str(excinfo.value))
    assert len(messages) == 1


def test_default_ttl_from_config_applies(tokens):
    limited = ApiTokenManager(InMemoryApiTokenRepository(), default_ttl=60)
    issued = limited.create(user_id=1)
    assert issued.record.expires_at == pytest.approx(time.time() + 60, abs=5)


def test_explicit_expires_at_overrides_default_ttl():
    limited = ApiTokenManager(InMemoryApiTokenRepository(), default_ttl=60)
    deadline = time.time() + 5
    issued = limited.create(user_id=1, expires_at=deadline)
    assert issued.record.expires_at == deadline


def test_revoke_all_and_list(tokens):
    a = tokens.create(user_id=1, name="a")
    tokens.create(user_id=1, name="b")
    other = tokens.create(user_id=2, name="c")
    assert {rec.name for rec in tokens.tokens_for(1)} == {"a", "b"}
    assert tokens.revoke_all(1) == 2
    assert tokens.tokens_for(1) == []
    tokens.verify(other.plain_text)
    with pytest.raises(InvalidToken):
        tokens.verify(a.plain_text)


def test_create_opportunistically_purges_expired_tokens():
    eager = ApiTokenManager(InMemoryApiTokenRepository(), purge_interval=0)
    dead = eager.create(user_id=1, expires_at=time.time() - 1)
    eager.create(user_id=1)
    assert eager.repository._tokens.get(dead.record.id) is None


def test_purge_on_create_respects_the_interval():
    lazy = ApiTokenManager(InMemoryApiTokenRepository(), purge_interval=3600)
    dead = lazy.create(user_id=1, expires_at=time.time() - 1)
    lazy.create(user_id=1)
    # Interval not elapsed: the expired row is still sitting in the store.
    assert dead.record.id in lazy.repository._tokens


# --- guard + dependencies end-to-end ----------------------------------


def seeded_provider(users=USERS):
    hasher = BcryptHasher(rounds=4)
    provider = InMemoryUserProvider(hasher=hasher, username_field="email")
    for user in users:
        row = dict(user)
        row["password"] = hasher.make(row["password"])
        provider.add(row)
    return provider


def token_config(api_tokens=None, guards=None, default=None):
    provider = seeded_provider()

    class Config(AuthConfig):
        key = "api-token-tests-secret-32-bytes-minimum!"
        bcrypt_rounds = 4
        providers = {"users": {"driver": "instance", "instance": provider}}

    Config.default = default or {"guard": "api", "passwords": "users"}
    Config.guards = guards or {"api": {"driver": "token", "provider": "users"}}
    Config.api_tokens = api_tokens or {}
    return Config


def wire_routes(api):
    @api.get("/me")
    def me(user=Depends(current_user)):
        return user

    @api.get("/maybe")
    def maybe(user=Depends(optional_user)):
        return {"user": user}

    @api.get("/needs-read")
    def needs_read(ctx=Depends(require_abilities("posts:read"))):
        return {"ok": True}


def make_client(api_tokens=None, guards=None, default=None):
    api = FastAPI()
    manager = register_auth(api, token_config(api_tokens=api_tokens, guards=guards, default=default))
    wire_routes(api)
    return TestClient(api), manager


SQL_API_TOKENS = {
    "store": "sql",
    "connection": lambda: sqlite3.connect(":memory:", check_same_thread=False),
}


@pytest.fixture(params=["memory", "sql"])
def guard_client(request):
    return make_client(api_tokens=SQL_API_TOKENS if request.param == "sql" else None)


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def test_bearer_token_resolves_the_user(guard_client):
    client, manager = guard_client
    issued = manager.api_tokens.create(user_id=1, name="cli")
    response = client.get("/me", headers=bearer(issued.plain_text))
    assert response.status_code == 200
    assert response.json()["email"] == "ada@example.com"


def test_missing_token_is_401(guard_client):
    client, _ = guard_client
    response = client.get("/me")
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_token"


def test_wrong_secret_is_a_generic_401(guard_client):
    client, manager = guard_client
    issued = manager.api_tokens.create(user_id=1)
    response = client.get("/me", headers=bearer(f"{issued.record.id}|forged"))
    assert response.status_code == 401
    unknown = client.get("/me", headers=bearer("unknown-id|forged"))
    assert response.json() == unknown.json()


def test_revoked_token_is_401(guard_client):
    client, manager = guard_client
    issued = manager.api_tokens.create(user_id=1)
    assert client.get("/me", headers=bearer(issued.plain_text)).status_code == 200
    manager.api_tokens.revoke(issued.record.id)
    assert client.get("/me", headers=bearer(issued.plain_text)).status_code == 401


def test_expired_token_is_401(guard_client):
    client, manager = guard_client
    issued = manager.api_tokens.create(user_id=1, expires_at=time.time() - 1)
    assert client.get("/me", headers=bearer(issued.plain_text)).status_code == 401


def test_optional_user_returns_none_without_token(guard_client):
    client, manager = guard_client
    assert client.get("/maybe").json() == {"user": None}
    issued = manager.api_tokens.create(user_id=2)
    body = client.get("/maybe", headers=bearer(issued.plain_text)).json()
    assert body["user"]["email"] == "grace@example.com"


def test_abilities_gate_require_scopes(guard_client):
    client, manager = guard_client
    reader = manager.api_tokens.create(user_id=1, abilities=["posts:read"])
    limited = manager.api_tokens.create(user_id=1, abilities=["posts:write"])
    unrestricted = manager.api_tokens.create(user_id=1)
    assert client.get("/needs-read", headers=bearer(reader.plain_text)).status_code == 200
    assert client.get("/needs-read", headers=bearer(unrestricted.plain_text)).status_code == 200
    denied = client.get("/needs-read", headers=bearer(limited.plain_text))
    assert denied.status_code == 403
    assert denied.json()["error"] == "insufficient_scope"


def test_require_abilities_is_require_scopes():
    assert require_abilities is require_scopes


def test_configurable_token_header():
    client, manager = make_client(api_tokens={"header": "X-Api-Token"})
    issued = manager.api_tokens.create(user_id=1)
    assert client.get("/me", headers={"X-Api-Token": issued.plain_text}).status_code == 200
    # The default Authorization header is no longer consulted.
    assert client.get("/me", headers=bearer(issued.plain_text)).status_code == 401


def test_default_ttl_flows_from_config():
    _, manager = make_client(api_tokens={"ttl": 120})
    issued = manager.api_tokens.create(user_id=1)
    assert issued.record.expires_at == pytest.approx(time.time() + 120, abs=5)


def test_token_guard_coexists_with_passport_guard():
    client, manager = make_client(
        guards={
            "api": {"driver": "passport", "provider": "users"},
            "mobile": {"driver": "token", "provider": "users"},
        }
    )
    issued = manager.api_tokens.create(user_id=1)
    context = manager.guard("mobile").user_from_token(issued.plain_text)
    assert context.user["id"] == 1
    # The default passport guard still owns the OAuth2 routes and JWT flow.
    jwt_token = manager.token_service.issue(user_id=1, client_id=None, scopes=["*"])
    response = client.get("/me", headers=bearer(jwt_token.access_token))
    assert response.status_code == 200


def test_unknown_api_token_store_raises():
    from fastapi_startkit_auth.manager import AuthManager

    with pytest.raises(ValueError, match="Unknown api_tokens store"):
        AuthManager(token_config(api_tokens={"store": "redis"})).api_tokens


def test_sql_store_requires_a_connection():
    from fastapi_startkit_auth.manager import AuthManager

    with pytest.raises(ValueError, match="requires a \"connection\""):
        AuthManager(token_config(api_tokens={"store": "sql"})).api_tokens


def test_sql_store_accepts_a_raw_connection():
    """A raw connection is itself callable; the store must not misfire the
    factory branch and call it (regression for the callable() detection)."""
    from fastapi_startkit_auth.manager import AuthManager

    conn = sqlite3.connect(":memory:", check_same_thread=False)
    manager = AuthManager(
        token_config(api_tokens={"store": "sql", "connection": conn})
    )
    repo = manager.api_tokens.repository
    assert isinstance(repo, SqlApiTokenRepository)
    issued = manager.api_tokens.create(user_id=1, name="cli")
    assert manager.api_tokens.repository.find(issued.record.id) is not None


def test_instance_store_is_used_verbatim():
    from fastapi_startkit_auth.manager import AuthManager

    repository = InMemoryApiTokenRepository()
    manager = AuthManager(token_config(api_tokens={"store": "instance", "instance": repository}))
    assert manager.api_tokens.repository is repository


def test_guard_satisfies_the_guard_protocol():
    from fastapi_startkit_auth.guards.guard import Guard

    _, manager = make_client()
    assert isinstance(manager.guard("api"), Guard)
    assert isinstance(manager.guard("api"), TokenGuard)


def test_orphaned_token_fails_generically_and_is_revoked(tokens):
    provider = seeded_provider()
    guard = TokenGuard(name="api", tokens=tokens, provider=provider)
    issued = tokens.create(user_id=999)  # no such user
    with pytest.raises(InvalidToken):
        guard.user_from_token(issued.plain_text)
    assert tokens.repository.find(issued.record.id) is None
