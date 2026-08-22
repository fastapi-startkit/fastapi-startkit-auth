"""Contract tests for the session stores.

Every test runs against BOTH implementations (in-memory and SQL) through the
parametrized factory, so the two backends are guaranteed interchangeable.
"""
import sqlite3
import time

import pytest

from fastapi_startkit_auth.sessions import (
    InMemorySessionStore,
    SessionStore,
    SqlSessionStore,
)


@pytest.fixture(params=["memory", "sql"])
def make_store(request):
    def _make(idle_ttl=None):
        if request.param == "memory":
            return InMemorySessionStore(idle_ttl=idle_ttl)
        conn = sqlite3.connect(":memory:", check_same_thread=False)
        return SqlSessionStore(conn, idle_ttl=idle_ttl)

    return _make


@pytest.fixture
def store(make_store):
    return make_store()


def test_create_returns_populated_record(store):
    record = store.create(user_id=1, guard="web", ttl=3600)
    assert record.id
    assert record.csrf_token
    assert record.user_id == 1
    assert record.guard == "web"
    assert record.expires_at == pytest.approx(record.created_at + 3600)


def test_create_generates_unique_ids_and_csrf_tokens(store):
    a = store.create(user_id=1, guard="web", ttl=3600)
    b = store.create(user_id=1, guard="web", ttl=3600)
    assert a.id != b.id
    assert a.csrf_token != b.csrf_token


def test_find_round_trips_the_record(store):
    created = store.create(user_id=1, guard="web", ttl=3600)
    found = store.find(created.id)
    assert found is not None
    assert found.id == created.id
    assert found.user_id == created.user_id
    assert found.guard == created.guard
    assert found.csrf_token == created.csrf_token


@pytest.mark.parametrize("user_id", [1, "uuid-abc-123"])
def test_user_id_type_round_trips(store, user_id):
    created = store.create(user_id=user_id, guard="web", ttl=3600)
    assert store.find(created.id).user_id == user_id


def test_find_unknown_id_returns_none(store):
    assert store.find("no-such-session") is None


def test_find_expired_session_returns_none(store):
    record = store.create(user_id=1, guard="web", ttl=-1)
    assert store.find(record.id) is None


def test_null_ttl_means_no_absolute_expiry(store):
    record = store.create(user_id=1, guard="web", ttl=None)
    assert record.expires_at is None
    assert store.find(record.id) is not None


def test_invalidate_deletes_server_side(store):
    record = store.create(user_id=1, guard="web", ttl=3600)
    assert store.invalidate(record.id) is True
    assert store.find(record.id) is None
    assert store.invalidate(record.id) is False


def test_regenerate_id_rekeys_and_kills_old_id(store):
    record = store.create(user_id=1, guard="web", ttl=3600)
    old_id = record.id
    regenerated = store.regenerate_id(old_id)
    assert regenerated is not None
    assert regenerated.id != old_id
    assert store.find(old_id) is None
    found = store.find(regenerated.id)
    assert found.user_id == 1
    assert found.csrf_token == record.csrf_token


def test_regenerate_unknown_id_returns_none(store):
    assert store.regenerate_id("no-such-session") is None


def test_touch_updates_last_activity(store):
    record = store.create(user_id=1, guard="web", ttl=3600)
    before = store.find(record.id).last_activity
    time.sleep(0.01)
    store.touch(record.id)
    assert store.find(record.id).last_activity > before


def test_idle_ttl_expires_inactive_sessions(make_store):
    store = make_store(idle_ttl=-1)
    record = store.create(user_id=1, guard="web", ttl=None)
    assert store.find(record.id) is None


def test_touch_slides_the_idle_window(make_store):
    store = make_store(idle_ttl=0.08)
    record = store.create(user_id=1, guard="web", ttl=None)
    time.sleep(0.05)
    store.touch(record.id)
    time.sleep(0.05)
    # 0.1s after creation but only 0.05s after last activity: still alive.
    assert store.find(record.id) is not None


def test_purge_expired_drops_only_dead_sessions(store):
    dead = store.create(user_id=1, guard="web", ttl=-1)
    alive = store.create(user_id=2, guard="web", ttl=3600)
    store.purge_expired()
    assert store.find(dead.id) is None
    assert store.find(alive.id) is not None


def test_both_implementations_satisfy_the_protocol(store):
    assert isinstance(store, SessionStore)
