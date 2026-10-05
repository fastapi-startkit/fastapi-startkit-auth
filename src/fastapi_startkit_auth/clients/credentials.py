from __future__ import annotations

import secrets
import uuid

from starlette.concurrency import run_in_threadpool

from ..security.hashing import Hasher
from .models import Client


async def new_client(
    hasher: Hasher,
    *,
    name: str,
    redirect_uris: list[str] | None = None,
    confidential: bool = True,
    grant_types: list[str] | None = None,
    provider: str | None = None,
    scopes: list[str] | None = None,
) -> tuple[Client, str | None]:
    """Build a client with a fresh id, returning it with its plaintext secret (``None`` when public)."""
    plain_secret = secrets.token_urlsafe(40) if confidential else None
    client = Client(
        id=uuid.uuid4().hex,
        name=name,
        redirect_uris=list(redirect_uris or []),
        confidential=confidential,
        grant_types=list(grant_types or []),
        provider=provider,
        scopes=[] if scopes is None else scopes,
    )
    if plain_secret is not None:
        # bcrypt is deliberately slow; keep it off the event loop.
        client.secret = await run_in_threadpool(hasher.make, plain_secret)
    return client, plain_secret


async def verified_client(hasher: Hasher, client: Client | None, secret: str | None) -> Client | None:
    if client is None or client.revoked:
        return None
    if not client.confidential:
        return client
    if secret is None or client.secret is None:
        return None
    return client if await run_in_threadpool(hasher.verify, secret, client.secret) else None
