from __future__ import annotations

import secrets
import time
from typing import Any

from ..clients.models import Client
from ..concurrency import call
from ..exceptions import InvalidClient, InvalidGrant
from ..policy import GrantPolicy, ensure_client_may, ensure_same_resource, ensure_valid_verifier
from ..tokens.service import IssuedToken, TokenService
from ..tokens.models import AuthorizationCode
from .pkce import verify_pkce
from .refresh import OwnerProviderResolver, ensure_owner_active, ensure_owner_active_async, owner_resolver


def _validate_request(
    policy: GrantPolicy,
    client: Client,
    redirect_uri: str | None,
    scopes: list[str],
    code_challenge: str | None,
    code_challenge_method: str | None,
    resource: str | None,
) -> None:
    ensure_client_may(client, "authorization_code")
    policy.check_redirect(client, redirect_uri)
    policy.check_pkce(client.confidential, code_challenge, code_challenge_method)
    policy.check_scopes(scopes)
    policy.check_resource(resource)


def _validate_exchange(
    record: AuthorizationCode | None,
    client: Client,
    redirect_uri: str | None,
    code_verifier: str | None,
    client_authenticated: bool,
    resource: str | None,
) -> None:
    ensure_client_may(client, "authorization_code")
    if client.confidential and not client_authenticated:
        raise InvalidClient("Confidential clients must authenticate to exchange a code.")
    if record is None or record.expired:
        raise InvalidGrant("The authorization code is invalid or expired.")
    if record.client_id != client.id:
        raise InvalidGrant("The authorization code was issued to a different client.")
    if record.redirect_uri != redirect_uri:
        raise InvalidGrant("The redirect URI does not match the authorization request.")
    # PKCE is mandatory unless the client proved its identity with a secret.
    if not client_authenticated and not record.code_challenge:
        raise InvalidGrant("PKCE is required: this code was not bound to a code_challenge.")
    if record.code_challenge:
        ensure_valid_verifier(code_verifier)
        if not verify_pkce(code_verifier, record.code_challenge, record.code_challenge_method):
            raise InvalidGrant("PKCE verification failed.")
    ensure_same_resource(record.resource, resource)


class AuthorizationCodeGrant:
    """Authorization-code grant with PKCE (RFC 6749 §4.1 + RFC 7636).

    PKCE is mandatory for public (secretless) clients and for any exchange where
    the client did not authenticate — both at code issuance (a public client
    cannot obtain a code without a ``code_challenge``) and at exchange (the
    verifier must match). Confidential clients that authenticate may omit PKCE,
    but any challenge they do supply is still verified.

    ``issue_code`` is called after the resource owner approves a request;
    ``handle`` exchanges the resulting single-use code for tokens.
    """

    def __init__(
        self,
        token_service: TokenService,
        code_ttl: int = 600,
        user_provider: Any = None,
        owner_provider: OwnerProviderResolver | None = None,
        policy: GrantPolicy | None = None,
    ) -> None:
        self._tokens = token_service
        self._code_ttl = code_ttl
        self._policy = policy or GrantPolicy()
        self._owner_provider = owner_resolver(user_provider, owner_provider)

    def validate_request(
        self,
        *,
        client: Client,
        redirect_uri: str | None,
        scopes: list[str],
        code_challenge: str | None,
        code_challenge_method: str | None,
        resource: str | None = None,
    ) -> None:
        """Reject an authorization request before the user is asked to approve it."""
        _validate_request(
            self._policy, client, redirect_uri, scopes, code_challenge, code_challenge_method, resource
        )

    def issue_code(
        self,
        *,
        client: Client,
        user_id: Any,
        scopes: list[str],
        redirect_uri: str | None,
        code_challenge: str | None,
        code_challenge_method: str | None,
        resource: str | None = None,
    ) -> str:
        _validate_request(
            self._policy, client, redirect_uri, scopes, code_challenge, code_challenge_method, resource
        )
        code = secrets.token_urlsafe(40)
        self._tokens.repository.store_auth_code(
            code=code,
            client_id=client.id,
            user_id=user_id,
            scopes=scopes,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            expires_at=time.time() + self._code_ttl,
            resource=resource,
        )
        return code

    def handle(
        self,
        *,
        client: Client,
        code: str,
        redirect_uri: str | None,
        code_verifier: str | None,
        client_authenticated: bool = False,
        resource: str | None = None,
    ) -> IssuedToken:
        record = self._tokens.repository.pull_auth_code(code)
        _validate_exchange(record, client, redirect_uri, code_verifier, client_authenticated, resource)
        ensure_owner_active(self._owner_provider(client.id), record.user_id)
        return self._tokens.issue(
            user_id=record.user_id,
            client_id=client.id,
            scopes=record.scopes,
            with_refresh=True,
            audience=record.resource,
        )


class AsyncAuthorizationCodeGrant:
    def __init__(
        self,
        token_service: Any,
        code_ttl: int = 600,
        user_provider: Any = None,
        owner_provider: OwnerProviderResolver | None = None,
        policy: GrantPolicy | None = None,
    ) -> None:
        self._tokens = token_service
        self._code_ttl = code_ttl
        self._policy = policy or GrantPolicy()
        self._owner_provider = owner_resolver(user_provider, owner_provider)

    def validate_request(
        self,
        *,
        client: Client,
        redirect_uri: str | None,
        scopes: list[str],
        code_challenge: str | None,
        code_challenge_method: str | None,
        resource: str | None = None,
    ) -> None:
        """Reject an authorization request before the user is asked to approve it."""
        _validate_request(
            self._policy, client, redirect_uri, scopes, code_challenge, code_challenge_method, resource
        )

    async def issue_code(
        self,
        *,
        client: Client,
        user_id: Any,
        scopes: list[str],
        redirect_uri: str | None,
        code_challenge: str | None,
        code_challenge_method: str | None,
        resource: str | None = None,
    ) -> str:
        _validate_request(
            self._policy, client, redirect_uri, scopes, code_challenge, code_challenge_method, resource
        )
        code = secrets.token_urlsafe(40)
        await call(
            self._tokens.repository.store_auth_code,
            code=code,
            client_id=client.id,
            user_id=user_id,
            scopes=scopes,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            expires_at=time.time() + self._code_ttl,
            resource=resource,
        )
        return code

    async def handle(
        self,
        *,
        client: Client,
        code: str,
        redirect_uri: str | None,
        code_verifier: str | None,
        client_authenticated: bool = False,
        resource: str | None = None,
    ) -> IssuedToken:
        record = await call(self._tokens.repository.pull_auth_code, code)
        _validate_exchange(record, client, redirect_uri, code_verifier, client_authenticated, resource)
        await ensure_owner_active_async(await call(self._owner_provider, client.id), record.user_id)
        return await call(
            self._tokens.issue,
            user_id=record.user_id,
            client_id=client.id,
            scopes=record.scopes,
            with_refresh=True,
            audience=record.resource,
        )
