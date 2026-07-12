from __future__ import annotations

import secrets
import time
from typing import Any

from ..clients.models import Client
from ..exceptions import InvalidGrant, InvalidRequest
from ..tokens.service import IssuedToken, TokenService
from .pkce import verify_pkce


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

    def __init__(self, token_service: TokenService, code_ttl: int = 600) -> None:
        self._tokens = token_service
        self._code_ttl = code_ttl

    def issue_code(
        self,
        *,
        client: Client,
        user_id: Any,
        scopes: list[str],
        redirect_uri: str | None,
        code_challenge: str | None,
        code_challenge_method: str | None,
    ) -> str:
        if not client.confidential and not code_challenge:
            raise InvalidRequest("A PKCE code_challenge is required for public clients.")
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
    ) -> IssuedToken:
        record = self._tokens.repository.pull_auth_code(code)
        if record is None or record.expired:
            raise InvalidGrant("The authorization code is invalid or expired.")
        if record.client_id != client.id:
            raise InvalidGrant("The authorization code was issued to a different client.")
        if record.redirect_uri != redirect_uri:
            raise InvalidGrant("The redirect URI does not match the authorization request.")
        # PKCE is mandatory unless the client proved its identity with a secret.
        pkce_required = not client_authenticated
        if pkce_required and not record.code_challenge:
            raise InvalidGrant("PKCE is required: this code was not bound to a code_challenge.")
        if record.code_challenge:
            if not verify_pkce(code_verifier or "", record.code_challenge, record.code_challenge_method):
                raise InvalidGrant("PKCE verification failed.")
        return self._tokens.issue(
            user_id=record.user_id,
            client_id=client.id,
            scopes=record.scopes,
            with_refresh=True,
        )
