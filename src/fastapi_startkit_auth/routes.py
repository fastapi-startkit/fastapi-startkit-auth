from __future__ import annotations

import base64
import binascii
from typing import Any
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, Request, Response
from pydantic import BaseModel

from .clients.models import Client
from .concurrency import call
from .dependencies import current_user, get_auth_manager
from .exceptions import (
    InvalidClient,
    InvalidGrant,
    InvalidRequest,
    ThrottleException,
    UnauthorizedClient,
    UnsupportedGrantType,
)
from .manager import AuthManager


# --- request bodies ------------------------------------------------------
class ClientCreate(BaseModel):
    name: str
    redirect_uris: list[str] = []
    confidential: bool = True
    grant_types: list[str] = []


class AuthorizeRequest(BaseModel):
    client_id: str
    redirect_uri: str | None = None
    scope: str = ""
    state: str | None = None
    code_challenge: str | None = None
    code_challenge_method: str | None = "S256"


class PersonalAccessTokenCreate(BaseModel):
    name: str
    scopes: list[str] = []


class ForgotPasswordRequest(BaseModel):
    email: str


class ResetPasswordRequest(BaseModel):
    email: str
    token: str
    password: str


def _scopes(raw: str | None) -> list[str]:
    return [s for s in (raw or "").split() if s]


def _client_credentials_from_request(
    request: Request, client_id: str | None, client_secret: str | None
) -> tuple[str | None, str | None]:
    """Prefer HTTP Basic auth for client credentials, falling back to form fields."""
    header = request.headers.get("authorization", "")
    if header.lower().startswith("basic "):
        try:
            decoded = base64.b64decode(header[6:]).decode("utf-8")
            cid, _, secret = decoded.partition(":")
            return cid, secret
        except (binascii.Error, UnicodeDecodeError):
            raise InvalidClient("Malformed Basic authorization header.")
    return client_id, client_secret


def _authenticate_client(manager: AuthManager, client_id: str, secret: str | None, grant: str) -> Client:
    client = manager.client_repository.authenticate(client_id, secret)
    if client is None:
        raise InvalidClient("Client authentication failed.")
    if not client.allows_grant(grant):
        raise UnauthorizedClient(f"Client is not authorized for the {grant} grant.")
    return client


def _require_authenticated_client(
    manager: AuthManager, request: Request, client_id: str | None, client_secret: str | None
) -> Client:
    """Authenticate the calling client for the introspection/revocation endpoints."""
    client_id, client_secret = _client_credentials_from_request(request, client_id, client_secret)
    if not client_id:
        raise InvalidClient("Client authentication is required.")
    client = manager.client_repository.authenticate(client_id, client_secret)
    if client is None:
        raise InvalidClient("Client authentication failed.")
    return client


def build_router(prefix: str = "") -> APIRouter:
    """Build the OAuth2/Passport router. Mounted onto the app by AuthProvider."""
    router = APIRouter(prefix=prefix)

    # --- unified token endpoint (RFC 6749 §3.2) -----------------------
    @router.post("/oauth/token")
    async def token(
        request: Request,
        grant_type: str = Form(...),
        username: str | None = Form(None),
        password: str | None = Form(None),
        scope: str | None = Form(None),
        refresh_token: str | None = Form(None),
        code: str | None = Form(None),
        redirect_uri: str | None = Form(None),
        code_verifier: str | None = Form(None),
        client_id: str | None = Form(None),
        client_secret: str | None = Form(None),
        manager: AuthManager = Depends(get_auth_manager),
    ) -> dict[str, Any]:
        client_id, client_secret = _client_credentials_from_request(request, client_id, client_secret)
        scopes = _scopes(scope)

        if grant_type == "password":
            if client_id:
                _authenticate_client(manager, client_id, client_secret, "password")
            issued = await call(
                manager.password_grant().handle,
                username=username or "",
                password=password or "",
                scopes=scopes,
                client_id=client_id,
            )
            return issued.to_response()

        if grant_type == "client_credentials":
            if not client_id:
                raise InvalidClient("client_id is required for the client_credentials grant.")
            client = _authenticate_client(manager, client_id, client_secret, "client_credentials")
            issued = await call(manager.client_credentials_grant().handle, client=client, scopes=scopes)
            return issued.to_response()

        if grant_type == "refresh_token":
            if not refresh_token:
                raise InvalidRequest("refresh_token is required.")
            if client_id:
                _authenticate_client(manager, client_id, client_secret, "refresh_token")
            issued = await call(manager.refresh_grant().handle, refresh_token=refresh_token, scopes=scopes or None)
            return issued.to_response()

        if grant_type == "authorization_code":
            if not code:
                raise InvalidRequest("code is required.")
            if not client_id:
                raise InvalidClient("client_id is required for the authorization_code grant.")
            client = manager.client_repository.find(client_id)
            if client is None:
                raise InvalidClient("Unknown client.")
            client_authenticated = False
            if client.confidential:
                _authenticate_client(manager, client_id, client_secret, "authorization_code")
                client_authenticated = True
            issued = await call(
                manager.authorization_code_grant().handle,
                client=client,
                code=code,
                redirect_uri=redirect_uri,
                code_verifier=code_verifier,
                client_authenticated=client_authenticated,
            )
            return issued.to_response()

        raise UnsupportedGrantType(f"Unsupported grant_type: {grant_type!r}")

    # --- simple password endpoint (FastAPI tutorial style) ------------
    @router.post("/token")
    async def simple_token(
        username: str = Form(...),
        password: str = Form(...),
        scope: str | None = Form(None),
        manager: AuthManager = Depends(get_auth_manager),
    ) -> dict[str, Any]:
        issued = await call(
            manager.password_grant().handle, username=username, password=password, scopes=_scopes(scope), client_id=None
        )
        return issued.to_response()

    # --- authorization endpoint (code + PKCE) -------------------------
    @router.post("/oauth/authorize")
    async def authorize(
        body: AuthorizeRequest,
        user=Depends(current_user),
        manager: AuthManager = Depends(get_auth_manager),
    ) -> dict[str, Any]:
        client = manager.client_repository.find(body.client_id)
        if client is None:
            raise InvalidClient("Unknown client.")
        if body.redirect_uri is not None and not client.allows_redirect(body.redirect_uri):
            raise InvalidRequest("redirect_uri is not registered for this client.")
        user_id = manager.guard().provider.get_identifier(user)
        code = await call(
            manager.authorization_code_grant().issue_code,
            client=client,
            user_id=user_id,
            scopes=_scopes(body.scope),
            redirect_uri=body.redirect_uri,
            code_challenge=body.code_challenge,
            code_challenge_method=body.code_challenge_method,
        )
        result: dict[str, Any] = {"code": code, "state": body.state}
        if body.redirect_uri:
            sep = "&" if "?" in body.redirect_uri else "?"
            params = {"code": code}
            if body.state is not None:
                params["state"] = body.state
            result["redirect_to"] = f"{body.redirect_uri}{sep}{urlencode(params)}"
        return result

    # --- introspection (RFC 7662) -------------------------------------
    @router.post("/oauth/introspect")
    async def introspect(
        request: Request,
        token: str = Form(...),
        client_id: str | None = Form(None),
        client_secret: str | None = Form(None),
        manager: AuthManager = Depends(get_auth_manager),
    ) -> dict[str, Any]:
        _require_authenticated_client(manager, request, client_id, client_secret)
        return await manager.introspect(token)

    # --- revocation (RFC 7009) ----------------------------------------
    @router.post("/oauth/revoke")
    async def revoke(
        request: Request,
        token: str = Form(...),
        token_type_hint: str | None = Form(None),
        client_id: str | None = Form(None),
        client_secret: str | None = Form(None),
        manager: AuthManager = Depends(get_auth_manager),
    ) -> dict[str, Any]:
        _require_authenticated_client(manager, request, client_id, client_secret)
        svc = manager.token_service
        # Try refresh first when hinted; otherwise decode as an access token.
        if token_type_hint == "refresh_token":
            await call(svc.revoke_refresh, token)
            return {"revoked": True}
        try:
            claims = svc.encoder.decode(token, verify_exp=False)
            await call(svc.revoke_access, claims.get("jti", ""))
        except Exception:
            await call(svc.revoke_refresh, token)
        return {"revoked": True}

    # --- client management --------------------------------------------
    @router.post("/oauth/clients", status_code=201)
    async def create_client(
        body: ClientCreate,
        manager: AuthManager = Depends(get_auth_manager),
    ) -> dict[str, Any]:
        client, secret = manager.client_repository.register(
            name=body.name,
            redirect_uris=body.redirect_uris,
            confidential=body.confidential,
            grant_types=body.grant_types,
        )
        return {
            "id": client.id,
            "name": client.name,
            "secret": secret,
            "redirect_uris": client.redirect_uris,
            "confidential": client.confidential,
            "grant_types": client.grant_types,
        }

    @router.get("/oauth/clients")
    async def list_clients(manager: AuthManager = Depends(get_auth_manager)) -> list[dict[str, Any]]:
        return [
            {
                "id": c.id,
                "name": c.name,
                "redirect_uris": c.redirect_uris,
                "confidential": c.confidential,
                "grant_types": c.grant_types,
            }
            for c in manager.client_repository.all()
        ]

    @router.delete("/oauth/clients/{client_id}", status_code=204)
    async def delete_client(client_id: str, manager: AuthManager = Depends(get_auth_manager)) -> Response:
        manager.client_repository.delete(client_id)
        return Response(status_code=204)

    # --- personal access tokens ---------------------------------------
    @router.post("/oauth/personal-access-tokens", status_code=201)
    async def create_pat(
        body: PersonalAccessTokenCreate,
        user=Depends(current_user),
        manager: AuthManager = Depends(get_auth_manager),
    ) -> dict[str, Any]:
        user_id = manager.guard().provider.get_identifier(user)
        issued = await call(
            manager.token_service.create_personal_access_token, user_id=user_id, name=body.name, scopes=body.scopes
        )
        return {
            "jti": issued.jti,
            "name": body.name,
            "access_token": issued.access_token,
            "scopes": issued.scopes,
            "expires_in": issued.expires_in,
        }

    @router.get("/oauth/personal-access-tokens")
    async def list_pats(
        user=Depends(current_user),
        manager: AuthManager = Depends(get_auth_manager),
    ) -> list[dict[str, Any]]:
        user_id = manager.guard().provider.get_identifier(user)
        records = await call(manager.token_service.repository.list_access_tokens, user_id, personal_access=True)
        return [
            {"jti": r.jti, "name": r.name, "scopes": r.scopes, "revoked": r.revoked} for r in records if not r.revoked
        ]

    @router.delete("/oauth/personal-access-tokens/{jti}", status_code=204)
    async def delete_pat(
        jti: str,
        user=Depends(current_user),
        manager: AuthManager = Depends(get_auth_manager),
    ) -> Response:
        record = await call(manager.token_service.repository.find_access_token, jti)
        user_id = manager.guard().provider.get_identifier(user)
        # Only allow owners to revoke their own tokens.
        if record is not None and record.user_id == user_id:
            await call(manager.token_service.revoke_access, jti)
        return Response(status_code=204)

    # --- password reset -----------------------------------------------
    @router.post("/password/email")
    async def send_reset_link(
        body: ForgotPasswordRequest,
        manager: AuthManager = Depends(get_auth_manager),
    ) -> dict[str, Any]:
        # Always respond identically whether or not the email exists, so the
        # endpoint can't be used to enumerate accounts. The token is delivered
        # out-of-band via the configured notifier, never in the HTTP response
        # (unless debug_expose_reset_token is explicitly enabled).
        #
        # A throttled request is also swallowed to a generic 200: throttling only
        # fires for existing accounts, so surfacing a 429 would let two rapid
        # requests distinguish registered from unregistered emails. The broker
        # still enforces the throttle server-side (no extra notification is sent).
        generic = {"status": "If that account exists, a reset link has been sent."}
        try:
            token = await call(manager.broker().send_reset_link, body.email)
        except (InvalidGrant, ThrottleException):
            return generic
        if manager.debug_expose_reset_token:
            return {**generic, "token": token}
        return generic

    @router.post("/password/reset")
    async def reset_password(
        body: ResetPasswordRequest,
        manager: AuthManager = Depends(get_auth_manager),
    ) -> dict[str, Any]:
        await call(manager.broker().reset, body.email, body.token, body.password)
        return {"status": "password reset"}

    return router
