from __future__ import annotations

import base64
import binascii
from typing import Any
from urllib.parse import unquote_plus, urlencode

from fastapi import APIRouter, Depends, Form, Request, Response
from pydantic import BaseModel, Field

from .clients.models import Client
from .concurrency import call
from .dependencies import current_user, get_auth_manager, resolve_context
from .exceptions import (
    AccessDenied,
    InvalidClient,
    InvalidGrant,
    InvalidRequest,
    InvalidTarget,
    InvalidToken,
    UnauthorizedClient,
    UnsupportedGrantType,
    UnsupportedResponseType,
)
from .manager import AuthManager


# --- request bodies ------------------------------------------------------
class AuthorizeRequest(BaseModel):
    response_type: str = "code"
    approved: bool = False
    client_id: str
    redirect_uri: str | None = None
    scope: str | None = None
    state: str | None = None
    code_challenge: str | None = None
    code_challenge_method: str | None = None
    resource: str | None = None


class PersonalAccessTokenCreate(BaseModel):
    name: str
    scopes: list[str] | None = None
    ttl: int | None = Field(default=None, gt=0)


def _scopes(raw: str | None) -> list[str] | None:
    return None if raw is None else [s for s in raw.split() if s]


def _single_resource(resources: list[str] | None) -> str | None:
    resources = [resource for resource in resources or [] if resource]
    if not resources:
        return None
    if len(resources) > 1:
        raise InvalidTarget("Only one resource may be requested.")
    return resources[0]


def _no_store(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"


def _client_credentials_from_request(
    request: Request, client_id: str | None, client_secret: str | None
) -> tuple[str | None, str | None]:
    """Prefer HTTP Basic auth for client credentials, falling back to form fields."""
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("basic "):
        return client_id, client_secret
    try:
        decoded = base64.b64decode(header[6:], validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        raise InvalidClient("Malformed Basic authorization header.")
    cid, separator, secret = decoded.partition(":")
    if not separator or not cid:
        raise InvalidClient("Malformed Basic authorization header.")
    # RFC 6749 §2.3: a client must not use more than one authentication method per request.
    if client_secret is not None:
        raise InvalidRequest("Use one client authentication method per request.")
    return unquote_plus(cid), unquote_plus(secret)


async def _authenticate_client(manager: AuthManager, client_id: str, secret: str | None, grant: str) -> Client:
    client = await call(manager.client_repository.authenticate, client_id, secret)
    if client is None or client.revoked:
        raise InvalidClient("Client authentication failed.")
    if not client.allows_grant(grant):
        raise UnauthorizedClient(f"Client is not authorized for the {grant} grant.")
    return client


async def _require_authenticated_client(
    manager: AuthManager, request: Request, client_id: str | None, client_secret: str | None
) -> Client:
    """Authenticate the calling client for the introspection/revocation endpoints."""
    client_id, client_secret = _client_credentials_from_request(request, client_id, client_secret)
    if not client_id:
        raise InvalidClient("Client authentication is required.")
    client = await call(manager.client_repository.authenticate, client_id, client_secret)
    if client is None or client.revoked:
        raise InvalidClient("Client authentication failed.")
    return client


def _require_password_grant(manager: AuthManager) -> None:
    if not manager.grant_enabled("password"):
        raise UnsupportedGrantType('The password grant is disabled; add "password" to OAuth2Config.grant_types.')


async def _validate_authorization_request(manager: AuthManager, body: AuthorizeRequest) -> tuple[Client, list[str]]:
    if body.response_type != "code":
        raise UnsupportedResponseType("Only response_type=code is supported.")
    client = await call(manager.client_repository.find, body.client_id)
    if client is None or client.revoked:
        raise InvalidClient("Unknown or revoked client.")
    if not client.allows_grant("authorization_code"):
        raise UnauthorizedClient("Client is not authorized for the authorization_code grant.")
    scopes = manager.resolve_scopes(_scopes(body.scope))
    manager.authorization_code_grant().validate_request(
        client=client,
        redirect_uri=body.redirect_uri,
        scopes=scopes,
        code_challenge=body.code_challenge,
        code_challenge_method=body.code_challenge_method,
        resource=body.resource or None,
    )
    return client, scopes


async def authorizing_user(request: Request, manager: AuthManager = Depends(get_auth_manager)) -> Any:
    context = await resolve_context(request, manager, manager.authorization_guard_name)
    if context.user is None:
        raise InvalidToken("This token is not associated with a user.")
    return context.user


def build_router(prefix: str = "") -> APIRouter:
    """Build the OAuth2 router. Mounted onto the app by AuthOAuth2Provider."""
    router = APIRouter(prefix=prefix)

    def issuer_for(request: Request, manager: AuthManager) -> str:
        return manager.oauth_issuer or f"{str(request.base_url).rstrip('/')}{prefix}"

    # --- metadata (RFC 8414) ------------------------------------------
    @router.get("/.well-known/oauth-authorization-server")
    async def metadata(request: Request, manager: AuthManager = Depends(get_auth_manager)) -> dict[str, Any]:
        endpoint_base = f"{str(request.base_url).rstrip('/')}{prefix}"
        return {
            "issuer": issuer_for(request, manager),
            "authorization_endpoint": f"{endpoint_base}/oauth/authorize",
            "token_endpoint": f"{endpoint_base}/oauth/token",
            "revocation_endpoint": f"{endpoint_base}/oauth/revoke",
            "introspection_endpoint": f"{endpoint_base}/oauth/introspect",
            "response_types_supported": ["code"],
            "grant_types_supported": manager.grant_types,
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
            "code_challenge_methods_supported": sorted(manager.grant_policy.pkce_methods),
            "scopes_supported": list(manager.scopes),
            "authorization_response_iss_parameter_supported": True,
        }

    # --- unified token endpoint (RFC 6749 §3.2) -----------------------
    @router.post("/oauth/token")
    async def token(
        request: Request,
        response: Response,
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
        resources: list[str] | None = Form(None, alias="resource"),
        manager: AuthManager = Depends(get_auth_manager),
    ) -> dict[str, Any]:
        _no_store(response)
        client_id, client_secret = _client_credentials_from_request(request, client_id, client_secret)
        resource = _single_resource(resources)
        if grant_type not in ("password", "client_credentials", "refresh_token", "authorization_code"):
            raise UnsupportedGrantType(f"Unsupported grant_type: {grant_type!r}")
        if not manager.grant_enabled(grant_type):
            raise UnsupportedGrantType(f"The {grant_type} grant is not enabled on this server.")

        if grant_type == "password":
            client = await _authenticate_client(manager, client_id, client_secret, "password") if client_id else None
            issued = await call(
                manager.password_grant(client=client).handle,
                username=username or "",
                password=password or "",
                scopes=manager.resolve_scopes(_scopes(scope)),
                client_id=client_id,
            )
            return issued.to_response()

        if grant_type == "client_credentials":
            if not client_id:
                raise InvalidClient("client_id is required for the client_credentials grant.")
            client = await _authenticate_client(manager, client_id, client_secret, "client_credentials")
            if not client.confidential:
                raise UnauthorizedClient("Only confidential clients may use the client_credentials grant.")
            issued = await call(
                manager.client_credentials_grant().handle,
                client=client,
                scopes=manager.resolve_scopes(_scopes(scope)),
                resource=resource,
            )
            return issued.to_response()

        if grant_type == "refresh_token":
            if not refresh_token:
                raise InvalidRequest("refresh_token is required.")
            record = await call(manager.token_service.repository.find_refresh_token, refresh_token)
            if record is None:
                raise InvalidGrant("The refresh token is invalid, expired, or revoked.")
            if record.client_id is not None:
                if not client_id:
                    raise InvalidClient("client_id is required for this refresh token.")
                await _authenticate_client(manager, client_id, client_secret, "refresh_token")
                if record.client_id != client_id:
                    raise InvalidGrant("The refresh token was issued to a different client.")
            elif client_id or not manager.grant_enabled("password"):
                # Only the password grant issues client-less refresh tokens.
                raise InvalidGrant("The refresh token is not bound to the requesting client.")
            requested = _scopes(scope)
            issued = await call(
                manager.refresh_grant().handle,
                refresh_token=refresh_token,
                scopes=manager.resolve_scopes(requested) if requested else None,
                resource=resource,
                client_id=client_id,
            )
            return issued.to_response()

        if not code:
            raise InvalidRequest("code is required.")
        if not client_id:
            raise InvalidClient("client_id is required for the authorization_code grant.")
        client = await call(manager.client_repository.find, client_id)
        if client is None or client.revoked:
            raise InvalidClient("Unknown or revoked client.")
        client_authenticated = False
        if client.confidential:
            client = await _authenticate_client(manager, client_id, client_secret, "authorization_code")
            client_authenticated = True
        elif not client.allows_grant("authorization_code"):
            raise UnauthorizedClient("Client is not authorized for the authorization_code grant.")
        issued = await call(
            manager.authorization_code_grant().handle,
            client=client,
            code=code,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
            client_authenticated=client_authenticated,
            resource=resource,
        )
        return issued.to_response()

    # --- simple password endpoint (FastAPI tutorial style) ------------
    @router.post("/token")
    async def simple_token(
        response: Response,
        username: str = Form(...),
        password: str = Form(...),
        scope: str | None = Form(None),
        manager: AuthManager = Depends(get_auth_manager),
    ) -> dict[str, Any]:
        _no_store(response)
        _require_password_grant(manager)
        issued = await call(
            manager.password_grant().handle,
            username=username,
            password=password,
            scopes=manager.resolve_scopes(_scopes(scope)),
            client_id=None,
        )
        return issued.to_response()

    # --- authorization endpoint (code + PKCE) -------------------------
    @router.get("/oauth/authorize")
    async def authorization_request(
        client_id: str,
        response_type: str,
        redirect_uri: str | None = None,
        scope: str | None = None,
        state: str | None = None,
        code_challenge: str | None = None,
        code_challenge_method: str | None = None,
        resource: str | None = None,
        user=Depends(authorizing_user),
        manager: AuthManager = Depends(get_auth_manager),
    ) -> dict[str, Any]:
        body = AuthorizeRequest(
            client_id=client_id,
            response_type=response_type,
            redirect_uri=redirect_uri,
            scope=scope,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            resource=resource,
        )
        client, scopes = await _validate_authorization_request(manager, body)
        return {
            "client_id": client.id,
            "client_name": client.name,
            "redirect_uri": redirect_uri,
            "scope": " ".join(scopes),
            "state": state,
            "response_type": "code",
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "resource": resource,
            "requires_approval": True,
        }

    @router.post("/oauth/authorize")
    async def authorize(
        request: Request,
        body: AuthorizeRequest,
        user=Depends(authorizing_user),
        manager: AuthManager = Depends(get_auth_manager),
    ) -> dict[str, Any]:
        client, scopes = await _validate_authorization_request(manager, body)
        if not body.approved:
            raise AccessDenied("The resource owner has not approved this authorization request.")
        guard_provider = manager.guard(manager.authorization_guard_name).provider
        if manager.provider_for_client(client) is not guard_provider:
            raise UnauthorizedClient("This client does not act for users of the authenticated provider.")
        code = await call(
            manager.authorization_code_grant().issue_code,
            client=client,
            user_id=guard_provider.get_identifier(user),
            scopes=scopes,
            redirect_uri=body.redirect_uri,
            code_challenge=body.code_challenge,
            code_challenge_method=body.code_challenge_method,
            resource=body.resource or None,
        )
        issuer = issuer_for(request, manager)
        result: dict[str, Any] = {"code": code, "state": body.state, "iss": issuer}
        if body.redirect_uri:
            sep = "&" if "?" in body.redirect_uri else "?"
            params = {"code": code, "iss": issuer}
            if body.state is not None:
                params["state"] = body.state
            result["redirect_to"] = f"{body.redirect_uri}{sep}{urlencode(params)}"
        return result

    # --- introspection (RFC 7662) -------------------------------------
    @router.post("/oauth/introspect")
    async def introspect(
        request: Request,
        response: Response,
        token: str = Form(...),
        client_id: str | None = Form(None),
        client_secret: str | None = Form(None),
        manager: AuthManager = Depends(get_auth_manager),
    ) -> dict[str, Any]:
        _no_store(response)
        client = await _require_authenticated_client(manager, request, client_id, client_secret)
        if not client.confidential:
            raise InvalidClient("Introspection requires confidential client authentication.")
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
        client = await _require_authenticated_client(manager, request, client_id, client_secret)
        # RFC 7009 §2.2: an unknown or foreign token still answers 200, so nothing leaks.
        await call(
            manager.token_service.revoke_token, token, client.id, allow_unbound=manager.grant_enabled("password")
        )
        return {"revoked": True}

    # --- the user's OAuth tokens --------------------------------------
    @router.get("/oauth/tokens")
    async def list_user_tokens(
        user=Depends(current_user),
        manager: AuthManager = Depends(get_auth_manager),
    ) -> list[dict[str, Any]]:
        user_id = manager.guard().provider.get_identifier(user)
        records = await call(manager.token_service.tokens_for, user_id, personal_access=False)
        return [
            {
                "jti": record.jti,
                "client_id": record.client_id,
                "scopes": record.scopes,
                "created_at": record.created_at,
                "expires_at": record.expires_at,
                "active": record.active,
            }
            for record in records
        ]

    @router.delete("/oauth/tokens", status_code=204)
    async def revoke_user_tokens(
        user=Depends(current_user),
        manager: AuthManager = Depends(get_auth_manager),
    ) -> Response:
        user_id = manager.guard().provider.get_identifier(user)
        await call(manager.token_service.revoke_all_for_user, user_id, personal_access=False)
        return Response(status_code=204)

    @router.delete("/oauth/tokens/{jti}", status_code=204)
    async def revoke_user_token(
        jti: str,
        user=Depends(current_user),
        manager: AuthManager = Depends(get_auth_manager),
    ) -> Response:
        user_id = manager.guard().provider.get_identifier(user)
        await call(manager.token_service.revoke_for_user, jti, user_id, personal_access=False)
        return Response(status_code=204)

    # --- personal access tokens ---------------------------------------
    @router.post("/oauth/personal-access-tokens", status_code=201)
    async def create_pat(
        response: Response,
        body: PersonalAccessTokenCreate,
        user=Depends(current_user),
        manager: AuthManager = Depends(get_auth_manager),
    ) -> dict[str, Any]:
        _no_store(response)
        user_id = manager.guard().provider.get_identifier(user)
        issued = await call(
            manager.token_service.create_personal_access_token,
            user_id=user_id,
            name=body.name,
            scopes=manager.resolve_scopes(body.scopes),
            ttl=body.ttl,
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
        records = await call(manager.token_service.tokens_for, user_id, personal_access=True)
        return [
            {
                "jti": r.jti,
                "name": r.name,
                "scopes": r.scopes,
                "revoked": r.revoked,
                "created_at": r.created_at,
                "expires_at": r.expires_at,
            }
            for r in records
            if r.active
        ]

    @router.delete("/oauth/personal-access-tokens", status_code=204)
    async def delete_all_pats(
        user=Depends(current_user),
        manager: AuthManager = Depends(get_auth_manager),
    ) -> Response:
        user_id = manager.guard().provider.get_identifier(user)
        await call(manager.token_service.revoke_all_for_user, user_id, personal_access=True)
        return Response(status_code=204)

    @router.delete("/oauth/personal-access-tokens/{jti}", status_code=204)
    async def delete_pat(
        jti: str,
        user=Depends(current_user),
        manager: AuthManager = Depends(get_auth_manager),
    ) -> Response:
        user_id = manager.guard().provider.get_identifier(user)
        await call(manager.token_service.revoke_for_user, jti, user_id, personal_access=True)
        return Response(status_code=204)

    return router
