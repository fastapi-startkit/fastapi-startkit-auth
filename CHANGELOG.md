# Changelog

All notable changes to `fastapi-startkit-auth` are documented in this file.

Release notes are also published on
[GitHub Releases](https://github.com/fastapi-startkit/fastapi-startkit-auth/releases).

## [Unreleased]

## [0.1.0]

Initial release.

- Passport-style OAuth2 authorization server for FastAPI: authorization code
  (with PKCE), password, client credentials, and refresh token grants
- JWT access tokens with scopes, token guards, and route dependencies
- Personal access tokens
- Pluggable user/client providers (in-memory and Masonite ORM)
- Password reset flow with throttling hardened against account enumeration
