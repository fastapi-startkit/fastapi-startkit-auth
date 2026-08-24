#!/usr/bin/env bash
#
# release.sh — build, validate, and (optionally) publish fastapi-startkit-auth.
#
# USAGE
#   bin/release.sh [--publish] [--repository <name>] [--skip-tests]
#
#   (no flags)           Dry run: build the sdist + wheel, then `twine check`
#                        them. Nothing is uploaded. This is the default so the
#                        script is always safe to run.
#   --publish            Actually upload to PyPI after building and validating.
#                        Requires explicit confirmation (set RELEASE_YES=1 to
#                        skip the interactive prompt in CI).
#   --repository <name>  Upload target for --publish (default: pypi). Use
#                        "testpypi" to push to the TestPyPI index first.
#   --skip-tests         Skip the pytest run before building (not recommended).
#
# CREDENTIALS (never hardcode secrets in this file)
#   Publishing reads credentials from the environment / a trusted publisher:
#     * Trusted publisher (recommended): run from GitHub Actions with OIDC and
#       no token is needed at all.
#     * API token: export UV_PUBLISH_TOKEN=pypi-... (or, for twine,
#       TWINE_USERNAME=__token__ and TWINE_PASSWORD=pypi-...).
#   For TestPyPI use UV_PUBLISH_URL=https://test.pypi.org/legacy/ (or the
#   matching twine repository config).
#
# EXAMPLES
#   bin/release.sh                       # build + validate only (safe default)
#   UV_PUBLISH_TOKEN=pypi-xxx bin/release.sh --publish
#   RELEASE_YES=1 UV_PUBLISH_URL=https://test.pypi.org/legacy/ \
#       bin/release.sh --publish --repository testpypi
#
set -euo pipefail

# Always run from the repository root, regardless of where we are invoked from.
cd "$(dirname "$0")/.."

PUBLISH=0
REPOSITORY="pypi"
RUN_TESTS=1

while [[ $# -gt 0 ]]; do
    case "$1" in
        --publish)      PUBLISH=1; shift ;;
        --repository)   REPOSITORY="${2:?--repository needs a value}"; shift 2 ;;
        --skip-tests)   RUN_TESTS=0; shift ;;
        -h|--help)      sed -n '2,32p' "$0"; exit 0 ;;
        *)              echo "Unknown argument: $1" >&2; exit 2 ;;
    esac
done

VERSION="$(uv version --short)"
echo "==> fastapi-startkit-auth ${VERSION}"

if [[ "$RUN_TESTS" -eq 1 ]]; then
    echo "==> Running test suite"
    uv run --extra test pytest
fi

echo "==> Building sdist + wheel"
rm -rf dist/
uv build

echo "==> Validating artifacts with twine"
uv run --with twine twine check dist/*

if [[ "$PUBLISH" -eq 0 ]]; then
    echo
    echo "Dry run complete. Artifacts in ./dist:"
    ls -1 dist/
    echo "Re-run with --publish to upload."
    exit 0
fi

# --- Upload path: guarded behind explicit confirmation ---------------------
if [[ "${RELEASE_YES:-0}" != "1" ]]; then
    read -r -p "Publish ${VERSION} to '${REPOSITORY}'? [y/N] " reply
    [[ "$reply" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 1; }
fi

echo "==> Publishing ${VERSION} to '${REPOSITORY}'"
# uv publish reads UV_PUBLISH_TOKEN / UV_PUBLISH_URL (or a trusted publisher's
# OIDC credentials) from the environment — no secrets live in this script.
if [[ "$REPOSITORY" == "pypi" ]]; then
    uv publish dist/*
else
    uv publish --publish-url "${UV_PUBLISH_URL:?set UV_PUBLISH_URL for a non-pypi repository}" dist/*
fi

echo "==> Published ${VERSION}."
