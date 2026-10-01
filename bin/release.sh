#!/bin/bash

# Exit on error
set -e

BUMP_TYPE=${1:-patch}

echo "🚀 Starting release process with $BUMP_TYPE bump..."

PACKAGE_DIR="."

if [ -f "$PACKAGE_DIR/pyproject.toml" ]; then
    echo "📦 Releasing package: $PACKAGE_DIR"

    # Navigate to package directory
    cd "$PACKAGE_DIR"

    # Bump version
    echo "   Bumping version..."
    uv version --bump "$BUMP_TYPE"
    VERSION=$(uv version --short)
    sed -i.bak "s/^__version__ = .*/__version__ = \"$VERSION\"/" src/fastapi_startkit_auth/__init__.py
    rm src/fastapi_startkit_auth/__init__.py.bak

    # Build
    echo "   Building..."
    rm -rf dist/
    uv build

    # Publishing happens in CI (trusted publishing) when the tag is pushed
    echo "   Checking distributions..."
    uv run twine check --strict dist/*

    echo "📌 Committing version bump..."
    git add pyproject.toml uv.lock src/fastapi_startkit_auth/__init__.py
    git commit -m "chore: release v$VERSION"

    echo "🏷️ Creating git tag..."
    git tag "v$VERSION"

    echo "⬆️ Pushing commits + tags..."
    git push origin main
    git push origin "v$VERSION"

    echo "⏳ Waiting for the v$VERSION release workflow..."
    RUN_ID=""
    while [ -z "$RUN_ID" ]; do
        RUN_ID=$(gh run list --workflow release.yml --limit 20 --json headBranch,databaseId \
            --jq ".[] | select(.headBranch == \"v$VERSION\") | .databaseId" | head -n 1)
        if [ -z "$RUN_ID" ]; then
            sleep 3
        fi
    done
    if ! gh run watch "$RUN_ID" --exit-status; then
        echo "❌ Release workflow for v$VERSION failed; PyPI publishing may not have completed." >&2
        exit 1
    fi

    echo "🚀 Creating GitHub release..."

    PREV_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "")

    if [ -n "$PREV_TAG" ]; then
        git log "$PREV_TAG..HEAD" --pretty=format:"- %s" > CHANGELOG.tmp
    else
        git log --pretty=format:"- %s" > CHANGELOG.tmp
    fi

    gh release create "v$VERSION" \
        --title "v$VERSION" \
        --notes-file CHANGELOG.tmp

    rm CHANGELOG.tmp

    cd - > /dev/null
    echo "✅ Release complete: v$VERSION"
else
    echo "⚠️  pyproject.toml not found in $PACKAGE_DIR."
    exit 1
fi
