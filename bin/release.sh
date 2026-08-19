#!/bin/bash

# Exit on error
set -e

# Run from the repository root
cd "$(dirname "$0")/.."

BUMP_TYPE=${1:-patch}

if [[ -n $(git status --porcelain) ]]; then
    echo "⚠️  You have uncommitted changes. Please commit or stash them before releasing."
    exit 1
fi

echo "🚀 Starting release process with $BUMP_TYPE bump..."

echo "   Bumping version..."
uv version --bump "$BUMP_TYPE"
VERSION=$(uv version --short)

echo "   Building..."
rm -rf dist/
uv build

echo "   Validating distribution..."
uv run twine check dist/*

echo "   Publishing..."
uv run twine upload dist/* --verbose

echo "📌 Committing version bump..."
git add pyproject.toml uv.lock
git commit -m "chore: release v$VERSION"

echo "🏷️ Creating git tag..."
git tag "v$VERSION"

echo "⬆️ Pushing commits + tags..."
git push origin main
git push origin "v$VERSION"

echo "🚀 Creating GitHub release..."

PREV_TAG=$(git describe --tags --abbrev=0 "v$VERSION"^ 2>/dev/null || echo "")

if [ -n "$PREV_TAG" ]; then
    git log "$PREV_TAG..HEAD" --pretty=format:"- %s" > CHANGELOG.tmp
else
    git log --pretty=format:"- %s" > CHANGELOG.tmp
fi

gh release create "v$VERSION" \
    --title "v$VERSION" \
    --notes-file CHANGELOG.tmp

rm CHANGELOG.tmp

echo "✅ Release complete: v$VERSION"
