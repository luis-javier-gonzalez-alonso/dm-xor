#!/bin/bash
set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 1.3.2"
    exit 1
fi

VERSION=$1

# Validate version format (X.Y.Z)
if [[ ! $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Error: Version must be in format X.Y.Z (e.g., 1.3.2)"
    exit 1
fi

echo "Bumping version to $VERSION in all configuration files..."

# Helper function to run sed cross-platform (macOS and Linux compatible)
run_sed() {
    local pattern="$1"
    local file="$2"
    if [ ! -f "$file" ]; then
        echo "Warning: File $file not found, skipping."
        return
    fi
    sed -i '' "$pattern" "$file" 2>/dev/null || sed -i "$pattern" "$file"
}

# 1. Makefile
run_sed "s/^MODULE_VERSION := .*/MODULE_VERSION := ${VERSION}/" Makefile

# 2. Arch PKGBUILD
run_sed "s/^pkgver=.*/pkgver=${VERSION}/" arch/PKGBUILD

# 3. Debian changelog
run_sed "s/dm-xor-dkms ([0-9.]*-1)/dm-xor-dkms (${VERSION}-1)/" debian/changelog

# 4. Debian install paths
run_sed "s/dm-xor-[0-9.]*/dm-xor-${VERSION}/g" debian/dm-xor-dkms.install

# 5. DKMS config
run_sed "s/^PACKAGE_VERSION=.*/PACKAGE_VERSION=\"${VERSION}\"/" dkms.conf

# 6. RPM spec
run_sed "s/^Version:.*/Version:        ${VERSION}/" rpm/dm-xor-dkms.spec

echo "Success! Version bumped to $VERSION."
echo ""
echo "To commit and tag this release, run:"
echo "  git add Makefile arch/PKGBUILD debian/changelog debian/dm-xor-dkms.install dkms.conf rpm/dm-xor-dkms.spec"
echo "  git commit -m \"Bump version to $VERSION\""
echo "  git tag v$VERSION"
echo "  git push origin main --tags"
