#!/bin/bash
# The version a built package carries, for the Makefile's .deb and the Arch
# PKGBUILD alike: Cargo.toml's version, with the commit appended unless HEAD is
# a clean v* tag, so a locally built package can never be mistaken for the
# released one.
set -euo pipefail

cd "$(dirname "$0")/.."

version=$(grep '^version' Cargo.toml | head -1 | cut -d'"' -f2)
commit=$(git rev-parse --short HEAD)

if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
	echo "${version}+${commit}.dirty"
elif [ -n "$(git tag --points-at HEAD --list 'v*')" ]; then
	echo "$version"
else
	echo "${version}+${commit}"
fi
