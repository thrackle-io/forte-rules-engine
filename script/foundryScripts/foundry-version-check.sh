#!/bin/bash

# This script checks if Foundry, Anvil, and Cast are installed and up to date.
# It compares the installed versions with the pinned version specified in `foundry.lock`.
# If Foundry is not installed or out of date, it installs or updates Foundry unless the `--skip-install` flag is used.
#
# Steps:
# 1. Determine the pinned Foundry version from `foundry.lock`.
# 2. Check if Foundry, Anvil, and Cast are installed and match the pinned version.
# 3. If up to date, exit with a success message.
# 4. If out of date or not installed, install or update Foundry unless `--skip-install` is specified.
# 5. Use the `foundryup` script to manage installation and updates.

set -euo pipefail
cd "$(dirname "$0")/../.."


FOUNDRY_DIR="${FOUNDRY_DIR-"$HOME/.foundry"}"
FOUNDRY_BIN_DIR="$FOUNDRY_DIR/bin"
FOUNDRYUP_URL="https://raw.githubusercontent.com/thrackle-io/foundry/refs/heads/master/foundryup/foundryup"

foundry_pinned_version=$(awk '!/^#/ {print $0; exit}' script/foundryScripts/foundry.lock)
# `forge --version` refers to the first 8 characters of the commit hash
foundry_version_short=${foundry_pinned_version:0:8}
skip_install=${SKIP_INSTALL:-false}
flags=${1:-0}

if [ $flags = "--skip-install" ]; then
  skip_install=true
fi

function installed() {
  command -v "$1" >/dev/null 2>&1
}

function installed_current() {
  command "$1" --version 2>&1 | grep "$foundry_version_short" >/dev/null 2>&1
}

if installed_current forge && installed_current anvil && installed_current cast; then
  echo "✅ Foundry, Anvil, and Cast are already installed and up to date."
  exit 0
elif installed forge && installed anvil && installed cast; then
  echo "🦖 Foundry is out of date."
  if $skip_install; then
    echo "--skip-install used. Skipping installation..."
  else
    echo "🚀 Updating Foundry..."
    foundryup --version $foundry_pinned_version
  fi
else
  echo "❌ Foundry is not installed."
  if $skip_install; then
    echo "--skip-install used. Skipping installation..."
  else
    echo "🏗️ Installing Foundry..."
    mkdir -p "$FOUNDRY_BIN_DIR"
    PATH=$FOUNDRY_BIN_DIR:$PATH
    curl -sSf -L "$FOUNDRYUP_URL" -o "$FOUNDRY_BIN_DIR/foundryup"
    chmod +x "$FOUNDRY_BIN_DIR/foundryup"
    foundryup --version $foundry_pinned_version
  fi
fi