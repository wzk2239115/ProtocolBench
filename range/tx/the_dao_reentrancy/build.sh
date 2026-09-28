#!/usr/bin/env bash
# Idempotent build for the tx:the_dao_reentrancy range.
#
# Reuses the Foundry v1.8.3 arm64 release shared under range/tx/.foundry/
# (NOT system-wide) and compiles the contracts (including the vendored OZ
# ReentrancyGuard used by TheDAOSafe).
set -euo pipefail

TASK_DIR="$(cd "$(dirname "$0")" && pwd)"
FOUNDRY_DIR="$(cd "$TASK_DIR/.." && pwd)/.foundry"
FOUNDRY_VERSION="v1.8.3"
ASSET="foundry_${FOUNDRY_VERSION#v}_linux_arm64.tar.gz"
URL="https://github.com/foundry-rs/foundry/releases/download/${FOUNDRY_VERSION}/${ASSET}"

if [ ! -x "$FOUNDRY_DIR/forge" ]; then
  echo "[build] installing Foundry ${FOUNDRY_VERSION} into $FOUNDRY_DIR"
  mkdir -p "$FOUNDRY_DIR"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  curl -sSL --fail --retry 3 -o "$tmp/$ASSET" "$URL"
  tar -xzf "$tmp/$ASSET" -C "$FOUNDRY_DIR"
fi

export PATH="$FOUNDRY_DIR:$PATH"
forge --version

cd "$TASK_DIR"
forge build
echo "[build] done: $TASK_DIR/out"
