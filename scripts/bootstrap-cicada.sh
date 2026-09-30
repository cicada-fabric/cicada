#!/usr/bin/env bash
set -Eeuo pipefail

# Bootstrap is an explicit alias for the checkout-based, local-only Hub
# installer. It no longer creates a shared env file or asks for model keys.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
exec "$repo_root/scripts/install-cicada-server.sh" "$@"
