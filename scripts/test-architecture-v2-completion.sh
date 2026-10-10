#!/usr/bin/env bash
# One-click bounded Architecture v2 acceptance runner.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
exec python3 -B "${repo_root}/scripts/completion_runner.py" "$@"
