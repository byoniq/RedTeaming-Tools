#!/usr/bin/env bash
# Run any command with secrets injected from 1Password, resolved from .env.tpl.
# Nothing is written to disk; the values live only in the child process env.
#   ./op-run.sh python3 ../engagements/streamsync_connect_devtest.py
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
command -v op >/dev/null || { echo "1Password CLI (op) not found. brew install 1password-cli"; exit 1; }
exec op run --env-file="$here/.env.tpl" -- "$@"
