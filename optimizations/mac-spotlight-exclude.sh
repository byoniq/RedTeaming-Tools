#!/usr/bin/env bash
# Exclude folders from Spotlight indexing by dropping a .metadata_never_index marker.
# Usage: ./mac-spotlight-exclude.sh ~/code/*/node_modules ~/code/*/target ~/code/*/.build
set -euo pipefail
[[ $# -ge 1 ]] || { echo "usage: $0 <dir> [dir...]"; exit 1; }
for d in "$@"; do
  if [[ -d "$d" ]]; then
    touch "$d/.metadata_never_index" && echo "excluded: $d"
  else
    echo "skip (not a dir): $d"
  fi
done
echo "Spotlight will stop indexing these on its next pass. Remove the marker file to re-include."
