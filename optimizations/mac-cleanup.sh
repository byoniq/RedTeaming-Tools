#!/usr/bin/env bash
# Mac disk/memory cleanup. DRY-RUN by default; pass --apply to actually delete.
set -euo pipefail
APPLY=0; [[ "${1:-}" == "--apply" ]] && APPLY=1

say(){ printf '\n\033[1m%s\033[0m\n' "$*"; }
du_h(){ [[ -e "$1" ]] && du -sh "$1" 2>/dev/null || true; }
rm_path(){
  [[ -e "$1" ]] || return 0
  if [[ $APPLY -eq 1 ]]; then rm -rf "$1" && echo "removed: $1"
  else echo "would remove: $1 ($(du_h "$1" | cut -f1))"; fi
}

say "Xcode DerivedData"
rm_path "$HOME/Library/Developer/Xcode/DerivedData"

say "User caches (large subdirs only — review before --apply)"
for d in "$HOME/Library/Caches/"*; do
  sz=$(du -sm "$d" 2>/dev/null | cut -f1 || echo 0)
  [[ "${sz:-0}" -ge 200 ]] && rm_path "$d"
done

say "Unavailable simulators"
if [[ $APPLY -eq 1 ]]; then xcrun simctl delete unavailable || true
else echo "would run: xcrun simctl delete unavailable"; fi

say "Docker reclamation"
if command -v docker >/dev/null; then
  if [[ $APPLY -eq 1 ]]; then docker system prune -af || true
  else echo "would run: docker system prune -af  (add --volumes only if you're sure)"; fi
else echo "docker not found — skip"; fi

say "Homebrew cleanup"
if command -v brew >/dev/null; then
  if [[ $APPLY -eq 1 ]]; then brew cleanup -s || true
  else echo "would run: brew cleanup -s"; fi
fi

say "Reminder: cap the container VM (OrbStack/Docker Settings → Resources) so it can't balloon."
[[ $APPLY -eq 0 ]] && say "Dry run only. Re-run with --apply to delete."
