#!/usr/bin/env bash
# Read-only audit of what launches at login / in the background. Changes nothing.
set -euo pipefail
hdr(){ printf '\n\033[1m== %s ==\033[0m\n' "$*"; }

hdr "User LaunchAgents (~/Library/LaunchAgents)"
ls -1 "$HOME/Library/LaunchAgents" 2>/dev/null || echo "(none)"

hdr "Global LaunchAgents (/Library/LaunchAgents)"
ls -1 /Library/LaunchAgents 2>/dev/null || echo "(none)"

hdr "Global LaunchDaemons (/Library/LaunchDaemons)"
ls -1 /Library/LaunchDaemons 2>/dev/null || echo "(none)"

hdr "Loaded in your session (launchctl, non-com.apple)"
launchctl list 2>/dev/null | awk 'NR==1 || $3 !~ /^com\.apple\./' || true

hdr "Login items"
osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null \
  | tr ',' '\n' | sed 's/^ *//' || echo "(none or permission denied)"

printf '\nReview anything unfamiliar. To disable a user agent:\n'
printf '  launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/<label>.plist\n'
printf 'and move its plist out of the LaunchAgents folder.\n'
