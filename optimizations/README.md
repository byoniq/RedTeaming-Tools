# Environment optimizations

Generated from the decision card. Scope = the **Adopt** items only.
Skipped by choice: per-bot service accounts, devcontainers/Nix.
Deferred (Later): mise, declarative fleet config, concurrency locks, dotfiles.

## What's here (repo-side, ready to use)

| File | Covers | You run |
|------|--------|---------|
| `mac-cleanup.sh` | docker prune + VM cap reminder, DerivedData/caches/simulators, brew cleanup | `./mac-cleanup.sh` (dry-run) then `--apply` |
| `mac-launchagents-audit.sh` | LaunchAgents/Daemons + login items audit | `./mac-launchagents-audit.sh` (read-only) |
| `mac-spotlight-exclude.sh` | drops `.metadata_never_index` into build dirs | `./mac-spotlight-exclude.sh <dir>...` |
| `.env.tpl` | 1Password secret references (no secrets) | edit `op://` paths to your vault/items |
| `op-run.sh` | run any command with op-injected env | `./op-run.sh python3 ../engagements/streamsync_connect_devtest.py` |
| `envrc.template` | direnv auto-load of `.env.tpl` via op | rename to `.envrc`, `direnv allow` |
| `.pre-commit-config.yaml` | gitleaks (+ optional trufflehog) secret scanning | `pre-commit install` |
| `bot_runtime.py` | backoff+idempotency, structured logs, run ledger | `import bot_runtime` in your bots |

## Mac-side commands (I can't run these from the sandbox)

**1Password CLI (do first):**
```bash
brew install 1password-cli
# 1Password app → Settings → Developer → "Integrate with 1Password CLI"
op whoami && op vault list
```

**OrbStack swap:**
```bash
brew install orbstack          # then quit Docker Desktop; `docker` CLI points at OrbStack
# optional: brew uninstall --cask docker   (after you've confirmed OrbStack works)
```
Cap the VM in OrbStack → Settings → Resources (e.g. 4 CPU / 6 GB).

**direnv + gitleaks tooling:**
```bash
brew install direnv pre-commit gitleaks
# add to ~/.zshrc:  eval "$(direnv hook zsh)"
```

**Spotlight excludes** (GUI alternative): System Settings → Siri & Spotlight → Spotlight Privacy → add your build dirs. The script here does it per-folder without the GUI.
