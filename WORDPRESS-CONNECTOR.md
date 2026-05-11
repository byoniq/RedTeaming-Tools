# WordPress Connector for Claude

Connects Claude to two self-hosted WordPress sites so it can read and update them:

- `https://www.aladdinelston.com`
- `https://sentinelsec.ai`

This uses the official **[WordPress/mcp-adapter](https://github.com/WordPress/mcp-adapter)** plugin on each site, fronted by the **[@automattic/mcp-wordpress-remote](https://github.com/Automattic/mcp-wordpress-remote)** STDIO bridge so any MCP-capable Claude surface (Claude Code, Claude Desktop) can connect.

> Self-hosted sites have no OAuth path today — auth is **Application Passwords** over Basic Auth. Treat those passwords like full account credentials.

---

## 1. One-time setup on each WordPress site

Do this once per site, logged in as a user with the capability to perform the actions you want Claude to take (Administrator if you want full read/write).

### a. Install the MCP adapter plugin

The current canonical plugin is `WordPress/mcp-adapter`. Install it from:

- WP Admin → Plugins → Add New → upload the latest release ZIP from <https://github.com/WordPress/mcp-adapter/releases>, **or**
- Via WP-CLI on the server:
  ```
  wp plugin install https://github.com/WordPress/mcp-adapter/releases/latest/download/mcp-adapter.zip --activate
  ```

Confirm the default MCP endpoint responds (should return JSON, not a 404):

```
curl -i https://www.aladdinelston.com/wp-json/mcp/mcp-adapter-default-server
curl -i https://sentinelsec.ai/wp-json/mcp/mcp-adapter-default-server
```

### b. Create an Application Password

WP Admin → Users → Profile → **Application Passwords** → enter a name like `claude-mcp` → **Add New Application Password**.

Copy the generated password **immediately** — WordPress only shows it once. The username is your WP login name.

Repeat on both sites; you'll end up with four values total:

| Site | Username | App Password |
|---|---|---|
| aladdinelston.com | `<wp username>` | `xxxx xxxx xxxx xxxx xxxx xxxx` |
| sentinelsec.ai | `<wp username>` | `xxxx xxxx xxxx xxxx xxxx xxxx` |

---

## 2. Local credentials (do not commit)

Copy `.env.example` → `.env` in this repo and fill in the four values:

```
cp .env.example .env
```

`.env` is gitignored. Load it into your shell before launching Claude:

```
set -a; source .env; set +a
```

(Or use [direnv](https://direnv.net/) with an `.envrc` that does the same.)

---

## 3. Claude Code (this repo)

The repo already contains `.mcp.json` with both servers wired up to read the env vars above. Once `.env` is loaded:

```
claude mcp list
```

You should see `wordpress-aladdin` and `wordpress-sentinelsec` listed as healthy. Inside a `claude` session in this directory, try:

```
> List the 5 most recent posts on aladdinelston.com.
```

If Claude Code prompts you to approve the project-scoped MCP servers on first launch, approve them.

---

## 4. Claude Desktop

Claude Desktop reads `claude_desktop_config.json`. Locations:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

Merge this into the `mcpServers` block (replace the placeholder values — Claude Desktop does **not** expand `${VAR}` references, so credentials go in the file itself; protect it with filesystem permissions, e.g. `chmod 600`):

```json
{
  "mcpServers": {
    "wordpress-aladdin": {
      "command": "npx",
      "args": ["-y", "@automattic/mcp-wordpress-remote"],
      "env": {
        "WP_API_URL": "https://www.aladdinelston.com",
        "WP_API_USERNAME": "REPLACE_ME",
        "WP_API_PASSWORD": "REPLACE_ME",
        "OAUTH_ENABLED": "false"
      }
    },
    "wordpress-sentinelsec": {
      "command": "npx",
      "args": ["-y", "@automattic/mcp-wordpress-remote"],
      "env": {
        "WP_API_URL": "https://sentinelsec.ai",
        "WP_API_USERNAME": "REPLACE_ME",
        "WP_API_PASSWORD": "REPLACE_ME",
        "OAUTH_ENABLED": "false"
      }
    }
  }
}
```

Restart Claude Desktop. Both connectors should appear in the tools picker.

---

## 5. Claude.ai web

Self-hosted WordPress sites don't yet have a hosted OAuth bridge for the Claude.ai web Connectors directory. The Connectors directory at `claude.com/connectors/wordpress-com` only covers WordPress.com–hosted sites. For these two self-hosted sites, use Claude Code or Claude Desktop (steps 3–4).

---

## 6. Troubleshooting

- **`401` from the MCP endpoint** — username/app password mismatch, or the user lacks the capability for the requested action. Re-issue the Application Password.
- **`404` on `/wp-json/mcp/mcp-adapter-default-server`** — plugin not active, or permalinks not set to anything other than "Plain". WP Admin → Settings → Permalinks → Save.
- **Server hangs on first call** — `npx` is downloading `@automattic/mcp-wordpress-remote`. Subsequent calls are cached.
- **Need a fresh start** — `rm -rf ~/.npm/_npx` then retry.

---

## What I did NOT do

- I did **not** install the plugin on either WordPress site (no credentials, no access).
- I did **not** create Application Passwords on either site.
- I did **not** commit any secrets — only env-var *names* live in `.mcp.json`.

Steps 1 and 2 are on you.
