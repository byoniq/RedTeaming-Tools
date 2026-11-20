# Playwright MCP for web app security testing

`.mcp.json` at the repo root registers two Playwright MCP servers for Claude Code. Any
Claude Code session opened in this repo picks them up after you approve the project MCP prompt.

| Server | Use it for |
|---|---|
| `playwright` | Headless browser driven by Claude: login flows, SPA crawling, DOM XSS confirmation, screenshots and network logs as evidence |
| `playwright-burp` | Headed browser routed through Burp/ZAP on `127.0.0.1:8080` (TLS errors ignored), so every request Claude makes shows up in your proxy history for replay and Intruder |

The version is pinned (`@playwright/mcp@0.0.84`, published 2026-10-31). Don't switch to
`@latest`: an unpinned `npx -y` on a pentest box runs whatever was last published.

## First run (local machine)

```bash
npx -y @playwright/mcp@0.0.84 install-browser chromium   # one time
claude mcp list                                           # should show playwright + playwright-burp
```

Evidence (screenshots, traces, network dumps) goes to `pentest-evidence/`, which is gitignored
because it will hold session tokens and customer data.

## Where it helps over plain curl / Burp

- **Authenticated, JS-heavy apps.** Claude logs in, handles MFA prompts you hand it, and keeps
  state across steps. With `--storage-state` you can hand it a saved session per role.
- **Access control (A01) across roles.** Run the same flow as user A and user B, diff what renders.
- **DOM XSS / client-side injection (A03).** Proof is "did the payload execute in a real browser",
  which `browser_evaluate` and `browser_console_messages` answer directly.
- **Evidence.** `browser_take_screenshot`, `browser_start_tracing`, `browser_network_requests`
  produce artifacts you can attach to SEC tickets.

Where it does not help: raw API fuzzing, high-volume brute force, anything Burp Intruder or
ffuf already does better. Use the `playwright-burp` server to get the traffic into Burp and fuzz there.

## Flags worth knowing

- `--storage-state <file>` – start already logged in (export from a manual session).
- `--allowed-origins "https://app.example.com;https://api.example.com"` – keep the browser on
  in-scope hosts. Not a hard boundary (redirects bypass it), but it stops accidental drift.
- `--caps devtools` (enabled) – network request inspection and console access.
- `browser_run_code_unsafe` runs arbitrary JS in the page; that is the point for testing, but
  don't point the server at untrusted sites while it has your real session cookies loaded.

## Claude Code on the web / cloud containers

The cloud container ships its own Chromium. Add these to the args to use it:
`--no-sandbox --executable-path /opt/pw-browsers/chromium-1243/chrome-linux64/chrome`.
Target hosts must also be allowed by the environment's network policy, or navigation fails with
`ERR_TUNNEL_CONNECTION_FAILED`.
