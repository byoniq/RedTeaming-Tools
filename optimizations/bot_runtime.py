"""
bot_runtime.py — stack-agnostic helpers for your bot fleet. Stdlib only.

Covers the three "Adopt" orchestration items:
  - Centralized backoff + idempotency keys  -> @retry, idempotency_key()
  - Structured logs + shared run ledger      -> StructuredLogger, RunLedger

Drop this next to your bots and import it. If your bots aren't Python, treat
this as the reference behavior to port.
"""
from __future__ import annotations
import functools, hashlib, json, os, random, sys, time
from datetime import datetime, timezone

# --- backoff ------------------------------------------------------------------
class RetryableError(Exception):
    """Raise (or let a 429/5xx raise) to trigger a retry."""

def retry(max_attempts=5, base_delay=0.5, max_delay=30.0, jitter=True,
          retry_on=(RetryableError,)):
    """Exponential backoff with full jitter. Honors a `.retry_after` attr if the
    exception carries one (e.g. from an HTTP 429 Retry-After header)."""
    def deco(fn):
        @functools.wraps(fn)
        def wrapped(*a, **kw):
            attempt = 0
            while True:
                try:
                    return fn(*a, **kw)
                except retry_on as e:
                    attempt += 1
                    if attempt >= max_attempts:
                        raise
                    ra = getattr(e, "retry_after", None)
                    delay = float(ra) if ra else min(max_delay, base_delay * 2 ** (attempt - 1))
                    if jitter:
                        delay = random.uniform(0, delay)
                    time.sleep(delay)
        return wrapped
    return deco

# --- idempotency --------------------------------------------------------------
def idempotency_key(*parts) -> str:
    """Stable key for an action so parallel bots don't double-apply it.
    Pass the stable inputs: (agent, action, target, *distinguishing_args)."""
    raw = "\x1f".join(str(p) for p in parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:32]

# --- structured logging -------------------------------------------------------
class StructuredLogger:
    """One JSON object per line, to stdout and optionally a file. Greppable,
    machine-parseable, and safe to interleave across concurrent bots."""
    def __init__(self, agent: str, path: str | None = None):
        self.agent = agent
        self._fh = open(path, "a", encoding="utf-8") if path else None

    def log(self, level: str, event: str, **fields):
        rec = {"ts": datetime.now(timezone.utc).isoformat(),
               "agent": self.agent, "level": level, "event": event, **fields}
        line = json.dumps(rec, default=str)
        print(line, file=sys.stderr if level in ("error", "warn") else sys.stdout, flush=True)
        if self._fh:
            self._fh.write(line + "\n"); self._fh.flush()

    def info(self, event, **f):  self.log("info", event, **f)
    def warn(self, event, **f):  self.log("warn", event, **f)
    def error(self, event, **f): self.log("error", event, **f)

# --- shared run ledger --------------------------------------------------------
class RunLedger:
    """Append-only JSONL record of what every bot did. Use `seen()` to make a
    run idempotent across restarts and across sibling bots sharing the file."""
    def __init__(self, path="run_ledger.jsonl"):
        self.path = path

    def seen(self, idem: str) -> bool:
        if not os.path.exists(self.path):
            return False
        with open(self.path, encoding="utf-8") as fh:
            for line in fh:
                try:
                    if json.loads(line).get("idem") == idem:
                        return True
                except json.JSONDecodeError:
                    continue
        return False

    def record(self, agent, action, target, status, idem=None, **extra):
        row = {"ts": datetime.now(timezone.utc).isoformat(), "agent": agent,
               "action": action, "target": target, "status": status,
               "idem": idem, **extra}
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, default=str) + "\n")

# --- example ------------------------------------------------------------------
if __name__ == "__main__":
    log = StructuredLogger("demo-bot")
    ledger = RunLedger("/tmp/demo_ledger.jsonl")
    key = idempotency_key("demo-bot", "send", "ticket-42")
    if ledger.seen(key):
        log.info("skip_duplicate", idem=key)
    else:
        @retry(max_attempts=3)
        def do_work():
            log.info("working", target="ticket-42")
            return "ok"
        status = do_work()
        ledger.record("demo-bot", "send", "ticket-42", status, idem=key)
        log.info("done", status=status, idem=key)
