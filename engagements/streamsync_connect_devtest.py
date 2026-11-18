#!/usr/bin/env python3
"""
StreamSync /api/connect/* — dev pen-test harness  (run on your allowlisted Mac)

Scope (verified from the Abe/Aladdin thread, 2026-11-12 → 11-17):
  - DEV ONLY. Base host must be api.sync-dev.workstream.us. Prod is out of scope.
  - Source must be an allowlisted IP (98.248.154.177 home / 73.252.205.250 office).
  - Credentials come from your shell env (you export them from 1Password). This
    script never opens 1Password links and never prints secret values.
  - Synthetic SSNs only: 000-XX-XXXX. The script refuses anything else.

This file does NOT run anything by itself. You run it, from your Mac. It is a
request harness for the authz/isolation cases you listed to Abe, with backoff so
you stay under 60/min per token, 500/day per company, 5 rps route throttle, and
don't needlessly trip the 10-refusals/5-min guardians@ alarm.

Fill in the  # CONFIRM:  markers with the exact routes/bodies before a real pass.
"""

import os, re, sys, time, json
import urllib.request, urllib.error

# ---- hard scope guards -------------------------------------------------------
BASE = os.environ.get("SYNC_BASE", "https://api.sync-dev.workstream.us")
if "sync-dev.workstream.us" not in BASE:
    sys.exit(f"REFUSED: base host {BASE!r} is not the dev surface. Dev only.")

SSN_OK = re.compile(r"^000-\d{2}-\d{4}$")  # synthetic only

def _ssn(s):
    if not SSN_OK.match(s):
        sys.exit(f"REFUSED: {s!r} is not a synthetic SSN (000-XX-XXXX).")
    return s

# ---- creds from env (exported from 1Password; never hard-coded) --------------
def _req(name):
    v = os.environ.get(name)
    if not v:
        sys.exit(f"Missing env {name}. Export it from 1Password before running.")
    return v

PARTNER_KEY = _req("FLEXSPRING_PARTNER_KEY")   # dev Flexspring partner key
TOKEN_A     = _req("COMPANY_A_TOKEN")          # internal test company A
UUID_A      = _req("COMPANY_A_UUID")
TOKEN_B     = _req("COMPANY_B_TOKEN")          # internal test company B
UUID_B      = _req("COMPANY_B_UUID")

# ---- throttled request -------------------------------------------------------
_MIN_INTERVAL = 0.25  # ~4 rps, under the 5 rps burst-10 route throttle
_last = [0.0]
def call(method, path, token=None, key=None, body=None):
    dt = time.time() - _last[0]
    if dt < _MIN_INTERVAL:
        time.sleep(_MIN_INTERVAL - dt)
    url = BASE + path
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    if token: r.add_header("Authorization", f"Bearer {token}")
    if key:   r.add_header("X-Partner-Key", key)   # CONFIRM: exact header name
    if data:  r.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(r, timeout=20) as resp:
            _last[0] = time.time()
            return resp.status, resp.read(400).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        _last[0] = time.time()
        return e.code, e.read(400).decode("utf-8", "replace")

def check(name, got, want, note=""):
    ok = got == want
    print(f"[{'PASS' if ok else 'FAIL'}] {name}: got {got}, want {want}  {note}")
    return ok

# ---- test cases (the 9 you dry-ran with Abe) ---------------------------------
# CONFIRM every path/body below against the #428/#477 routes before a real pass.
def run():
    KNOWN_SSN = _ssn(os.environ.get("KNOWN_SSN_A", "000-00-0000"))  # the dry-run hit on A

    # 1. lookup + record found (company A, own data, synthetic SSN)
    s, _ = call("POST", "/api/connect/request", token=TOKEN_A, key=PARTNER_KEY,
                body={"company": UUID_A, "ssn": KNOWN_SSN})  # CONFIRM body shape
    check("A reads own record", s, 200)

    # 2. cross-company isolation: B must NOT see A's record
    s, _ = call("POST", "/api/connect/request", token=TOKEN_B, key=PARTNER_KEY,
                body={"company": UUID_A, "ssn": KNOWN_SSN})
    check("B cannot read A", s, 403, "(or 404 by design — confirm w/ Abe)")

    # 3. token refused for the other company's UUID
    s, _ = call("POST", "/api/connect/request", token=TOKEN_A, key=PARTNER_KEY,
                body={"company": UUID_B, "ssn": KNOWN_SSN})
    check("A token refused for B's UUID", s, 403)

    # 4. no partner key
    s, _ = call("POST", "/api/connect/request", token=TOKEN_A, key=None,
                body={"company": UUID_A, "ssn": KNOWN_SSN})
    check("missing partner key refused", s, 401, "(confirm 401 vs 403)")

    # 5. bad token
    s, _ = call("POST", "/api/connect/request", token="not-a-real-token",
                key=PARTNER_KEY, body={"company": UUID_A, "ssn": KNOWN_SSN})
    check("bad token refused", s, 404, "(thread showed 404 for bad bearer)")

    # 6. bad SSN (still synthetic, just no record)
    s, _ = call("POST", "/api/connect/request", token=TOKEN_A, key=PARTNER_KEY,
                body={"company": UUID_A, "ssn": _ssn("000-99-9999")})
    check("unknown synthetic SSN -> not found", s, 404)

    # 7. headers on the /connect rewrite path (CSP / XFO / HSTS)
    #    run: curl -sI https://sync-dev.workstream.us/connect   and diff against
    #    the baseline Abe posted (CSP self, XFO DENY, HSTS 31536000).

    # --- connection-link cases for #428 (single-use link tokens, NOT the above) ---
    # 8. reconnect account-binding -> partner_account_mismatch
    # 9. claim-before-write race: fire 2 concurrent claims on one single-use link,
    #    expect exactly one win; link locks after 5 failed attempts.
    #    OAuth secret-capture: new link against an OAuth2 authz-code service.
    #    These need the fresh single-use links Abe reshared — wire them in once
    #    you've confirmed the /api/connect/* claim + oauth callback routes.
    print("\nconnection-link cases (8-9): fill in once link routes are confirmed.")

if __name__ == "__main__":
    print(f"Target: {BASE}  (dev-only guard passed)")
    print("Reminder: run from an allowlisted IP; expect 429s and the refusal alarm.\n")
    run()
