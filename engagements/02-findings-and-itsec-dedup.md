# Findings documentation & Jira ITSEC dedup

The brief: **document only critical vulnerabilities that are not already reported in
Jira ITSEC.** Workflow below keeps that disciplined.

## Step 1 — Dedup against ITSEC before writing anything up

For each candidate finding, search the ITSEC project first. Suggested JQL:

```
project = ITSEC AND statusCategory != Done
  AND (summary ~ "<service/host/CVE>" OR description ~ "<service/host/CVE>")
```

Match on: affected host/IP, service+port, and vuln class (e.g. "SMB null session",
"default mssql sa"). If an open/in-progress ticket already covers it → **do not
re-report**; add a comment with new evidence only if it materially changes severity.

> A Jira (Atlassian) connector can run these searches directly from this session once
> connected. If it isn't connected, do the searches in Jira and paste the ticket keys
> into the table below.

## Step 2 — Only file what is CRITICAL and NEW

Severity bar for filing (tune to your rubric — e.g. CVSS ≥ 9.0, or
unauthenticated access to sensitive data / RCE / domain foothold). Medium/low go in
the appendix of the engagement report, not as new ITSEC criticals.

## Step 3 — Finding record format

```
### FINDING-NN: <short title>
- Severity:            Critical
- Affected asset:      <host/IP : port  — service/version>
- ITSEC dedup:         searched <date> — no existing open ticket  (or: dupes ITSEC-####)
- Summary:             <what it is>
- Evidence:            <tool + command + sanitized output ref; store raw evidence
                        in the secure evidence store, NOT inline, NOT in this repo>
- Impact:              <what an attacker gains>
- Remediation:         <fix>
- Proposed ITSEC ticket: ITSEC-____ (created <date>)
```

## Step 4 — Evidence handling

- Raw scan output, credentials, PII: secure evidence store only. **Never** commit to
  this repo or paste into chat/tickets.
- This repo holds methodology and templates — not live results.

## Findings index

| # | Title | Severity | Asset | ITSEC | New? |
|---|-------|----------|-------|-------|------|
| | | | | | |
