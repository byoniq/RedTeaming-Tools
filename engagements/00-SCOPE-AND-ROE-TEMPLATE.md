# Scope & Rules of Engagement (ROE) — Template

> **No scanning, credential testing, or exploitation begins until this document is
> filled out, signed, and stored.** "All of Workstream" is not a scope. A scope is
> an explicit list of in-scope hosts/ranges, explicit exclusions, an authorized time
> window, and a named owner who can authorize the activity and stop it.

## 1. Engagement metadata

| Field | Value |
|-------|-------|
| Engagement name | |
| Date authorized | |
| Test window (start → end) | |
| Tester(s) | |
| Authorizing owner (name + role) | |
| Emergency stop contact (24/7) | |
| Jira tracking epic | ITSEC-____ |

## 2. Authorization statement

> I, _________________ (authorizing owner), confirm I have the authority to
> approve active security testing against the assets listed in Section 3, during
> the window in Section 1. Signed: ____________  Date: ________

## 3. In-scope targets (explicit)

List exact CIDRs / hostnames. No wildcards like "everything".

```
# Example
10.20.0.0/24        # corp-lan office subnet
10.30.10.0/28       # staging app servers
vpn.example.internal
```

## 4. Out-of-scope / DO NOT TOUCH

```
# Example
10.40.0.0/16        # production payroll segment — excluded
*.prod.example.com  # customer-facing prod — excluded
Any host hosting QuickBooks / Deel / payroll / PII data
```

## 5. Permitted activities (tick what is authorized)

- [ ] Passive recon / port discovery (SYN scan, service/version detection)
- [ ] Service banner / config enumeration (read-only)
- [ ] Default-credential checks against **in-scope** services (netexec)
- [ ] Credential spraying  ⚠️ requires explicit sign-off + lockout-policy review
- [ ] Exploitation / foothold  ⚠️ requires explicit sign-off + named owner

## 6. Constraints

- Rate limits / timing restrictions:
- Blackout periods (no testing):
- Data handling: findings with PII or secrets are stored in ______ and never
  pasted into chat, tickets, or this repo.
- Detection coordination: SOC notified? (Y/N) — contact: ______

## 7. Sign-off

| Role | Name | Signature | Date |
|------|------|-----------|------|
| Authorizing owner | | | |
| Lead tester | | | |
