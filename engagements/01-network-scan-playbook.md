# Network Scan Playbook (authorized internal assessment)

> **Preconditions:** `00-SCOPE-AND-ROE-TEMPLATE.md` is completed and signed, and you
> are running this **from an authorized host that sits on / can reach the in-scope
> network** — not from an ephemeral cloud sandbox. Set `$SCOPE` to your signed
> in-scope file; never substitute "the whole company".

```bash
export ENGAGEMENT="itsec-XXXX"
export SCOPE="./scope/in-scope.txt"        # one CIDR/host per line, from signed ROE
export EXCLUDE="./scope/exclude.txt"       # out-of-scope hosts (Section 4 of ROE)
export OUT="./out/${ENGAGEMENT}"; mkdir -p "$OUT"
```

## Phase 1 — Host discovery (know what's alive before you scan ports)

```bash
sudo nmap -sn -iL "$SCOPE" --excludefile "$EXCLUDE" \
  -oA "$OUT/01-discovery"
# Extract live hosts for the next phases:
grep "Up" "$OUT/01-discovery.gnmap" | cut -d' ' -f2 > "$OUT/live-hosts.txt"
```

**Transition checkpoint #1 — report after this:** count of live hosts, any surprises
(hosts that shouldn't be alive, unexpected subnets responding).

## Phase 2 — Top 100 ports (SYN), fast triage

```bash
sudo nmap -sS --top-ports 100 -iL "$OUT/live-hosts.txt" --excludefile "$EXCLUDE" \
  -T3 --open -oA "$OUT/02-top100"
```

Review for the things that "entice attackers":
- Unnecessary exposed services (RDP/3389, SMB/445, Telnet/23, FTP/21, old DBs).
- Management interfaces that shouldn't be reachable.

**Transition checkpoint #2 — report after this:** per-host open-port summary, list of
"why is this open?" candidates.

## Phase 3 — Top 1000 ports + service/version + safe scripts

```bash
sudo nmap -sS --top-ports 1000 -sV -iL "$OUT/live-hosts.txt" \
  --excludefile "$EXCLUDE" -T3 --open \
  --script "default,banner" \
  -oA "$OUT/03-top1000-sv"
```

This captures **service banners and version giveaways** (the info-leak the request is
really about): server versions, OS hints, default landing pages, verbose error pages.

**Transition checkpoint #3 — report after this:** full service/version inventory,
flagged banner/version disclosures, and a shortlist of services for Phase 4.

## Phase 4 — Service enumeration with netexec (read-only / default-cred check)

> Only the protocols in scope, only against in-scope hosts, only if Section 5 of the
> ROE authorizes default-credential checks. netexec is loud and authenticates — this
> is where accidental account lockouts and IDS alerts happen, so confirm lockout
> policy first.

```bash
# Enumerate first (no auth) to see what answers on each protocol:
for proto in smb ldap mssql ssh ftp rdp winrm vnc; do
  nxc $proto "$OUT/live-hosts.txt" --log "$OUT/04-nxc-$proto.log"
done
```

Default-cred / null-session checks (authorized engagements only):
```bash
nxc smb  "$OUT/live-hosts.txt" -u '' -p ''          # null session
nxc smb  "$OUT/live-hosts.txt" --shares             # readable shares
nxc mssql "$OUT/live-hosts.txt" -u sa -p ''         # classic default
# Use a curated default-cred list, NOT a brute-force wordlist:
nxc <proto> "$OUT/live-hosts.txt" -u defaults.txt -p defaults.txt --no-bruteforce
```

**Stop conditions (mandatory):** stop and notify the owner if you (a) trigger an
account lockout, (b) land a foothold on a host that turns out to be out of scope,
(c) touch anything holding PII/payroll/financial data, or (d) cause a service
disruption. Foothold/post-exploitation beyond proving access requires separate
explicit sign-off.

**Transition checkpoint #4 — final report:** services with default/weak/null auth,
each mapped to an affected host, severity, and remediation.
