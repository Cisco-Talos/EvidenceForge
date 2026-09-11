# Iteration Test Blind Assessment — Loop 66

## Outcome

Loop 66 published the RDP authentication frontier before dependent authored user activity. The
automated evaluation scored 96.2339 PASS across 125,914 records. The blind panel produced
synthetic-confidence scores of 73, 92, 89, and 86 (mean 85.00), unanimously Synthetic. No
deliberation was required: average verdict confidence was 89.5 and the score spread was 19.

## Individual Expert Summaries

**Threat Hunter:** Synthetic, 78 verdict confidence, 73 synthetic-confidence. Multi-source pivots,
network distributions, and lifecycle bookkeeping were strong, but the repaired RDP session later
continued launching Explorer-owned interactive tools after its transport and Event 4779
disconnect, with no reconnect or alternate execution mechanism. Repeated uncommon Linux admin
one-liners were supporting texture.

**Detection Engineer:** Synthetic, 94 verdict confidence, 92 synthetic-confidence. Source schemas,
process correlation, Zeek linkage, ASA lifecycles, and bounded-window session semantics were
strong. The decisive defect was one Explorer 19041 binary identity reused on hosts whose adjacent
Windows components identify 17763, 20348, and 22621 build families. Narrow logon-chain timing,
integer-millisecond failed-SSH sequences, all-zero Security 4689 statuses, and selective hash gaps
reinforced the verdict.

**Network Forensics:** Synthetic, 94 verdict confidence, 89 synthetic-confidence. Sensor-local
tuples, DNS/TLS texture, and connection lifecycles were broadly convincing. The Nmap `-sT` family
nevertheless created application payload transactions, scanned all 254 addresses without `-Pn`
despite only nine discovery responses, and emitted 1,244 identical one-SYN `S0` flows. Proxy tunnel
durations also exceeded their exact TCP carrier lifetimes in 431 of 715 inspected tunnels.

**Host/EDR Forensics:** Synthetic, 92 verdict confidence, 86 synthetic-confidence. Windows/eCAR
correlation and role-specific host activity were strong. The same cross-build Explorer identity
was a decisive contradiction; fleet-wide SSH shell termination long before PAM/session close,
148–152 ms userinit-to-Explorer timing, and all-five-field PE metadata gaps across 691 of 938
Sysmon process creates were additional family-level tells.

## Fix Verification

- For the targeted RDP session, eCAR now renders the TCP/3389 FLOW at 15:20:19.944, Type 10 LOGIN
  for LogonID `0x27015bf` at 15:20:25.365, `cmd.exe` at 15:20:25.366, and `whoami.exe` at
  15:20:26.200. The former same-LUID process-before-login contradiction is gone.
- Windows Security retains the same source tuple `10.10.1.99:58332`, LogonID, and causal order into
  Event 4688 evidence; Sysmon receives the same post-login process frontier.
- Exact deferred RDP/SSH projection timing now stages the already-planned session publication
  frontier without retroactively reordering bundle-owned bootstrap evidence. The compatibility
  Type 10 storyline path records the same readiness contract.
- Behavior revision 30 records the family change with surface digest
  `9ad3c48fa5b74e270d2ba31d3da22649500cb5a703f62999e6db564f576780f2`.
- The routine gate passed with 8,397 tests and 5 skips; repository-wide Ruff check and format check
  passed across 769 files.
- The repaired process-before-login inversion did not recur in any blind report.

## Prioritized Improvements

### P0 — Make Windows binary identity host-build complete

Resolve all Windows-owned PE identities from the host build, architecture, and exact binary
release. In particular, Explorer, winlogon, userinit, PowerShell, and other inbox components on one
host must belong to the same build family, while different host builds must not reuse one fixed
Explorer hash. Model metadata/hash collection loss as a scoped observation condition instead of a
deterministic executable-family omission.

### P1 — Make Nmap effects obey command semantics

Default connect scans must perform discovery and scan only hosts considered up unless `-Pn` is
present. Plain `-sT` sockets must not inherit normal HTTP, TLS, SMB, or SSH application payloads,
and unanswered targets need realistic retransmission/history texture rather than a 1,244-row
one-SYN clone.

### P2 — Preserve a control path for post-disconnect RDP activity

Keep the RDP transport active, emit a source-correlated reconnect/Event 4778, or move later
activity to a visible service, task, WMI/WinRM, injection, or resident-script owner. New Explorer
children in a disconnected Type 10 session should fail lifecycle validation when no replacement
control path is present.

### P3 — Bound source-native lifecycles and carrier durations

Keep proxy tunnel summaries within their canonical TCP carriers and prevent SSH login shells from
terminating long before PAM/logind close unless a surviving same-session process explains the gap.
Carry file-transfer shortfalls into the owning HTTP/connection loss contract.

### P4 — Broaden timing and outcome texture

Replace the narrow userinit-to-Explorer and failed-SSH timestamp constructions with host/load-aware
native-precision timing. Populate realistic process exit outcomes and expand source-native PE and
ProcessAccess fields from canonical identities rather than small image/path pools.

## Priority Rationale

Host-build binary identity is first because two experts independently found the same impossible
Explorer build/hash reuse, it spans multiple Windows roles, and it extends the already established
canonical binary-identity family. Nmap semantics is next because it contains both hard protocol
contradictions and a large repeated distribution. RDP continuation and lifecycle/carrier bounds are
material but narrower, while timing and outcome texture have lower logical severity.

## Comparison with Quantitative Eval

The deterministic evaluator scored 96.2339: 99.9992 parseability, 96.8682 plausibility, 94.2708
causality, and 92.2471 timing. It confirmed broad schema conformance, intent reconciliation,
source-field agreement, IDS integrity, and plausible rates, but did not detect cross-build PE
identity reuse, Nmap application/discovery semantics, RDP post-disconnect control loss, proxy
tunnel/carrier inversion, SSH shell/session gaps, or repeated source-native timing and exit-status
texture. Its one strict schema failure remains eCAR `FILE/RENAME`.
