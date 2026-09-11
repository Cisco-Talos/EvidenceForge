# Iteration Test Blind Assessment — Loop 64

## Outcome

Loop 64 made installed-release and selected Windows OS-binary hashes and PE metadata canonical
before Sysmon rendering. The automated evaluation scored 96.5904 PASS across 127,148 records. The
current-model blind panel produced initial synthetic-confidence scores of 49, 71, 68, and 87
(mean 68.75), with one Inconclusive and three Synthetic verdicts. Required deliberation revised
the scores to 66, 78, 74, and 90 (mean 77.00), with a unanimous final Synthetic verdict.

## Individual Expert Summaries

**Threat Hunter:** Inconclusive, 82 verdict confidence, 49 initial synthetic-confidence; revised
to Synthetic, 86 and 66. Strong lifecycle, source-mix, byte-accounting, and pivot coherence were
offset by universal cross-source timing bands, alternate-token creator semantics, and repeated
built-in Type 5 service logons.

**Detection Engineer:** Synthetic, 82 verdict confidence, 71 initial synthetic-confidence;
revised to 88 and 78. Canonical third-party release hashes improved, but broader inbox binaries
still carried host-incompatible PE versions, widespread metadata placeholders, and selective
hash absence. Nearly identical Linux PID advancement across unrelated hosts was also decisive.

**Network Forensics:** Synthetic, 86 verdict confidence, 68 initial synthetic-confidence;
revised to 89 and 74. Network topology, transport variation, TLS, and multi-sensor correlation
were strong. Missing redirect locations and follow-on TLS clients, DNS-after-origin timing,
REFUSED/rejected disagreement, noncanonical IPv6 text, and orphaned FUIDs remained concrete tells.

**Host/EDR Forensics:** Synthetic, 95 verdict confidence, 87 initial synthetic-confidence;
revised to 96 and 90. Low-range anacron PIDs interrupted high-range process allocation on ten
hosts, timestamp precision was event-family dependent, and hardware/package vocabularies repeated
across unrelated systems. Repeated Type 5 service logons were an additional fleet-wide texture.

## Fix Verification

- Five cross-host application release groups now use one hash set per exact product release and
  artifact: Slack, Slack ELF, Teams, OneDrive, and FileSyncShell64.
- `winlogon.exe` and `userinit.exe` now separate the modeled 17763, 19041, 20348, and 22621 build
  families with one stable hash set per family; the targeted probe found zero build violations.
- Production generation now compiles and binds the deployment registry before process dispatch,
  so exact release or explicit unresolved identity reaches canonical process events.
- The loop exposed a broader sibling: other Windows inbox binaries still use fallback metadata
  not coherently keyed to each host build, and many readable binaries remain explicitly unresolved.

## Prioritized Improvements

### P0 — Unify Linux PID allocation across every event family

Use one host-specific allocator for eCAR and syslog-only processes, including anacron, CRON, SSH,
and sudo. Vary churn by host role and workload; reject unexplained low-PID process starts inside a
high-range lifecycle.

### P0 — Complete host-build-owned Windows binary inventory

Extend the deployment registry beyond the initial winlogon/userinit and application releases so
explorer, mstsc, gpresult, gpupdate, runas, curl, taskhostw, svchost, dllhost, cmd, WmiPrvSE, and
other inbox binaries derive hashes and PE resources from the concrete host build.

### P0 — Complete HTTP redirect and DNS source-native contracts

Populate redirect locations and suitable entity metadata, continue clients into TLS where
appropriate, require valid DNS cache state before origin connection, align REFUSED/rejected
semantics, canonicalize IPv6 answers, and preserve HTTP/FUID/file observation groups.

### P1 — Model Windows creator and target-token ownership

When a SYSTEM or NETWORK SERVICE parent launches a user-token child, preserve the actual creator
in Security 4688 Subject and the alternate child token in Target Subject, aligned with Sysmon and
eCAR. Reuse persistent built-in service sessions instead of repeatedly emitting Type 5 logons.

### P1 — Apply host/source timing and inventory texture

Move precision and latency regimes from event families to host/source collection profiles. Bind
IRQ devices, snap packages, and similar environmental vocabulary to persistent host inventories.

## Comparison with Quantitative Eval

The deterministic evaluator scored 96.5904: 99.9992 parseability, 96.9310 plausibility, 94.8004
causality, and 93.2886 timing. It confirmed canonical ordering and broad source conformance but did
not detect Linux PID namespace contradictions, semantic timestamp quantization, incomplete
host-build binary inventories, redirect/DNS lifecycle gaps, or repeated service-logon texture.
