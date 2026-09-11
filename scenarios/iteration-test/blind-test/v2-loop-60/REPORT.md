# Iteration Test Blind Assessment — Loop 60

## Outcome

The loop-60 DNS packet-identity contract passes its direct rendered probe. All 3,863 qualifying
single-query, single-response UDP DNS exchanges across the core, DB, and DMZ sensors have exact
query-start and response-close equality between `dns.json` and `conn.json`, with zero mismatches.
The packet-sized interval exposed and repaired a sibling WFP source-admission defect: Windows 5156
can now occupy a valid sub-millisecond transport without inheriting the generic 1 ms lifecycle gap.
Automated evaluation passed at 96.2817 across 122,916 records.

## Individual Expert Summaries

**Threat Hunter:** Inconclusive, 80 verdict confidence, 56 synthetic-confidence. The repaired DNS
family was no longer cited. The strongest remaining defect was seven of 37 fully in-window SSH
sessions whose syslog retained PAM close evidence but omitted the matching open lifecycle. Selective
loss of process attribution on a pivotal SSH connection and under-specified WMI causality were
secondary concerns; scan texture and multi-source hunt pivots were strongly production-like.

**Detection Engineer:** Synthetic, 95 verdict confidence, 86 synthetic-confidence. All 11,605
Security 5156 records draw from the same 38 multiples-of-four execution ThreadIDs on every Windows
host, while authentication families use a second fixed pool and failures use a visibly different
regime. Uniform `HarddiskVolume1` mappings on 11,183 records and simplified SYSVOL/NETLOGON roots
reinforced the dataset-wide metadata fingerprint. No hard timing or identifier contradiction was
found.

**Network Forensics:** Real, 74 verdict confidence, 34 synthetic-confidence. Packet accounting,
state histories, DNS TTL aging, TLS/certificate behavior, independent sensor UIDs and clock drift,
and ASA lifecycle matching were judged production-like. The main contrary findings were an
unexplained firewall-policy discontinuity during an internal scan, 271/272 AAAA queries paired after
A in a narrow interval, and independently varying web page response sizes.

**Host/EDR Forensics:** Synthetic, 80 verdict confidence, 68 synthetic-confidence. Across 44 browser
creates on eight hosts, only two roots had visible children and most completed roots lived longer
than one hour; four concurrent Firefox URL-bearing roots on one workstation neither reused an
instance nor produced normal child families. Sparse Windows process texture, fleet-wide Linux
daemon templates, a narrow scanner population, and questionable Event 8 semantics added support.

## Deliberation Findings

Verdict disagreement and the 52-point synthetic-confidence spread required deliberation. The
facilitator judged the identical exhaustive Windows execution-thread pools to be the strongest
remaining fingerprint, because protocol realism does not explain independent endpoint metadata.
Final scores were 68, 88, 53, and 77 (mean 71.5): three Synthetic verdicts and one Inconclusive,
synthetic-leaning verdict. The network analyst's production-like findings remained the strongest
counterweight and prevented near-certain corpus-wide synthetic confidence.

## Prioritized Improvements

### P0 — Replace finite Windows execution metadata pools

Generate `System/Execution` process and thread metadata from persistent, host-specific provider
state. Related event families should share the correct provider process and thread lifecycles,
without globally exhaustive ranges or sharp success/failure regimes. Assign installation-specific
NT device-volume mappings through the same host identity layer.

### P1 — Model browser roots, children, reuse, and turnover as one action lifecycle

Create persistent browser roots with realistic renderer, GPU, network, utility, and crash-handler
children. Later URL invocations should usually hand off to an existing instance and exit quickly
unless an independent profile or explicit new-instance option owns a separate root.

### P1 — Make SSH source observation lifecycle-coherent

Apply one source-local observation decision to accepted authentication, PAM open, session creation,
shell activity, PAM close, and session termination. Preserve source process attribution when its
lifecycle permits; distribute intentional attribution loss independently of storyline importance.

### P1 — Make firewall policy authoritative during scans

Have scan outcomes consume the active ACL. If temporary access is intended, model the rule or
dynamic authorization, its effective interval, and restoration so ASA, Zeek, endpoint, and IDS
evidence agree with one policy state.

### P2 — Broaden host-specific distribution texture

Vary Linux daemons, package history, scheduled commands, message pools, and cadence by host role and
installation. Add a long tail of low-frequency scanners, diversify A/AAAA resolver behavior, and
derive stable page response sizes from resource identity and content encoding.

### P2 — Correct source-native identity and semantics

Render deployment-appropriate SYSVOL/NETLOGON paths, resolve the three sparse FUID gaps through
coherent observation, and omit Sysmon Event 8 for read-only LSASS access unless an actual injection
lifecycle owns a plausible remote entry point.

## Priority Rationale

Windows execution metadata is first because it is a high-volume, dataset-wide fingerprint with no
credible explanation from source loss or bounded collection. Browser and SSH lifecycle defects are
next because they recur across independently visible process/session evidence. Firewall policy and
distribution improvements are broad but admit more operational alternatives. Source-native path,
FUID, and one-off Event 8 defects remain important lower-scope cleanup.

## Comparison with Quantitative Eval

The deterministic evaluator remained at 96.2817: 99.9992 parseability, 96.8186 plausibility,
93.9479 causality, and 92.9514 timing. It confirmed broad source conformance, field agreement,
causal ordering, and rate plausibility while retaining the known eCAR rename, sparse FUID/OCSP,
storyline presence, pivot, and timing findings. It did not detect the repaired packet-derived DNS
identity or the newly prioritized Windows ThreadID, browser lifecycle, SSH observation, firewall
policy, and cross-host distribution fingerprints, so rendered probes and blind review remain
necessary complements.
