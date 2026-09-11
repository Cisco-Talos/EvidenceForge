# Iteration Test Blind Assessment — Loop 61

## Outcome

Loop 61 removed the prior dataset-wide Windows Security execution-metadata fingerprint. The
rendered corpus has no unaligned execution ThreadIDs, no identical WFP ThreadID population between
Windows hosts, and seven installation-specific NT device-volume identities across ten hosts. The
automated evaluation remained at 96.2817 PASS across 122,916 records. The current-model blind panel
was unanimously Synthetic, with synthetic-confidence scores of 84, 66, 68, and 83 (mean 75.25).

## Individual Expert Summaries

**Threat Hunter:** Synthetic, 94 verdict confidence, 84 synthetic-confidence. The strongest finding
was a probable generator-identity leak: all proxy tunnel IDs and many eCAR file IDs expose the same
zero-padded 32-bit-in-64-bit construction, reinforced by low-entropy Postfix queue IDs. Visible Nmap
commands did not explain the nearly exhaustive scan matrix, and the encoded reverse shell omitted
mandatory `base64` and child-shell processes. Cross-source pivots, lifecycles, byte accounting, and
the source mix remained convincing.

**Detection Engineer:** Synthetic, 83 verdict confidence, 66 synthetic-confidence. The strongest
fingerprints were per-packet random selection from the same three TCP window sizes for recurring
scanner identities, random-looking unique six-digit Nikto test IDs, and zero variance across 825
Security 4689 exit statuses. Schema fidelity, Windows/Sysmon/eCAR joins, Zeek references, packet-loss
effects, SMTP STARTTLS, ASA lifecycles, and Linux source formats were judged highly realistic.

**Network Forensics:** Synthetic, 81 verdict confidence, 68 synthetic-confidence. Background DNS
used one fixed eight-character token grammar across 15 hosts, sinkhole answers had implausibly broad
per-domain TTLs, and mail-policy TXT queries were scattered across unrelated endpoint roles. All IDS
families shared a narrow connection-start offset and most inspected proxy tunnels carried only one
request. Connection states, cache TTL aging, proxy chronology, TLS chains, sensor identities,
ephemeral-port ranges, scan outcomes, and firewall lifecycles were strong counterevidence.

**Host/EDR Forensics:** Synthetic, 91 verdict confidence, 83 synthetic-confidence. Sysmon Event 8
used `NtCreateThreadEx` as a target thread entry function for a credential-read operation, while
Crashpad was repeatedly rendered as an Event 7 module. Only eight shallow ProcessAccess stack
templates covered 741 events, almost every paired Type 3 session ended within 65 seconds, two WMI
providers hit the exact same four-hour ceiling, and Firefox roots lacked native child/reuse behavior.
Process/session ordering, cross-source process joins, Linux SSH, privilege transitions, role texture,
and transfer lifecycles were otherwise strong.

## Prioritized Improvements

### P0 — Give each source family native identifier entropy

Proxy tunnel IDs, eCAR file IDs, and Postfix queue IDs reveal a shared zero-padded low-entropy
construction. Move identifier allocation to source-specific owners with realistic width, alphabet,
entropy, stability, and rollover behavior; shared canonical identity should remain internal and each
emitter should project its own native identifier.

### P0 — Correct Sysmon Event 8 ownership and target-thread semantics

Do not synthesize remote-thread evidence for ordinary LSASS memory access. When an actual injection
action owns Event 8, populate `StartAddress`, `StartModule`, and `StartFunction` from the target
thread entry routine rather than the creator API, and add a source/target lifecycle probe.

### P1 — Expand command semantics into executable action bundles

The reverse-shell pipeline requires `base64` and child-shell lifecycles, and the visible Nmap
command lacks `-Pn` despite scanning nearly every target after sparse discovery. Shell and scanner
bundles should derive children, socket ownership, discovery probes, and target eligibility from the
actual command semantics.

### P1 — Bind scanner, DNS-noise, and Nikto texture to persistent identities

Recurring scanner sources should preserve stack fingerprints rather than resampling one global
three-value TCP-window pool. Nikto test identifiers should come from a test catalog, while suspicious
background DNS should use per-family grammars and sinkhole-policy TTLs instead of one fleet-wide
template. Mail-policy TXT traffic should originate from role-appropriate software and hosts.

### P1 — Replace clipped process and session lifetimes with reusable lifecycles

Model persistent browser roots and children, short URL handoff invocations, protocol-specific
heavy-tailed Type 3 sessions, and activity/idle-driven WMI provider turnover. Remove exact duration
ceilings and broaden normal Windows process populations by host role.

### P2 — Derive source timing and outcomes from native causes

Timestamp IDS alerts from the triggering packet or one sensor clock transform, reuse proxy tunnels
for same-origin browser resources, and add a small process-specific nonzero 4689 status tail. Expand
ProcessAccess stacks by source process, call site, build, and occasional unresolved frames.

## Priority Rationale

The source-identifier family is first because it is the only panel finding labeled a probable
generator-identity leak, spans unrelated products, and drove the highest reviewer score. Sysmon
Event 8 is next because it is a source-native semantic contradiction, but its scope is smaller.
Command bundles, persistent scanner/DNS identity, and lifecycle texture are broad, repeated families
with high leverage but larger implementation surfaces. Timing and outcome texture follows after the
harder disbelief anchors.

## Comparison with Quantitative Eval

The deterministic evaluator remained at 96.2817: 99.9992 parseability, 96.8186 plausibility,
93.9479 causality, and 92.9514 timing. It confirmed source conformance, field agreement, causal
ordering, rate plausibility, and acceptance while retaining known eCAR rename, sparse FUID/OCSP,
storyline presence, pivot, and timing findings. It did not detect the identifier entropy leak,
Sysmon Event 8 semantics, command-to-process/scan gaps, scanner fingerprint instability, DNS-noise
grammar, browser/session clipping, or source-trigger timing distributions identified by the panel.
