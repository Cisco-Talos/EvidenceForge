# Loop 23 — TLS responder wire budget


Classification: family_level. Owner: canonical TLS/network traffic accounting, before event publication. Every complete certificate-bearing TLS 1.2 responder stream must cover all DER bytes, certificate framing, ServerHello, cipher/key-dependent key exchange and signatures, ChangeCipherSpec, Finished, TLS record overhead, and visible application payload. Entry paths: direct SSL, HTTPS/proxy, SMTP STARTTLS and other SSL attach callers; both initial context attach and final network reconciliation invoke the shared owner. Consumers: all Zeek sensors, endpoint FLOW and traffic ledgers, files/X509 observations, validation. Preserve connection tuple/UID and coherent payload/packet/IP-byte counts. Test RSA/ECDSA and HTTPS/STARTTLS siblings. Tunable optional extensions/tickets/dialogue are YAML backed; mandatory RFC framing cannot be configured away. Duration timing is the next loop, not part of this fix.

## Implementation and verification

The shared TLS accounting owner now computes DER framing, ServerHello, key-dependent exchange/signature size, completion records, optional extensions/tickets and visible application bytes. Optional ranges are YAML-backed and schema validated. Revision419; 92 focused tests, config validation (0 errors), Ruff and formatting passed. Fresh eval passed at96.564114 over125,255 records; all118 blind-copy files are identical. Whole-output probes found zero insufficient RSA2048 ECDHE budgets across460 observations (82 core,370 DMZ,8 DB). Duration floor remains for loop24.

## Individual Expert Summaries

**Threat Hunter:** Inconclusive; verdict confidence 82; synthetic-confidence score 47. The collection supports practical hunting across a mixed enterprise fleet, with coherent remote sessions, credential boundaries, staging, and proxy transfers. A narrow, repeated pattern of shell-based document access on the Macs looks constructed, particularly the approximately 26-minute cadence on one machine, but the checked attack and process lifecycles did not expose a decisive contradiction. I would lean slightly toward synthetic on behavioral texture, while retaining substantial uncertainty.

**Detection Engineer:** Inconclusive; verdict confidence 78; synthetic-confidence score 42. The supplied records generally ingest and correlate sensibly: Windows provider/event structure, Zeek protocol references, process identities, and visible lifecycle ordering held up under systematic checks. A suspicious application-module representation and concentrated loss of PE resource metadata leave a modest synthetic lean, but neither proves fabrication independently.

**Network Forensics:** Synthetic; verdict confidence 84; synthetic-confidence score 72. The network evidence is substantially coherent: protocol references, connection intervals, TLS certificate facts, proxying, and infrastructure roles agree in the checks performed. A repeated TCP packet-accounting artifact across unrelated services and sensors is the main reason for a synthetic verdict: clean histories have byte counters incompatible with ordinary complete IPv4/TCP header arithmetic, usually at an exact 1,500-bytes-per-packet ceiling.

**Host Forensics:** Synthetic; verdict confidence 86; synthetic-confidence score 64. The endpoint evidence has convincing process identity and lifecycle correlation, particularly across Windows sources and macOS fork/exec chains. Native macOS file metadata nevertheless exhibits a pronounced fractional-timestamp fingerprint, with repeated browser startup timing providing secondary support. Concurrent Chrome lifetimes raise a further concern, although unrecorded profile configuration limits that finding.

## Deliberation Findings

Standalone47/42/72/64 mean56.25, confidence mean82.5. Split verdicts triggered deliberation: facilitator-modeled64/60/72/69 mean66.25. These are not new independent reviews or measured consensus; TCP sequence-accounting caveat is retained.

## Prioritized Improvements

| Priority | Category | Scope/reviewer/leverage | Owner, action and risk |
|---|---|---|---|
| P1 | distribution_texture | Native Mac stat fractions; Host; repeated/high | Canonical installed provisioning produces tiny nanosecond tails. Loop25 separates package and host-local precision; moderate risk. |
| P1 | hard_contradiction, with caveat |65 clean TCP directional arithmetic failures; Network; high | Shared IP-byte helper clamps at1500 times packets. Fix compatible header/segmentation construction across SMB, HTTP/TLS, RDP/SSH; moderate risk. Sequence-derived bytes remain a real interpretation caveat. |
| P2 | distribution_texture | Mac helpers and share cadence; Host/Threat; medium | Separate explicit intent from generated timing before fixing shared process planner; moderate risk. |
| P3 | environment_or_collection_plausibility | DBeaver JDBC-like DLL and PE metadata blanks; Detection; low/medium | Verify module catalog and binary metadata against bounded native references; do not assume an impossible private binary. |

## Quantitative comparison and priority rationale

Score fell2.5 versus loop22; direct probes clear the targeted wire budget. New families surfaced rather than a verified latest-fix regression. Eval remains above90 without a material guardrail drop. Fix the already-verified metadata owner after duration, then the shared TCP clamp. No scenario edits or commits. Preserve alternative collector/session explanations and distinguish them from impossible source-native fields.
