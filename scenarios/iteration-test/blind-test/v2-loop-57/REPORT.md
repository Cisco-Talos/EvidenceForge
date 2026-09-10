# Iteration Test Blind Assessment — Loop 57

## Outcome

The restarted loop-57 contracts pass their rendered probes. All 18 DHCP transactions preserve
source-native phase order with 54 distinct microsecond suffixes, and all 23 visible
`userinit.exe` process starts identify a SYSTEM-owned `winlogon.exe` parent with no resolvable
Sysmon parent-principal mismatch. Automated evaluation passed at 97.3622 across 122,545 records.

## Expert summaries

- **Threat Hunter:** Inconclusive, 78 verdict confidence, 44 synthetic-confidence. Found an
  account-enable lifecycle gap, a close-only SCP receiver syslog lifecycle, and weaker DNS-cache
  and command-pool texture.
- **Detection Engineer:** Synthetic, 78 verdict confidence, 65 synthetic-confidence. Found
  sub-millisecond phase retention in failed-logon retry bursts and an all-zero population of 840
  Windows process exit statuses, while rating schemas and keyed correlations highly.
- **Network Forensics:** Synthetic, 94 verdict confidence, 83 synthetic-confidence. Found
  packet-derived DNS duration contradictions, incoherent HTTP/file loss accounting, exact
  cross-sensor DNS RTT reuse, and unstable SYN header sizes within one scan campaign.
- **Host/EDR Forensics:** Synthetic, 94 verdict confidence, 84 synthetic-confidence. Confirmed
  the repaired parent principal, then found session-length RDP `userinit.exe` lifetimes, one RDP
  transport/disconnect mismatch, systematic Sysmon metadata placeholders, and narrow SSH timing.

Deliberation was required by the verdict disagreement and 40-point score spread. It ended
unanimously Synthetic at 74, 80, 87, and 88 synthetic-confidence (mean 82.25). The facilitator
gave greatest weight to packet-level contradictions and the repeated RDP `userinit.exe` lifecycle
split while retaining source-native fidelity, topology, and cross-source identity as strong
counterevidence.

## Prioritized improvements

1. **P0 — packet-owned DNS timing:** derive UDP DNS connection close from the counted request and
   response packet times; a one-request/one-response `Dd` flow must not retain a seconds-long tail.
2. **P0 — RDP initializer lifecycle:** terminate `userinit.exe` shortly after it launches Explorer
   for Type 10 as well as Type 2 sessions, with one cross-source terminalization contract.
3. **P0 — sensor-local HTTP/file loss:** make connection loss, HTTP body length, file seen/total
   bytes, analyzer limits, and hash availability consequences of one observation decision.
4. **P1 — authentication and process outcome texture:** independently time failed-logon retries
   and add source-correlated nonzero process exit outcomes as a small, cause-aware tail.
5. **P1 — lifecycle-coherent collection:** emit account-enable 4722 when UAC semantics require it
   and keep SSH/SCP open/auth/PAM/close evidence coherent under source observation.
6. **P1 — image metadata:** populate build-aware PE version fields for standard session binaries
   and common third-party services instead of family-wide `-` placeholders.
7. **P2 — network and operational texture:** derive DNS RTT per sensor, keep scanner packet
   construction stable per invocation, and tie repeated shell/cron/SSH timing to observable
   organization or runtime causes.

## Quantitative comparison

The deterministic score rose from loop 56's 96.1263 to 97.3622, primarily because this generated
bundle contains 122,545 records and scores 97.53 on causality. The deterministic evaluator does
not yet measure the two repaired source-native contracts or the new packet/lifecycle findings, so
the hard probes and blind reports remain the authoritative evidence for those families.
