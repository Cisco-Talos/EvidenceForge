# Loop 42 Assessment Report

Loop 42 generated 79,750 new records after binding endpoint file and registry
effects to source-native process families. Automated evaluation scored 96.1147
and failed only pivot linkability. Current-output probes found zero ambient WER,
CBS, or Office-registry records; Defender history was owned only by
`MsMpEng.exe`, and user Explorer state was owned by Explorer. No reviewer
repeated the prior WER/Defender/CBS/Office ownership contradiction.

The initial blind panel was Inconclusive/Inconclusive/Synthetic/Synthetic at
43/43/88/87, average 65.25. Verdict disagreement and a 45-point spread triggered
deliberation; all four revised to Synthetic at 82/84/91/91, average 87.0.

## Individual Expert Summaries

The Threat Hunter was initially Inconclusive (74% verdict confidence,
synthetic-confidence 43). It found the environment, tradecraft, volumes, and
most pivots convincing, but repeated WMI-attributed target execution lacked a
contemporaneous source caller and viable RPC/WinRM transport, while one SSH
pivot lacked its source client process.

The Detection Engineer was initially Inconclusive (82%, 43). Windows schemas,
process lifecycles, Zeek UID correlation, and hash/build fidelity were strong.
It found one Event 1102 with empty required subject fields and 132 ICMP Zeek JSON
connections using the ASCII unset marker `-` as history.

The Network analyst assessed Synthetic (94%, 88). Across hundreds of CONNECT
sessions, Zeek byte counters equaled the logged tunnel counters while omitting
the separately logged control exchange on the same UID; ASA totals independently
supported the larger total. It also found bounded TLS delays, exact-millisecond
DNS RTT concentration, and near-universal 42–66 ms inter-sensor offsets.

The Host/EDR analyst assessed Synthetic (94%, 87). Linux logind session IDs
advanced at one of two nearly exact wall-clock rates across nine hosts, unrelated
hosts reused an identical IRQ/device map, and 103 of 111 Sysmon Event 11 rows
used one five-decimal-digit temp filename grammar.

## Deliberation Findings

All four specialists converged on Synthetic. The proxy byte ledger and Linux
session counter were judged dataset-wide semantic/allocation contradictions,
not mere completeness or bounded-window artifacts. Strong local schemas and
causality can coexist with global generator fingerprints; IRQ reuse, bounded
network timing, source-native schema gaps, and incomplete remote-execution
contracts supplied independent corroboration.

## Prioritized Improvements

- **P0 — Separate CONNECT control bytes from tunnel payload while preserving one
  canonical TCP total.** Network quantified hundreds of same-UID records where
  proxy control plus reported tunnel bytes exceeded Zeek, while Zeek equaled the
  reported tunnel fields exactly. Derive source-native proxy scopes from the
  canonical client-to-proxy transport: `control + tunnel = connection` and emit
  no tunnel ledger for terminal denial/auth outcomes. Owning layer: proxy action
  byte contract plus proxy projection; high leverage, medium risk.
- **P0 — Allocate Linux session IDs from persistent per-host session state.**
  Host found IDs tracking wall time at shared exact rates across nine hosts.
  Allocate only when PAM/logind sessions are created and preserve the same ID
  through close. Owning layer: SSH/session bundle and state manager; high
  leverage, medium risk.
- **P1 — Make hardware/daemon state durable per host.** Reused exact IRQ maps and
  oscillating fwupd ages are dataset-wide environmental fingerprints. Owning
  layer: host inventory and Linux ambient state; medium risk.
- **P1 — Replace bounded network timing draws with path-conditioned heavy-tailed
  timing.** TLS handshakes and sensor offsets expose hard ceilings/narrow bands.
  Owning layer: source timing and network observation planners; medium risk.
- **P1 — Complete remote execution contracts.** WMI target processes need a
  contemporaneous source caller plus RPC/DCOM or WinRM transport; source SSH
  clients should exist unless source-local observation coherently drops the
  lifecycle. Owning layer: remote-admin/SSH action bundles; medium-high risk.
- **P2 — Correct current source-native shapes.** Populate Event 1102 subject
  fields, omit unset ICMP JSON history, and diversify temp filenames by process
  family. Owning layers: Security occurrence context, network plan/Zeek JSON
  projection, and file-effect config; low-to-medium risk.

## Priority Rationale

The proxy byte ledger is selected for Loop 43 because it is the freshest
panel's most strongly quantified hard contradiction, spans three independent
sources, recurs hundreds of times, and has a bounded owning contract. Linux
session allocation is equally severe but touches a broader lifecycle/state
surface, so it follows after the lower-risk high-frequency byte correction.

## Comparison with Quantitative Eval

Automated checks passed parseability, causal ordering, event presence, field
agreement, and IDS integrity, but do not yet validate additive proxy byte scopes,
session-ID allocation rates, hardware individuality, or these timing shapes.
The only automated gate failure remained pivot linkability at 51.6129, which the
panel did not emphasize. Automated evaluation remains a regression guardrail,
not the target-selection objective.
