# Iteration Test Blind Assessment — Loop 75

## Outcome

Loop 75 made explicit-proxy CONNECT tunnel counters consume the authoritative carrying-client
transport byte ledger. The automated evaluation scored 96.5394 PASS across 117,110 records.
Initial blind synthetic-confidence scores were 68, 53, 82, and 94 (mean 74.25). Verdict
disagreement and a 41-point spread triggered deliberation; final scores were 76, 70, 86, and 94
(mean 81.50), with all four experts converging on Synthetic.

## Individual Expert Summaries

**Threat Hunter:** Synthetic, 86 verdict confidence, 68 synthetic-confidence. Strong environment
and attack-chain realism were offset by successful Samba `opendir` operations against document
paths, one process-owned flow after termination, remote-service authentication/transport gaps, and
repeated Linux shell commands.

**Detection Engineer:** Initially Inconclusive, 80 verdict confidence, 53 synthetic-confidence.
The strongest issues were the same post-termination process-owned OCSP flow, missing authoritative
4776 events for 69 of 80 successful domain NTLM logons, and narrow fleet-wide Linux background
texture. Windows, Sysmon, Zeek, ASA, IDS, and source-native correlation otherwise held up well.

**Network Forensics:** Synthetic, 92 verdict confidence, 82 synthetic-confidence. Exact 0.600-second
HTTP asset spacing, a broad 1.200-second TLS duration mode, stateless UDP syslog source ports and
multi-packet flows without duration, and a missing public-DNS CNAME long tail drove the score.

**Host/EDR Forensics:** Synthetic, 97 verdict confidence, 94 synthetic-confidence. Post-date Zoom,
Webex, and Postman metadata in a March 2024 window was decisive. A 1.848-millisecond workstation
lock/unlock pair, the post-termination process flow, and fixed-profile Linux daemon noise reinforced
the verdict.

## Deliberation

Direct review confirmed the LOG-MON-01 Java process terminated before both its attributed eCAR
flow and the independently observed Zeek TCP/HTTP activity. The panel also treated the repeated
software chronology conflicts and cross-population HTTP/TLS timing modes as strong independent
evidence. Final synthetic-confidence scores were Threat Hunter 76, Detection Engineer 70, Network
Forensics 86, and Host/EDR 94; all four final verdicts were Synthetic.

## Fix Verification

- 458 successful CONNECT rows produced 455 exact client-transport joins; three lacked a retained
  transport under the configured observation profile.
- All joined rows had zero gross directional byte mismatch. Every one of the 52 residual
  proxy-versus-Zeek differences was covered by reported sensor `missed_bytes`; zero-loss rows had
  zero mismatches.
- Behavior revision 39 records surface digest
  `ccf193ccfc507846ebf4044d8b0af7a6e3b8116add68bb3a4549f20303987776`.
- The routine gate passed 8,409 tests with 5 skips and 2,009 deselections; focused proxy tests and
  Ruff checks passed.
- The loop-74 gross proxy/Zeek byte-accounting contradiction did not recur in any initial expert
  report.

## Prioritized Improvements

### P0 — Enforce process ownership through final dependent activity

Validate every process-attributed flow and application dependency after source timing is applied.
Keep the owning process alive through OCSP and related network close, or assign the activity to the
actual surviving process.

### P0 — Make software metadata scenario-date aware

Attach validity windows to application versions, product names, modules, and hashes. Reject binary
metadata that post-dates the scenario window and test date-bound product-name transitions.

### P1 — Replace HTTP and TLS timing constants with causal timing

Model browser waterfalls, parallelism, RTT, object-size-dependent completion, reuse, and think time.
Derive TLS close time from handshake, transfer, FIN/reset, and idle-timeout behavior.

### P1 — Give UDP syslog a persistent sender lifecycle

Reuse host/process sockets across messages, preserve source ports across sensor idle splits, and
emit nonzero duration when a Zeek pseudo-connection aggregates multiple datagrams.

### P1 — Correct source-semantic host lifecycles

Reserve Samba `opendir` for directories, enforce a human-scale lock interval with a companion Type
7 unlock, and make domain NTLM/Type 9 authentication companions coherent with visible audit policy.

### P1 — Drive Linux background evidence from host state

Vary installed and active daemons by role, emit messages from actual transitions and work, reduce
fixed bundle counts, and broaden host-specific long-tail vocabulary.

## Comparison with Quantitative Eval

The deterministic evaluator scored 96.5394: 99.9991 parseability, 96.9336 plausibility, 94.6556
causality, and 93.2120 timing. It did not flag the post-termination process ownership, post-date
software metadata, timing modes, UDP syslog lifecycle, Samba operation semantics, or fleet-wide
Linux texture identified by the blind panel.
