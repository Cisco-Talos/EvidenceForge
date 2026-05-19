# Loop 132 Blind Realism Report

## Score Summary

| Loop | Automated eval | Records | Threat hunter synthetic-confidence score | Detection synthetic-confidence score | Network synthetic-confidence score | Host/EDR synthetic-confidence score | Average synthetic-confidence score |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 128 | 96.2731 | 80,718 | 78 | 64 | 78 | 76 | 74.00 |
| 129 | 96.3773 | 78,080 | 68 | 67 | 72 | 72 | 69.75 |
| 130 | 96.4166 | 74,738 | 64 | 72 | 62 | 42 | 60.00 |
| 131 | 96.4166 | 74,738 | 64 | 78 | 82 | 76 | 75.00 |
| 132 | 95.5271 | 80,353 | 76 | 82 | 76 | 68 | 75.50 |

Loop 132 fixed the concrete Kerberos source-port and eCAR process-reference ordering findings from Loop 131, but blind review stayed high because reviewers shifted to Linux daemon field realism, reusable human/admin behavior, web/TLS distribution, and endpoint lifecycle texture. The quantitative score fell mainly from distribution/timing pressure, while hard probes confirmed the targeted Loop 132 fixes landed.

## Individual Expert Summaries

Threat Hunter: Verdict synthetic, confidence 76. The attack path was coherent and huntable across Windows, Zeek, ECAR, and bash history, but repeated bash command pools, repeated typo artifacts, cross-role devops commands, and a tidy attack vocabulary made the background behavior feel generated.

Detection Engineer: Verdict synthetic, confidence 82. Windows, Sysmon, Zeek, proxy, firewall, and ECAR schemas were mostly strong, but Linux syslog carried operationally implausible values: six-digit rsyslog file descriptors, random six-digit polkit `unix-session` identifiers, repeated bus names, and ECAR ICMP flows using `"0"` port strings.

Network Forensics: Verdict synthetic, confidence 76. Zeek field structure, UID linkage, DNS-to-connection sequencing, proxy behavior, and x509 linkage were good, but public EHR traffic, sparse branded health checks, TLS resumption, suspicious DNS red herrings, and compact scan sequences felt curated.

Host/EDR Forensics: Verdict synthetic, confidence 68. The host attack chain and cross-source process/flow correlation were strong, but long-lived short-task utilities, unstable ECAR principal enrichment for the same actor, templated bash histories, session logout type mismatch, and Let's Encrypt R3 validity concerns lowered authenticity.

## Prioritized Improvements

| Priority | Issue title | Reviewer original rating(s) | Score impact | Description |
| --- | --- | --- | --- | --- |
| P0 | Linux daemon runtime identifiers are impossible-looking | not labeled | High | Detection flagged six-digit rsyslog file descriptors, random polkit `unix-session` IDs not tied to logind sessions, and reused bus names. This is a concrete source-native field-value problem and should be fixed with per-daemon state for file descriptors, bus names, and session linkage. |
| P1 | Reusable human/admin command and typo pools | not labeled | High | Threat Hunter, Host/EDR, and Detection all flagged repeated bash commands, typo tokens, and cross-role devops/admin vocabulary. The owning layer is activity profile/data config: command pools need per-persona and per-role habits, host-appropriate remote targets, and user-specific typo behavior. |
| P1 | Endpoint process lifetimes look closed by generator | not labeled | High | Host/EDR found multi-hour lifetimes for short-task utilities such as Defender signature updates, TiWorker, dllhost, conhost, wsqmcons, and WmiPrvSE, often terminating near the end of the window. Process lifetime modeling should be executable-family aware, with incomplete observation allowed where realistic. |
| P1 | Public web and health-check distributions are too curated | not labeled | Medium-high | Network found sparse ELB health checks, many single-request public visitors, repeated exact response sizes, and limited web-session depth. The web baseline should produce sustained health-check cadence with jitter, repeat-client sessions, cache/referrer/header variance, and less uniform asset sizing. |
| P1 | TLS/x509 client and certificate texture remains narrow | not labeled | Medium-high | Network flagged overuse of TLS resumption for one-off public clients, while Host/EDR questioned the R3 intermediate validity profile. Fix ownership spans TLS activity profiles and x509 config/loader validation. |
| P2 | ECAR protocol/session enrichment weak spots | not labeled | Medium | Detection flagged ICMP flows represented with `"0"` port strings; Host/EDR flagged same actor/process flows alternating principal enrichment and logout records with mismatched session type. ECAR rendering should omit non-applicable port fields or model ICMP type/code, and session/principal enrichment should be stable per actor/session. |
| P2 | Suspicious DNS and scan red herrings feel staged | not labeled | Medium | Network found random `.top` domains resolving cleanly to CDN/provider IPs without follow-on flows, plus a compact scan burst with tidy outcomes. Red-herring generation should include NXDOMAIN/timeouts, resolver paths, uneven retries, and less scripted scan cadence. |
| P2 | Remaining hard-probe network/source-native issues | hard probe | Medium | Automated probes still sampled Zeek DMZ MTU-aware packet-accounting violations and malformed SOA answer payloads. These are concrete source-native corrections for future loops, separate from the fixed Kerberos/eCAR ordering issues. |
| P3 | Bare `tail -N` process commands remain | hard probe | Low-medium | Hard probes still found 30 bare stdin-oriented `tail -N` ECAR process command lines. This is lower leverage than daemon IDs and command-pool diversity but still visible endpoint texture. |

## Fixed And Verified In Loop 132

- Kerberos DC audit `IpPort` now correlates with matching TCP/88 flow source ports where visible: hard probes found `0` mismatches and `1,573` exact source-port matches.
- ECAR process-owned dependent records are no longer emitted before visible process creates: hard probes found `0` object-reference and `0` PID-only reference-before-create inversions.
- Verification passed before regeneration: focused Kerberos/eCAR/system traffic tests, `uv run eforge validate-config`, Ruff checks/format checks, and full normal `uv run pytest --no-cov -q` (`3364 passed, 15 skipped`).

## Comparison With Quantitative Eval

Automated eval passed at `95.5271/100` across `80,353` records with Parseability `100.0`, Plausibility `95.7900`, Causality `92.7658`, and Timing `91.9406`. Eval caught broad distribution/timing pressure and hard probes caught concrete Kerberos, ECAR, MTU, SOA, and bare-tail issues; blind reviewers surfaced source-native Linux daemon values, endpoint lifecycle modeling, behavior-pool reuse, and public web/TLS texture that are not yet covered strongly enough by automated scoring.

## Recommendations

Target Linux daemon state first because it is a crisp source-native contradiction and the detection reviewer gave the highest synthetic-confidence score. Then address reusable command/typo pools and short-task process lifetime modeling because multiple reviewers independently cited them and they shape the dataset-wide texture. Network follow-ups for public EHR/web health checks, TLS resumption, suspicious DNS realism, SOA completeness, and MTU-aware packet accounting remain good next-loop candidates.
