# Network Forensics Analyst — Authenticity Assessment

## Verdict

- **Assessment:** Inconclusive
- **Verdict Confidence:** 68/100
- **Synthetic-Confidence Score:** 38/100

## Executive Summary

The Zeek slice looks production-plausible: it contains varied flow outcomes, failed DNS lookups, partial handshakes, resets, inbound scanning, and coherent DNS, TLS, and file-transfer records. I found no clear impossible ordering or packet-accounting contradiction. A small set of repeated, unanswered probes from `10.10.3.10` to `10.10.2.30` merits contextual review, but could represent monitoring or an unavailable backend.

## Evidence For Synthetic

- **[environment_or_collection_plausibility; weak]** In `zeek-dmz`, `10.10.3.10` sent 83 TCP probes to `10.10.2.30:8080` and 74 to `:443`; all were `S0` with no reply. The attempts span the six-hour slice and have irregular gaps, so they do not establish an impossible sequence. Their purpose is not apparent from these records.
- **[weak_signal]** A DNS `SERVFAIL` for `sync-c42tu37t.bit` appears among otherwise ordinary results. One unusual query is insufficient to distinguish a real beacon attempt from deliberately modeled activity.
- **No hard contradictions identified.** The observations above are weak contextual leads, not evidence that the network records are fabricated.

## Evidence For Real

- The three sensors show varied traffic outcomes. `zeek-core` has 10,265 `SF`, 1,674 `S0`, 448 `OTH`, plus resets, rejects, and incomplete TCP states; `zeek-dmz` also includes 2,181 `S0` flows and multiple completed and reset states. These patterns fit normal service traffic mixed with failed attempts and scanning.
- DNS includes ordinary successful answers as well as `NXDOMAIN`, `SERVFAIL`, and `REFUSED`. Of successful A queries, a later flow from the same client to a returned address appears within ten minutes for 1,445/2,189 core queries, 30/30 database-sensor queries, and 730/744 DMZ queries. Those joins are consistent, though the match rate itself is not evidence of authenticity.
- TLS records have plausible protocol diversity: core has 422 established connections across TLS 1.2 and 1.3; the DMZ has 2,822. All listed certificate-chain file IDs match X.509 records. Three DMZ certificates are self-issued; none was expired or not-yet-valid at the recorded timestamp.
- Flow accounting is internally plausible. `orig_ip_bytes` and `resp_ip_bytes` are never below their corresponding payload byte counts; the median IP-over-payload difference is about 28–54 bytes per packet depending on sensor and direction.
- Connection starts span roughly 13:00–19:00 UTC. Auxiliary DNS records align closely with connection starts, TLS records follow the connection start, and the checked DNS, TLS, and HTTP timestamps fall within their parent flow intervals.

## Detailed Analysis

The dataset contains 12,715 `zeek-core` connections, 498 `zeek-db` connections, and 9,518 `zeek-dmz` connections. All three cover approximately six hours on November 2, 2026. The largest durations are longer than the observed slice; that is compatible with long-lived flows crossing the window boundary and is not, by itself, an ordering defect.

Flow states and histories are broadly coherent. Missing `duration` fields occur on connectionless or incomplete states, primarily `S0`, `REJ`, and ICMP `OTH` records; completed TCP and DNS flows generally carry durations. UDP one-way requests appear as `S0` with `D` history, while answered DNS exchanges appear as `SF` with `Dd`.

DNS, TLS, HTTP, SMB, and SMTP records in the core sensor all join to connection UIDs. The same is true for DNS, TLS, HTTP, and file records in the database and DMZ sensors. These joins support a coherent record set but are not treated as synthetic evidence. Core, database, and DMZ X.509 references also resolve to their listed certificate records.

The DMZ shows a substantial amount of public-source probing against the externally visible `10.10.3.10`, including attempts on ports 80, 443, and common administrative or database ports. Multiple distinct public sources and varied target ports are consistent with background internet scanning. The records alone do not establish that any probe succeeded.

The clearest unresolved behavior is the repeated internal `S0` traffic from `10.10.3.10` to `10.10.2.30` on ports 8080 and 443. It could be health checking against an unavailable backend or another repeated connection attempt; these Zeek records do not identify its purpose. Other traffic supports ordinary service roles: high DNS and Kerberos volume in the core segment, MySQL traffic at the database sensor, and mixed public-facing web/TLS traffic at the DMZ sensor.

## Synthetic Indicator Summary

| Observation | Classification | Weight |
|---|---|---|
| Repeated unanswered probes from `10.10.3.10` to `10.10.2.30:8080` and `:443` | `environment_or_collection_plausibility` | Weak |
| Single unusual `.bit` query returning `SERVFAIL` | `weak_signal` | Very weak |
| Missing duration on incomplete or connectionless states | `weak_signal` | Not an anomaly on its own |
| DNS, TLS, HTTP, file, and certificate UID joins | `weak_signal` | Neutral; high coverage is not a synthetic clue |
| Impossible timing, impossible flow-state sequence, or negative wire-byte accounting | `hard_contradiction` | None found |
| Zeek schema or format defect | `schema_or_format` | None found |

## Realism Score by Category

- **Field format:** 9/10
- **Temporal patterns:** 9/10
- **Cross-source correlation:** 10/10
- **Behavioral realism:** 8/10
- **Environmental consistency:** 8/10

## Recommendations

No confirmed network-record correction is indicated. If `10.10.2.30` is expected to be a healthy backend during this slice, review the 157 unanswered probes from `10.10.3.10` to ports 8080 and 443 against the intended monitoring or service behavior.
