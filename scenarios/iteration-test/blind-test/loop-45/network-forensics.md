# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 80
**Synthetic-Confidence Score:** 65

## Executive Summary

The network evidence is operationally convincing: transport state, protocol references, flow byte budgets, proxy behavior, and TLS visibility generally agree. I nevertheless favor synthetic because two recurrent source-native formatting problems occur across many records: DNS answers use zone-style values where Zeek logs different summaries, and SMB tree mappings put share names in the resource-type field. These are concrete rendering defects, rather than judgments about intrusion narrative or collection completeness; undocumented postprocessing of genuine logs remains an alternative explanation.

## Evidence For Synthetic

- [schema_or_format] **DNS answer serialization repeatedly differs from Zeek's native summaries.** `zeek-core/dns.json:1`, timestamp `1793624402.898315`, logs SRV answers `0 100 389 DC-01.meridianhcs.local` and `0 100 389 DC-02.meridianhcs.local`. Native Zeek logs the SRV target, without the priority/weight/port prefix. The same form occurs in all 120 answered SRV records across the three sensors. `zeek-core/dns.json:107` similarly includes MX preference in `10 mail.meridianhcs.local`; line 1433 includes the entire SOA textual tuple. Native Zeek's handlers summarize those as the MX hostname and SOA primary name, respectively. [Zeek DNS handlers](https://raw.githubusercontent.com/zeek/zeek/master/scripts/base/protocols/dns/main.zeek)
- [schema_or_format] **Answered TXT records omit Zeek's native TXT string encoding.** For example, `zeek-core/dns.json:2225` has `answers=["v=spf1 include:sendgrid.net -all"]`, and `zeek-dmz/dns.json:807` has a raw DMARC string. Native Zeek prefixes each TXT character-string with `TXT` and its length. There are 278 answered TXT rows in core, three in DB, and three in DMZ; this pattern is another manifestation of the DNS rendering issue, not 284 independent flaws. [Zeek DNS TXT handler](https://raw.githubusercontent.com/zeek/zeek/master/scripts/base/protocols/dns/main.zeek)
- [schema_or_format] **SMB tree `service` is systematically a share name.** In `zeek-core/smb_mapping.json:1`, UID `CmGYGsC9BRYehJ6NSdy`, `path` identifies `FILE-SRV-01`'s `ClinicalExports` share and `service="ClinicalExports"`; line 2 uses `service="SYSVOL"`, line 4 `service="NETLOGON"`. All 132 mappings put the final path component in `service`. Zeek defines this field as resource type, rather than share name; its SMB1 handler takes the protocol service string, while its SMB2 handler sets `share_type` without manufacturing `service` from the path. The records also carry a separate `share_type="DISK"`. [Zeek field definition](https://docs.zeek.org/en/v8.0.11/scripts/base/protocols/smb/main.zeek.html), [SMB1 implementation](https://raw.githubusercontent.com/zeek/zeek/master/scripts/base/protocols/smb/smb1-main.zeek), [SMB2 implementation](https://raw.githubusercontent.com/zeek/zeek/master/scripts/base/protocols/smb/smb2-main.zeek)

## Evidence For Real

- The transport mix includes successes, SYN-only attempts, rejections, resets, partial closes, and midstream observations. For example, `zeek-dmz/conn.json:639` has a rejected TCP/443 attempt with `history="Sr"`, one packet each way, and zero payload; `zeek-core/conn.json:211` has `S3` with responder FIN in `ShADadf`. Those combinations are internally sensible.
- DNS is not restricted to successful A lookups. Core includes A, AAAA, PTR, SRV, TXT, MX, NS, and SOA questions, with 227 NXDOMAIN, 14 SERVFAIL, and four REFUSED responses. `zeek-core/dns.json:19` is an NXDOMAIN with no invented answer; line 26 is an internal AAAA NOERROR response without an AAAA answer, which is legitimate NODATA behavior.
- TLS 1.3 does not expose certificate chains in the supplied SSL records. For example, `zeek-dmz/ssl.json:1` reports TLS 1.3/AES-256-GCM with no certificate chain; the TLS 1.2 record in `zeek-core/ssl.json:1` has chain FUIDs resolving to certificate records. Passive TLS 1.3 certificate invisibility is consistent with the protocol. [Zeek TLS discussion](https://docs.zeek.org/en/current/reference/logs/ssl.html)
- Proxy evidence distinguishes CONNECT control traffic from inspected application traffic. `PROXY-01.meridianhcs.local/proxy_access.log:1-2` shares tunnel ID `PT-a5e41cdf86225d43` and client source port `40446` across a CONNECT and an inspected HTTPS GET; the CONNECT reports `byte_scope=connect-control-message` separately from tunnel byte totals. `zeek-core/http.json:1` observes the matching client-to-proxy CONNECT tuple.
- Long-lived remote administration is represented separately from short web/database transactions. `zeek-core/conn.json:96` records an SSH session lasting `3384.936579` seconds; the DB sensor's MySQL median duration is about 2.27 seconds, and the core RDP median is about 1153 seconds. No rule requiring sessions to begin or end outside the supplied window was imposed.

## Detailed Analysis

### Provenance, scope, and method

I opened the supplied `network-prompt.md`, enumerated only the supplied `data` directory, and examined the copied raw evidence there. I did not open repository files, scenario files, previous reports, other reviewers' reports, or parent-directory inventories. Public Zeek documentation and upstream Zeek source were consulted to resolve native field semantics. The underlying production-versus-synthetic origin was not provided as an observed fact; the assessment above is an inference from the logs.

The three connection files cover approximately **2026-11-02 13:00–19:00 UTC**. I parsed every JSON record in the Zeek source family, inspecting samples and computing whole-file consistency checks. Principal counts are:

| Sensor | Connections | DNS | HTTP | SSL | Files |
|---|---:|---:|---:|---:|---:|
| zeek-core | 12,314 | 3,188 | 2,159 | 403 | 678 |
| zeek-db | 433 | 50 | 20 | 14 | 21 |
| zeek-dmz | 9,401 | 1,075 | 2,431 | 2,725 | 1,686 |

I also examined core SMB mappings/files, SMTP and DHCP, certificate records, and representative proxy, firewall, IDS, and endpoint records. The review is principally a network assessment, not an exhaustive endpoint audit. Sensor observations can duplicate traffic, so these counts and byte sums must not be interpreted as unique enterprise-wide traffic.

### Transport states and accounting

Core connection states are 10,053 SF, 1,897 S0, 150 RSTO, 116 RSTR, 29 OTH, 28 REJ, 16 S2, 15 S3, and 10 S1. DMZ has 6,516 SF, 2,606 S0, 129 RSTO, 70 RSTR, 32 REJ, 19 OTH, 12 S2, 10 S3, and seven S1. The relatively high S0 share is not itself implausible given visible rejected/blocked traffic; for example, the initial DMZ SYN to `10.10.2.21:443` in `zeek-dmz/conn.json:1` is also denied in `fw-perimeter/cisco_asa.log:1`.

For all **22,148 connection records**, neither direction's payload count exceeds its IP-byte count, and no positive payload is assigned to a zero-packet direction. These are useful sanity checks, though not packet-level proof. I also compared HTTP request/response body lengths, and conservative minimum HTTP status/request-line sizes, against the containing flow's corresponding byte count; no over-budget case was found. HTTP 304 rows have zero response body length.

The partial-close examples are coherent: `zeek-db/conn.json:21` and `zeek-dmz/conn.json:189` describe the same MySQL tuple with `S2`/originator FIN, identical payload counts, and slightly different sensor timestamps/durations. Separate sensor UIDs are expected. Timestamp offsets between independent sensors were not treated as impossible ordering without a demonstrated clock model.

### DNS behavior and native rendering

Core question types are 2,333 A, 279 AAAA, 154 PTR, 105 SRV, 300 TXT, eight MX, six NS, and three SOA. DMZ has 891 A, 113 AAAA, 58 PTR, ten SRV, and three TXT. Responses include NXDOMAIN and transient failures, and authoritative internal versus recursive external flags are generally plausible. I did not validate sanitized names against live DNS.

The important defect is how some answers are rendered, not whether those DNS records could exist on the wire. Native Zeek's SRV, MX, and SOA handlers deliberately log selected names. The dataset instead writes the familiar full zone-style presentation for each of those types. Native TXT rendering is also distinctive and missing here. Counts of affected answered records are 120 SRV, eight MX, three SOA, and 284 TXT, totaling **415 sensor rows**. Some sensors observe the same underlying transactions, so this is a row count, not a unique transaction count. These defects are judged together as one recurring DNS renderer problem.

A normalizer could rewrite these fields, and that would weaken origin attribution. No manifest explaining such a transformation was supplied among the evidence I examined. I therefore assess the mismatch as evidence for synthetic rendering, while retaining meaningful uncertainty.

### TLS and certificates

The SSL records contain 2,007 TLS 1.3, 1,128 TLS 1.2, and seven unspecified-version observations. The DMZ is more TLS-1.3-heavy than internal traffic: 1,808 of 2,725 SSL rows versus core's 199 of 403 and DB's zero of 14. This is plausible for externally facing web/cloud traffic versus internal services.

All supplied TLS 1.3 SSL rows lack `cert_chain_fuids`; I did not penalize this loss of passive visibility. Referenced TLS chain FUIDs resolve within each sensor's X.509 records. Repeated certificate fingerprints do not disagree on their certificate attributes in the examined fields. Where an ECDSA-authenticated TLS 1.2 cipher has a visible certificate, its key type agrees. These findings support internal consistency without making complete matching an authenticity penalty.

### Protocol timing, ownership, and visibility

I joined DNS, HTTP, SSL, SMB mappings/files, and SMTP to their containing connections by sensor-local UID. Across the supplied protocol rows there were no missing connection UIDs or conflicting four-tuples. No tested protocol timestamp preceded its connection by more than 10 ms, or exceeded the connection's stated duration by more than 100 ms. The same boundary checks on file observations found no exceptions. Those tolerances are stated to avoid claiming precision that this inspection did not establish.

Proxy CONNECT traffic dominates HTTP: core has 1,967 CONNECT requests out of 2,159 HTTP rows, while DMZ has 2,013 out of 2,431. This makes a naive HTTP-versus-SSL ratio misleading; CONNECT is a proxy transport setup observation, not necessarily a plaintext website visit. Likewise, the proxy's inspected GET entries do not establish that an unrelated passive sensor should see decrypted HTTP. The supplied evidence does not require that inference.

### Traffic timing and environment

Core hourly connection counts for 13–18 UTC are 1,849, 3,233, 1,757, 1,698, 2,068, and 1,709. Corresponding DMZ counts are 1,315, 2,713, 1,359, 1,465, 1,295, and 1,254. The shared 14 UTC peak is consistent with activity traversing more than one observation point. It is neither an impossible pattern nor evidence of a uniform schedule. A six-hour slice does not permit a meaningful judgment about overnight activity, weekend suppression, or full-day business-hour shape.

Sensitive-port traffic includes short and long sessions rather than one duration class. I found no demonstrated impossible visible same-session ordering in the network checks. The verdict is driven by the repeated DNS and SMB field semantics, not by missing out-of-window initiators or termination records, absence of additional collectors, or how readily suspicious activity can be narrated.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the score |
|---|---|---|---|
| schema_or_format | Zeek DNS | 415 answered sensor rows across SRV, MX, SOA, TXT and three sensors | Repeated values follow generic DNS presentation rather than native Zeek handler output; one coherent rendering defect with several manifestations. |
| schema_or_format | Zeek SMB mappings | All 132 core mappings | `service` duplicates the share name rather than describing the resource type; field meaning is systematically replaced. |

No hard temporal contradiction was established. The score is therefore near the lower end of “likely synthetic,” rather than the 81–100 band. A documented transformation pipeline could explain the schema issues while preserving a real underlying capture.

## Realism Score by Category

- **Field format accuracy:** 6 — Conn/TLS/HTTP fields are convincing, but DNS answer summaries and SMB `service` meaning are recurrent native-format defects.
- **Temporal patterns:** 9 — Diverse durations and hourly variation; tested protocol/file observations stay within their containing transport intervals.
- **Cross-source correlation:** 9 — Sensor-local UIDs, tuples, byte budgets, proxy joins, and sampled firewall evidence agree; complete alignment is not penalized.
- **Behavioral realism:** 8 — Plausible proxy-dominated browsing, infrastructure DNS, failed connections, and long remote-admin sessions within a limited observation window.
- **Environmental consistency:** 9 — Internal versus DMZ protocol/TLS differences are coherent; no demonstrated impossible role or visibility assignment in the reviewed network records.

## Recommendations

- If this were synthetic, render DNS answers according to the targeted Zeek version's actual per-RR handlers: SRV target, MX exchange name, SOA primary name, and TXT string length encoding. Keep the full DNS semantic content separately when useful.
- If this were synthetic, populate SMB `service` with native protocol resource-type semantics when observable, or omit the optional field where native Zeek would; retain the share name in `path` and the share type in `share_type`.
- If the records originate from real captures with deliberate field normalization, document those transformations and the Zeek version. That would let reviewers distinguish collection/postprocessing artifacts from authenticity defects without changing the underlying traffic.
