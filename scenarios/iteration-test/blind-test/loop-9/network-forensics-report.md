# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 44

## Executive Summary

The network evidence is operationally coherent and has substantial production-like detail: realistic failed connection states, differentiated protocol timing, explicit proxy tunnels, DNS failures, and passive TLS visibility limitations. I found no demonstrated impossible network ordering or certificate/connection contradiction; the principal reason to retain uncertainty is a conspicuously similar, approximately flat bulk byte distribution across unrelated application protocols.

## Evidence For Synthetic

- [distribution_texture] Successful database and directory connections have very similar broad byte envelopes. In `zeek-db/conn.json`, the 244 `mysql`/`SF` rows have request-byte quartiles 1,460 / 2,626 / 3,808 and response-byte quartiles 12,356 / 23,474 / 37,832. In `zeek-core/conn.json`, the 1,009 `ldap`/`SF` rows have request quartiles 1,627 / 2,726 / 4,086 and response quartiles 10,077 / 24,478 / 37,770. Both response distributions spread their bulk nearly evenly across successive 5,000-byte bins through 50,000 bytes, despite different applications. This suggests a reusable broad sampling envelope, although an application-heavy collection could also create similarities.
- [weak_signal] The less common mail-configuration DNS activity is temporally concentrated across diverse hosts. Of 298 core TXT rows, 264 originate at `10.10.2.30`; the other 34 span 18 other source addresses, including database, proxy, directory, file-server, Windows-workstation and Mac-workstation addresses. Their first records appear around 17:41 UTC after more than four hours of this slice without TXT records; almost all occur through approximately 18:03. Examples include `10.10.1.31` querying `s1._domainkey.okta.com` at epoch `1793641272.780396` and `10.10.4.10` querying `mta._domainkey.sendgrid.net` at `1793641443.109856`. Coordinated diagnostics or software activity can explain this, so it carries little weight by itself.

## Evidence For Real

- Connection states are diverse and protocol-appropriate. Core has 9,877 `SF`, 1,632 `S0`, 456 `OTH`, 165 `RSTO`, 91 `RSTR`, 47 `REJ`, and smaller `S1`/`S2`/`S3` groups. DMZ has a materially larger unanswered population: 2,234 `S0` among 9,858 connections, consistent with its visible external probes.
- All 4,432 DNS, 5,320 HTTP and 3,582 SSL records across the three sensors reference an existing same-sensor connection with the same four-tuple. Application observations fall within their connection intervals under the tested 1 ms lower-bound / 100 ms upper-bound tolerances. This supports coherence; its completeness is not a synthetic indicator.
- TLS 1.3 rows correctly lack certificate-chain identifiers, rather than exposing certificates that a passive observer generally cannot read. TLS 1.2 has both full and resumed handshakes, with certificate files and intermediate chains where visible.
- DNS includes A, AAAA, PTR, SRV, TXT, NS, SOA and MX queries, along with NXDOMAIN, SERVFAIL and REFUSED responses. For example, core UID `CfpVLFu1WSHMaK3mRKH` is an unanswered-name lookup for `wpad`, while `CMCsdV50185chFPRRx` records SERVFAIL for `api-plqz5sjh.cloud`.
- Protocol lifetimes differ meaningfully: core Kerberos median duration is approximately 21 ms, SSH approximately 2,402 seconds, and RDP approximately 443 seconds. Internal SMB includes large transfers instead of treating all flows as small web requests.
- HTTP CONNECT transactions, internal proxy addresses, external proxy-origin TLS flows, and the proxy access log's separate control-message/tunnel accounting form a plausible explicit-proxy observation path.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory and this assessment's instructions. Primary coverage was every JSON row in `zeek-core`, `zeek-dmz`, and `zeek-db`, with spot inspection of normalized endpoint FLOW evidence, the proxy access log, ASA messages and IDS alerts. There were 22,625 sensor-local connection rows; a flow observed at multiple sensors is represented multiple times, so that number is not a count of unique physical conversations.

The visible connection starts span 2026-11-02 approximately 13:00–18:59 UTC. This is a daytime slice, not evidence about overnight volume, complete session initiation, or end-of-day shutdown. I did not use absent endpoint event types, absent products, sanitized domains, or completeness of matching as synthetic clues.

### Transport state, packet accounting and lifetimes

Core's protocol mix is 6,928 TCP, 4,957 UDP and 428 ICMP rows; DMZ has 8,389 TCP, 1,179 UDP and 290 ICMP; DB has 391 TCP, 48 UDP and 15 ICMP. The database sensor is dominated by 298 MySQL connections, while core sees 2,041 Kerberos and 1,226 LDAP connections. This is credible segmentation rather than a single identical source mix everywhere.

An external unsuccessful example is DMZ UID `Cm5g56l3KSEjLaCra7`, epoch `1793624404.068734`, `185.220.163.140:24444 -> 10.10.3.10:3306`: `S0`, history `S`, one originator packet, no responder packet, and zero application bytes. I found no successful TLS records attached to `S0`, `REJ`, or `OTH` connections, no TCP `SF` rows with fewer than three originator/two responder packets, and no application byte count exceeding its direction's IP byte count.

Large flows are present. Core UID `CRU4kpUSxtqCSeNgPv` begins at `1793624405.357006`, from `10.10.1.31:57767` to `10.10.2.20:445`, with 119,613,292 originator bytes over 5.921707 seconds, 87,066 originator packets and 40,964 responder packets. Its `missed_bytes=32768` and `history=ShADadfFG` provide an explicit gap indication. I did not misclassify logical sequence-byte versus observed-packet differences in gap-bearing rows as impossible packet accounting.

A successful RDP example, core UID `ChBnE9O795i4RzGUmg`, starts at `1793627645.797271`, `10.10.1.35:62741 -> 10.10.2.27:3389`, lasts 1,682.625969 seconds, and has 318,437 / 1,136,711 directional bytes. SSH sessions range into hours. These are sensible application-dependent scales.

The concern is the bulk of short successful service traffic. MySQL and LDAP response distributions have similar near-linear quartiles and similar request envelopes. The MySQL counts in 5,000-byte response bins from 0–49,999 are `24, 28, 24, 33, 18, 29, 16, 22, 29, 21`; LDAP's corresponding counts are `116, 134, 100, 72, 94, 107, 76, 97, 108, 87`, with some additional larger responses. Real query/result sizes can be broad, but application operations often leave stronger concentrations and differences between services. This is a distribution concern, not proof that any individual flow is impossible.

### DNS behavior

Core's 3,272 DNS rows contain 2,405 A, 309 AAAA, 298 TXT, 149 PTR, 98 SRV, five NS, four SOA and four MX queries. The response mix is 3,054 NOERROR, 205 NXDOMAIN, 11 SERVFAIL and two REFUSED. DB and DMZ contribute 41 and 1,119 additional DNS rows. TTLs include internal 300/1,800-second values, short 30-second answers, variable external-cache TTLs, and negative/no-answer responses without invented successful answers.

The first core row, UID `Cy7bKJVXGBLSw4N5M0b`, epoch `1793624402.649837`, is a UDP SRV query from `10.10.1.31` to `10.10.2.10` for `_ldap._tcp.meridianhcs.local`, answered with both domain controllers, TTL 300 and RTT 1.111 ms. Other records show slower external-resolution behavior and normal failure cases. I did not require every connection to have a new preceding query: cache reuse, literals, and pre-window resolution are legitimate.

The temporally concentrated DKIM/SPF/DMARC-like lookups across diverse client roles remain a weak concern. The much larger TXT population at `10.10.2.30` uses many changing labels, including names beneath `ns1.westbridge-services.cloud`; its volume alone is not an authenticity defect and can represent suspicious DNS activity. I separated that population from the cross-host mail-configuration queries when evaluating the smaller temporal cluster.

### HTTP and proxy visibility

Most core HTTP is proxy control traffic: 2,234 CONNECT among 2,516 rows. DMZ has 2,271 CONNECT among 2,778 HTTP rows. Calling this excessive cleartext browsing would be incorrect because these requests establish encrypted tunnels.

The first proxy log row records `10.10.1.33` making a successful CONNECT at 13:00:04 UTC, with explicit `byte_scope=connect-control-message`, `cs_bytes=425`, `wire_sc_bytes=211`, and separate `tunnel_cs_bytes=790`, `tunnel_sc_bytes=1400`, `tunnel_duration_ms=1403`. Core and DMZ observe the corresponding client-to-proxy tuple `10.10.1.33:62940 -> 10.10.3.20:8080`, while DMZ SSL UID `CJG62Yc5UVovA1p91` observes the separate external leg `10.10.3.20:35777 -> 23.45.84.162:443` with matching server name. Slightly different timestamps and different UIDs at different sensors are compatible with distinct observation points and clocks.

No individual HTTP request-body or response-body length exceeded the corresponding parent flow's directional application-byte total. File `seen_bytes` also fitted the available directional connection bytes in the checked references. Statuses include authentication challenges, denials, redirects, cached responses, partial content and gateway errors, rather than exclusively successful 200s.

### TLS and certificate consistency

DMZ has 2,167 TLS 1.3 and 922 TLS 1.2 records, plus one record without a negotiated version. Core has 210 TLS 1.3 and 264 TLS 1.2, plus one without a version. DB has 17 TLS 1.2 records. Cipher distributions include AES-GCM and ChaCha20 TLS 1.3 suites, ECDHE RSA/ECDSA AES-GCM, and a smaller TLS 1.2 CBC population, which is plausible in a mixed enterprise environment.

All 2,377 TLS 1.3 rows lack `cert_chain_fuids`. Full TLS 1.2 handshakes can have one or two certificate records, while resumption generally lacks a new chain. For example, DMZ UID `CXBtpuV2NdCjm2NgEk` at `1793624622.159734` uses `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` and links to leaf `FnntB8NZERExajtjd3`, an ECDSA-256 certificate for `upload.wikimedia.org`, plus an intermediate certificate. I checked linked leaf key types against RSA/ECDSA cipher authentication and found no mismatches. Linked certificates were valid at the observation times; identical fingerprints did not describe conflicting certificate metadata; issuer-plus-serial pairs did not identify multiple distinct fingerprints.

These checks materially reduce concern about naive synthetic TLS construction. They do not authenticate the underlying bytes because the supplied JSON is not packet capture or actual DER certificate content.

### Timing and cross-source checks

Across all three sensors, DNS/HTTP/SSL four-tuples match their parent UID's connection tuples. No application record preceded its connection start by more than 1 ms or exceeded its recorded interval by more than 100 ms. Median HTTP offset from connection start is about 93–99 ms across sensors; median SSL offset is about 103–118 ms, with nonzero variation and larger tails. These values are plausible application-observation offsets rather than demonstrated impossible causality.

Core hourly connection counts are `1742, 3177, 1680, 1760, 2104, 1850` for UTC hours 13 through 18. DMZ counts are `1561, 2770, 1319, 1347, 1337, 1524`. There is a real peak rather than uniform per-hour production. Six hours and overlapping sensor coverage are insufficient to establish a weekly work pattern or overnight infrastructure behavior.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Zeek connection byte/duration summaries | 244 successful DB-sensor MySQL flows and 1,009 successful core LDAP flows | Main concern: broad request envelopes and nearly flat 0–50 KB response populations are unusually similar across different services. Moderate evidence, with plausible workload alternatives. |
| weak_signal | Zeek DNS | 34 core TXT observations outside the dominant `10.10.2.30` population, spread across 18 source addresses | Small upward adjustment for the late, cross-role mail-DNS cluster; coordinated tooling can explain it. |

No hard contradiction or demonstrated schema error was established. Correct correlation and realistic protocol detail pull the score below the midpoint; the unresolved distribution concern prevents an affirmative Real assessment.

## Realism Score by Category

- **Field format accuracy:** 9 — Types, four-tuples, states, protocol histories, certificate references and directional byte bounds were coherent in the checks performed.
- **Temporal patterns:** 8 — Protocol-dependent lifetimes and varied hourly volume are credible; cross-host TXT activity has an unexplained late concentration.
- **Cross-source correlation:** 9 — Application UIDs, intervals, certificate links and explicit proxy legs agree without a demonstrated contradiction.
- **Behavioral realism:** 7 — Admin sessions, scans, DNS failures and large SMB transfers are plausible; bulk MySQL/LDAP byte distributions have a reusable-envelope texture.
- **Environmental consistency:** 8 — Sensor segmentation, enterprise authentication, proxy use and mixed TLS support fit together; the mail-DNS client-role spread remains a weak uncertainty.

## Recommendations

- If this were synthetic, derive MySQL and LDAP request/result sizes from service-specific operations and result cardinalities. Preserve their visibly different operational semantics instead of relying on similarly broad, near-flat byte envelopes.
- If this were synthetic, tie the cross-host mail-configuration TXT cluster to explicit application or diagnostic activity on the affected hosts, or distribute those lookups according to host roles and activity. The observed cluster may be legitimate, but its explanation should come from visible activity rather than an assumption about routine DNS.
- Preserve the current protocol-aware details: passive TLS 1.3 certificate limitations, resumption behavior, distinct proxy control/tunnel accounting, failed-state diversity, scoped sensor identifiers, and application-dependent long-lived sessions.
