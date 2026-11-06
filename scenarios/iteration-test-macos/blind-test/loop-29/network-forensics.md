# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 64
**Synthetic-Confidence Score:** 18

## Executive Summary

The supplied network telemetry is production-like: transport accounting, protocol timing, TLS certificate relationships, and sampled endpoint SSH authentication agree without a demonstrated hard contradiction. I lean Real with moderate confidence; a capable synthetic system could reproduce these relationships, and this bounded log review has no packet capture with which to establish provenance.

## Evidence For Synthetic

- No important synthetic indicator was established by the checks below. In particular, differences between sensors were not treated as contradictions when visible packet-loss accounting explained them, and complete reference matching was not treated as a synthetic tell.
- Two SSH authentications in a deliberately limited endpoint sample lacked a matching supplied Zeek tuple: `APP-INT-01.meridianhcs.local/syslog.log:236` at `2026-11-02T18:56:14.486228Z`, source `10.10.1.35:63880`, and `DB-PROD-01.meridianhcs.local/syslog.log:179` at `18:10:15.623660Z`, source `10.10.1.42:52557`. These are unresolved coverage observations, not scored synthetic indicators: the supplied collection does not establish that every successful session must appear in Zeek.

## Evidence For Real

- Network errors have source-native consequences. `zeek-core/http.json:91` records a CONNECT request to `login.microsoftonline.com:443` returning `407`, with an 845-byte HTML response and a response file reference. Other examples include the `403` response at line 18 and `504` at line 48; successful CONNECT examples instead have zero HTTP response-body bytes while tunnel traffic is accounted separately in proxy logs.
- Different sensors exhibit explainable capture gaps rather than arbitrary disagreement. The same `10.10.2.40:55197 -> 10.10.3.20:8080` flow has 4,305 originator bytes in `zeek-core/conn.json:22` and 4,277 in `zeek-dmz/conn.json:9`; the latter explicitly records `missed_bytes:28` and history `ShADadfFG`.
- DNS includes successful, negative, empty-answer, reverse, and infrastructure queries. Core DNS has 203 NXDOMAIN and 16 SERVFAIL rows, as well as A, AAAA, PTR, SRV, TXT, NS, MX, and SOA queries. `zeek-core/dns.json:4` is a successful AAAA lookup with no address answer, rather than a fabricated IPv6 address for an IPv4-only name.
- Visible TLS certificate material is internally consistent. For example, the TLS 1.2 session in `zeek-dmz/ssl.json:4` references the certificate file in `zeek-dmz/files.json:1` and certificate in `zeek-dmz/x509.json:1`; the SHA-1 fingerprint, issuer, subject, SAN, and RSA authentication are compatible.
- Sampled SSH authentication follows transport opening. `zeek-core/conn.json:1105` opens `10.10.1.35:61718 -> 10.10.2.30:22` at epoch `1793626969.971494`; `APP-INT-01.meridianhcs.local/syslog.log:60` accepts the corresponding public key approximately 10.731 seconds later, within the 1,061.201128-second connection.

## Detailed Analysis

### Scope and method

I accessed only the supplied network briefing and files inside `/private/tmp/log-study-q6v4ix3p/data` for this assessment. No project files, implementation, scenario, prior assessment, or other project/prior context was accessed or consulted. The output report is separate from the supplied evidence. All line citations are one-based physical lines relative to the supplied data directory.

This was a bounded review with broad mechanical checks and representative manual inspection, not a packet-level audit or exhaustive endpoint review. I parsed all JSON rows in the three supplied Zeek sensor directories. Their connection counts are 11,497 core, 8,791 DMZ, and 453 DB: 20,741 sensor observations in total, including overlapping observations of some underlying connections. I also inspected examples from firewall, proxy, and Snort logs and sampled normalized endpoint FLOW records and SSH syslog on APP-INT-01 and DB-PROD-01. Counts across sensors are not counts of unique physical connections.

The visible connection start times span approximately `2026-11-02 13:00:06Z` through `18:59:39Z`. I treated missing pre-window initiators and post-window closure as neutral and did not infer a full-day activity pattern from six hours.

### Connections, packet accounting, and timing

All 20,741 connection rows passed elementary checks for payload bytes exceeding IP bytes, nonzero payload with zero packets, and TCP IP accounting below minimum IPv4/TCP header size. I found no overlapping same-direction TCP five-tuples within a sensor when comparing each flow's start and duration. These checks do not prove that every packet count is accurate; they exclude common mechanical impossibilities.

The connection-state distributions differ sensibly by observation path. Core has 9,325 SF and 1,871 S0 rows; DMZ has 5,742 SF and 2,836 S0; DB has 374 SF and no S0. DMZ `conn.json:1`, for example, records one inbound SYN, zero responder packets, history `S`, and S0 toward the web segment. That is consistent with an unanswered attempt. The raw state proportions should not be compared as independent random samples of the same traffic.

Successful SSH sessions are substantially longer than typical web transactions. Core's 73 SF port-22 connections have a median duration around 1,911 seconds, while its 1,770 SF port-8080 connections have a median around 2.087 seconds. DB's 229 SF port-3306 connections have a median around 2.915 seconds. Short connections and longer administration sessions coexist; the visible evidence does not require that every MySQL application use connection pooling.

A near-time, same-tuple comparison identified 4,825 cross-sensor pairs and 530 differences in state or basic byte/packet fields. I did not score this aggregate as a defect. The inspected examples carry explicit capture-gap accounting: in addition to the 28-byte example above, core `conn.json:239` and DMZ `conn.json:92` differ by 192 responder bytes, and the DMZ row records exactly 192 missed bytes with responder gap history. Small sensor timestamp differences can also reflect clock offsets or observation paths.

### DNS and protocol companions

The supplied logs contain 3,841 DNS, 4,065 HTTP, and 2,794 SSL rows. Every row in these three families referenced an existing local sensor connection UID with an identical endpoint tuple. No checked protocol timestamp preceded its connection by more than 1 ms or exceeded a positive recorded duration by more than 20 ms. DNS RTTs did not exceed corresponding connection durations by more than 2 ms. No HTTP request or response body exceeded the corresponding flow-direction payload byte count.

The first DMZ DNS row resolves `20-205-195-86.microsoft.com` to `23.72.51.162` at epoch `1793624490.729597`, with an 86.179-ms RTT. `zeek-dmz/ssl.json:1` subsequently records TLS to that address with the same SNI at epoch `1793624491.182604`. This example respects name-resolution timing. The spelling and public resolution of sanitized names were not used as authenticity evidence.

Infrastructure traffic is visible where the host roles support it: core has 2,500 `krb`, 1,056 `ldap`, and 60 DHCP-tagged connection rows; DB is dominated by 288 MySQL-tagged rows. HTTP method counts are strongly influenced by the explicit proxy: 1,716 of 1,913 core HTTP rows are CONNECT. Consequently, a naive HTTP-versus-HTTPS row ratio would mischaracterize browsing behavior.

### TLS, certificates, and transferred files

TLS 1.2 and 1.3 are both visible. Core has 171 TLS 1.3 and 129 TLS 1.2 rows; DMZ has 1,643 and 831; DB has 17 TLS 1.2 rows. Remaining SSL rows lack a version. I did not require encrypted TLS 1.3 certificates to be available to passive inspection.

For the 611 TLS 1.2 rows carrying certificate-chain references, I checked visible certificate existence, file-to-connection references, certificate validity interval, leaf SAN compatibility with SNI, and RSA/ECDSA authentication compatibility. No mismatch was found. For example, the AWS session in DMZ SSL line 4 uses `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` with an RSA leaf certificate, rather than an incompatible ECDSA leaf.

Across the supplied Zeek file logs, repeated SHA-256 values did not disagree on total bytes, seen bytes, or MIME type. Repeated X.509 fingerprints did not disagree on serial, subject, issuer, validity interval, or key length. File observation timestamps remained within their referenced flow intervals under the same timing tolerances. These are consistency findings, not proof of genuine certificate bytes or actual transferred content.

### Endpoint correlation and limitations

I compared 18 accepted SSH authentication lines on APP-INT-01 and DB-PROD-01 with supplied Zeek source tuples. Sixteen had matching transport observations; every matched authentication fell after transport opening and before its recorded end, on an SF flow. The two unmatched examples are identified above and remain neutral absent a comprehensive capture guarantee.

Windows workstation samples also use a different outbound source-port range from Linux server samples. All 217 sampled WS-MCHEN-01 outbound TCP FLOW rows use ports at or above 49,152, whereas 78 of 139 APP-INT-01 rows use lower ports. This supports platform awareness rather than a single indiscriminate source-port pool.

The review cannot validate original packet bytes, retransmission sequence numbers, TLS cryptographic authenticity, sensor configuration, NAT correctness across every firewall record, or the entire endpoint lifecycle. The verdict is therefore a moderate-confidence lean toward Real, while the low synthetic-confidence score describes the production-like visible network evidence.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| No supported high-impact indicator | Zeek connections, DNS, HTTP, SSL, files, X.509 | Broad mechanical checks plus representative inspection | No hard contradiction or demonstrated contract gap established |
| Unresolved coverage observation; not a scored indicator | SSH syslog versus Zeek | Two unmatched authentications in an 18-line sample | Neutral without a comprehensive capture guarantee |

## Realism Score by Category

- **Field format accuracy:** 9 — Source-native fields, counters, references, and checked certificate relationships are coherent; packet bytes were unavailable.
- **Temporal patterns:** 8 — Protocol evidence fits transport intervals and sampled SSH ordering; a six-hour window limits broader behavioral inference.
- **Cross-source correlation:** 9 — UID/tuple integrity and sampled capture-gap accounting are strong; two sampled SSH tuples remain unobserved in Zeek.
- **Behavioral realism:** 8 — Proxy errors, negative DNS, inbound failures, and different service-duration distributions are credible.
- **Environmental consistency:** 8 — Segment protocol roles and sampled platform-specific source ports are plausible; complete collection configuration is unknown.

## Recommendations

No corrective change is justified by a demonstrated network defect in this bounded review. If this were synthetic, I would preserve the visible protocol accounting, platform-specific ports, and coherent capture-gap behavior; I would not add arbitrary failures or force agreement between different sensor observations merely to change its apparent authenticity.
