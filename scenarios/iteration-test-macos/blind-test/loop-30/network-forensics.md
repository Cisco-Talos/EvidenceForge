# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 88
**Synthetic-Confidence Score:** 65

## Executive Summary

The network data is broadly coherent, including realistic sensor segmentation, proxy tunnels, DNS variety, negotiated TLS, and long-lived administration sessions. My synthetic verdict rests on a localized but reproducible transport-accounting contradiction: several fully observed DNS-over-TCP exchanges have byte totals too small to contain their decoded DNS messages and mandatory TCP DNS length prefixes. This outweighs the otherwise strong network realism, but does not justify treating the entire dataset as implausible.

## Evidence For Synthetic

- [hard_contradiction] DNS-over-TCP request and response lengths are undercounted in otherwise complete flows. At `zeek-core/dns.json:246`, UID `CcD9Et1R7mhxctnEo` decodes an A query for `DC-01.meridianhcs.local` and answer `10.10.2.10`; `zeek-core/conn.json:838` reports TCP, `SF`, `missed_bytes=0`, `orig_bytes=41`, and `resp_bytes=57`. An ordinary DNS query containing that 23-character name requires 41 DNS message bytes plus the two-byte DNS-over-TCP length prefix, or 43 TCP payload bytes. A minimally compressed one-A-answer response requires 57 message bytes plus the prefix, or 59 TCP payload bytes. Both directions are short by exactly two bytes.
- [hard_contradiction] The same defect recurs independently in time and identity. `zeek-core/dns.json:1935` / `conn.json:8719`, UID `Cn2nb0PCrh2RKgsPFY`, repeat the complete `41/57` TCP exchange at 17:25:00 UTC. `dns.json:1181` / `conn.json:5788`, UID `C5labejzMnyBLD3oNI`, have a 41-byte TCP query at 15:44:39 UTC, again with `missed_bytes=0`. `dns.json:234` / `conn.json:753`, UID `CCqRNTsA1cwTYcGMfi`, have a 57-byte successful A-answer response at 13:28:41 UTC with no missed bytes. This is a repeated protocol-specific accounting pattern, not an isolated unusual connection.

## Evidence For Real

- All examined DNS, HTTP, SSL, SMB-file, and SMTP rows join to a connection in the same sensor by UID, have matching originator/responder addresses and ports, and have timestamps inside their connection intervals. This supports coherent evidence construction; completeness itself is neutral for authenticity.
- Protocol and role distributions vary meaningfully by sensor. `zeek-db/conn.json` has 288 MySQL-labeled connections out of 453, while `zeek-dmz/conn.json` is dominated by TLS, HTTP/proxy, DNS, and scan traffic. Core includes substantial Kerberos, LDAP, SMB, and infrastructure traffic.
- DNS contains A, AAAA, PTR, SRV, TXT, MX, NS, and SOA records, together with NXDOMAIN and SERVFAIL. Internal authoritative A records have stable TTLs: for example, the 351 `DC-02.meridianhcs.local` A answers from `10.10.2.11` in core all have TTL 300. External responses show more variable TTLs and latencies.
- TLS versions and cipher families are internally plausible. TLS 1.3 uses its corresponding AES-GCM/ChaCha20 suites; TLS 1.2 includes RSA and ECDSA suites, resumption, and observable certificate chains. Repeated certificate fingerprints retain identical certificate metadata, hashes, and file lengths across the supplied sensors.
- SSH and RDP have a long duration tail. Core SSH durations span approximately 0.254–13,302.802 seconds, with a median of 1,898.501 seconds; RDP spans 2.105–3,402.524 seconds. These differ appropriately from most DNS and web transactions.
- DHCP renewals use consistent identities and lease durations with nonidentical renewal timing. For example, `zeek-core/dhcp.json:1,12,21,34,42,52` consistently associate MAC `d4:be:d9:a1:ac:76` with a 7,200-second lease and roughly hourly REQUEST/ACK exchanges.

## Detailed Analysis

### Scope and method

I parsed the supplied JSON records directly and examined 20,741 connection observations across `zeek-core`, `zeek-dmz`, and `zeek-db`, plus their protocol, file, and certificate companions. These are observations from different sensors, not necessarily unique real-world connections. The connection window is approximately 2026-11-02 13:00–19:00 UTC. All cited line numbers are one-based physical lines in the supplied files, relative to the data directory.

I checked UID and tuple joins, protocol timestamps against transport intervals, duplicate overlapping TCP four-tuples within a sensor, transport payload/IP-byte lower bounds, minimum DNS and HTTP message sizes, certificate fingerprint consistency, and file hashes/lengths. I also sampled proxy, firewall, and IDS records. I did not inspect project material or infer origin from filesystem metadata.

### DNS-over-TCP byte accounting

The strongest evidence is precise enough to reproduce without an assumed organizational baseline. For `DC-01.meridianhcs.local`, the DNS wire-format question name is 25 bytes: one length byte for each of three labels, the label contents, and the terminating zero. Adding the 12-byte DNS header and four bytes for QTYPE/QCLASS gives a 41-byte DNS message. DNS-over-TCP adds a two-byte message-length field, making 43 transport payload bytes before any optional additions.

For the successful A response in `dns.json:246`, allowing maximal ordinary answer-name compression, the question/header remain 41 bytes and the resource record needs 16 bytes: two-byte compressed owner name, ten bytes for type/class/TTL/RDLENGTH, and four bytes for the IPv4 address. That is 57 DNS bytes and 59 TCP payload bytes. The joined connection reports precisely the bare DNS lengths, `41/57`, while its complete handshake/FIN history is `ShADadfF` and capture loss is zero.

The three zero-gap underlength queries are at DNS lines 246, 1181, and 1935. Five zero-gap underlength successful A responses are at DNS lines 234, 246, 409, 1116, and 1935, joining connection lines 753, 838, 1415, 5539, and 8719. Together these involve six of the eleven TCP DNS transactions. Additional small totals occur in flows with nonzero `missed_bytes`; I exclude those from the decisive evidence because capture loss introduces ambiguity.

A responder could omit the question section in an unusual DNS response, so the response-only minimum is conditional on ordinary echoed-question behavior. The request-side failures remain decisive: the first question of these newly established, fully observed connections cannot acquire a two-byte transport length field without consuming transport payload. The exact recurrence of the bare 41-byte DNS length further supports a systematic accounting issue.

### Connection states, traffic mix, and timing

Core reports 9,325 SF and 1,871 S0 observations; DMZ reports 5,742 SF and 2,836 S0. Core also has 128 RSTO, 86 RSTR, 23 REJ, and smaller populations of partial and midstream states. The DMZ S0 population includes visible scan-like external attempts, so the failure volume is not independently implausible. The first DMZ connection, for example, is an unanswered external SYN to `10.10.3.10:8080`; the firewall logs a matching SYN timeout.

Connection counts fluctuate by hour. Core hourly counts are 1,428, 3,087, 1,709, 1,776, 1,822, and 1,675 from 13 through 18 UTC, rather than following a flat schedule. This six-hour daytime sample cannot establish overnight, weekend, or full business-day behavior; I make no penalty for those unavailable periods.

No overlapping same-direction TCP four-tuple intervals were found within an individual sensor. Protocol rows did not precede their transport starts or exceed the recorded transport end. Packet/IP-byte lower-bound checks found no general payload-versus-IP accounting deficit. Thus the DNS framing defect is not evidence of pervasive arbitrary connection construction.

### HTTP, proxy, TLS, and certificates

Most HTTP observations are CONNECT requests to the explicit proxy, rather than cleartext origin-server browsing. Core has 1,598 successful CONNECT transactions plus 403/407/502/503/504 outcomes; DMZ has 1,657 successful CONNECT transactions plus failures and direct HTTP traffic. Counting these as a large cleartext HTTP browsing share would misinterpret the observation path.

For example, core HTTP line 1 shows `10.10.1.42` connecting to proxy `10.10.3.20:8080` with an HTTPS CONNECT authority. The proxy log supplies separate control-message and tunnel byte counters. DMZ TLS observations then include external TLS from the proxy. This is a plausible deployment pattern and avoids falsely expecting endpoint-to-origin direct TLS for every browsing transaction.

TLS certificate evidence is also substantially consistent. DMZ SSL line 4, UID `CZTmnt1aIZnP0mPYG3r`, negotiates TLS 1.2 with `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` and references two certificate file IDs. The leaf in DMZ X.509 line 1 is an RSA certificate with the corresponding subject, SANs, and validity interval. Across the complete supplied certificate records, I found 186 distinct fingerprints and no contradictory immutable metadata for the same fingerprint. Across hashed file observations, identical SHA-256 values did not acquire different sizes or inconsistent MD5/SHA-1 values.

I did not use sanitized-looking domains, private/public address ownership, missing source families, or high cross-source matching rates as evidence of synthetic origin.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| hard_contradiction | Core Zeek DNS and TCP connection accounting | Three fully observed queries are shorter than their minimum DNS-over-TCP payload; five successful responses also have the bare DNS-sized total; six distinct zero-gap transactions are implicated | Main reason for the synthetic verdict; repeated two-byte framing deficit is concrete, while its limited protocol scope keeps the score below the strongest dataset-wide range |

## Realism Score by Category

- **Field format accuracy:** 7 — JSON fields and protocol vocabulary are generally credible; TCP DNS payload sizes contain a repeated source-native contradiction.
- **Temporal patterns:** 9 — Protocol events fit flow intervals, administration sessions have duration tails, and hourly counts vary.
- **Cross-source correlation:** 7 — UID, tuple, file, and certificate relationships are strong; DNS decoded content disagrees with its transport byte totals.
- **Behavioral realism:** 8 — Explicit proxy browsing, mixed successful/failed traffic, infrastructure activity, and long administration sessions are plausible.
- **Environmental consistency:** 9 — Sensor-specific protocol populations and stable DNS/certificate identities fit the visible segmentation; no substantial role contradiction was established.

## Recommendations

- If this were synthetic, calculate DNS-over-TCP transport bytes from the encoded DNS message plus its two-byte length prefix in each direction. Recheck the three zero-gap query failures and the five zero-gap successful responses listed above.
- If this were synthetic, validate decoded application-message minimum lengths against connection payload totals after protocol framing, optional records, retransmission, and capture-gap handling have been applied. Use the fully observed `41/57` TCP exchanges as regression examples.
- If these connection counters intentionally exclude application framing through a transformation, document that transformation explicitly instead of presenting them as ordinary Zeek TCP `orig_bytes` and `resp_bytes` semantics. That would change the interpretation of the principal finding.
