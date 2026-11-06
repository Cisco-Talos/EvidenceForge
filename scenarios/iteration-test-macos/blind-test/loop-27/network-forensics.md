# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 76
**Synthetic-Confidence Score:** 64

## Executive Summary

The network records have convincing protocol variety, plausible timing, and generally coherent connection-to-protocol relationships. My principal reason for judging them likely synthetic is a repeated mismatch between successful proxy tunnel byte counts and the corresponding upstream TCP stream, even in completed connections with no reported capture gaps. That conclusion depends on the visibly advertised tunnel being a pass-through connection; unrecorded TLS interception or nonstandard counter definitions would weaken it substantially.

## Evidence For Synthetic

- [contract_gap] Successful proxy tunnels do not consistently conserve their TCP payload across the proxy. At `PROXY-01.meridianhcs.local/proxy_access.log:1` (2026-11-02 13:01:30 UTC), the CONNECT to `20-205-195-86.microsoft.com:443` reports `proxy_action=tunnel`, `tunnel_cs_bytes=819`, and `tunnel_sc_bytes=1309`. `zeek-core/conn.json:11`, UID `CQH1v2BmvpZ9Az9nM`, independently accounts for exactly those amounts after subtracting the logged CONNECT control messages: `1101−282=819` and `1459−150=1309`. However, the matching proxy-to-server flow in `zeek-dmz/conn.json:6`, UID `CaHNiAR12JFO1vtNApX`, has `orig_bytes=620` and `resp_bytes=3219`; `zeek-dmz/ssl.json:1` supplies the matching SNI. Both connections are `SF` with `missed_bytes=0`. A completed pass-through tunnel should carry the same encrypted application byte stream on both legs, after excluding its CONNECT exchange.
- [contract_gap] This is repeated rather than a single ambiguous association. In the first 25 proxy access lines, 20 successful CONNECTs had unique client HTTP and upstream TLS candidates under the matching method described below. Sixteen pairs were `SF` with zero missed bytes on both legs; four had upstream byte totals differing from the logged tunnel totals. Additional examples are proxy line 8 (`drive.google.com`: 886 client tunnel bytes versus 560 upstream bytes, `zeek-core/conn.json:142`, `zeek-dmz/conn.json:57`, `zeek-dmz/ssl.json:16`); line 12 (`proxy.rxportal.dev`: 786 versus 811, core connection line 201, DMZ connection line 74, DMZ SSL line 21); and line 20 (`edge.typekit.org`: 581 versus 765, core connection line 246, DMZ connection line 100, DMZ SSL line 28). For these three examples, server-direction bytes agree, making a uniform counter-definition difference less persuasive. I treat all four examples as one recurring contract defect, not four independent categories of evidence.

## Evidence For Real

- The sensors observe distinct, plausible traffic mixes. Of 11,853 core connections, 3,015 identify DNS, 2,624 Kerberos, 1,063 LDAP, and 429 SMB. The database sensor has 282 MySQL-classified connections among 452 total; the DMZ has 2,734 SSL and 2,285 HTTP-classified connections among 9,158. This is consistent with different network positions and host roles.
- Failure and degradation behavior is present. Core connections include 1,867 `S0`, 134 `RSTO`, 86 `RSTR`, 27 `REJ`, and smaller partial-state groups. `zeek-core/ssl.json:45` records an incomplete ClientHello (`established=false`, history `C`); its connection at core line 1470 has zero responder payload and an `S1` state. This is a coherent failed-handshake example rather than an arbitrary success label.
- DNS contains heterogeneous query and response behavior: core records include 2,222 A, 260 AAAA, 248 TXT, 163 PTR, 102 SRV, plus NS/SOA/MX, with 205 NXDOMAINs, 14 SERVFAILs, and one REFUSED. At core DNS line 4, an internal AAAA query receives NOERROR without an invented IPv6 answer; core line 2 supplies two domain-controller SRV answers.
- TLS field relationships survive representative checks. For example, `zeek-dmz/ssl.json:50` negotiates an ECDHE-ECDSA TLS 1.2 suite, and its referenced leaf at `zeek-dmz/x509.json:32` has an EC public key. The leaf's RSA certificate signature is compatible with an RSA issuer signing an EC leaf and is not a contradiction. Across the supplied X.509 rows, repeated fingerprints retain consistent certificate metadata, and their observed timestamps fall within their validity intervals.
- Normal browsing includes proxy denials and authentication challenges rather than only success. Core HTTP has 44 responses with status 403 and 31 with 407, along with redirects, caching responses, and upstream failures. Core HTTP line 18, for example, has a CONNECT denial with a 189-byte HTML response body.

## Detailed Analysis

### Scope and method

I inspected only the supplied data directory. I parsed aggregate network contracts across the three sensors' connection, DNS, HTTP, SSL, files, and X.509 JSON records, then examined representative records and a bounded sample of the first 25 proxy access lines. I sampled the firewall and alert text for format/context; I did not attempt a complete endpoint or alert-rule audit. All line numbers are one-based physical JSON/text lines. Timestamps discussed here are UTC.

The visible connection-start window is approximately 13:00–19:00 on 2026-11-02. This six-hour window cannot establish overnight or weekend behavior, so their absence does not affect the score. Connections continuing outside the window are likewise neutral.

### Connection state, accounting, and timing

The three connection files contain 21,463 rows. No TCP connections with the same directional four-tuple visibly overlap by more than 10 ms within an individual sensor. No row has application payload bytes greater than its corresponding IP-byte count, and no `SF` row has an empty packet count on either side. Successful UDP exchanges and one-way UDP traffic were interpreted separately from TCP handshake states.

Connection-state distributions are not uniformly successful: core is approximately 81.6% `SF`, DMZ 67.2%, and database 82.1%. The higher DMZ failure fraction is compatible with external probing; for example, its opening connection is an inbound unanswered attempt to port 8080. Database MySQL durations range from roughly 10 ms to 29 seconds, while observed SSH sessions can last thousands of seconds. I found no basis for penalizing these distributions.

Every supplied DNS, HTTP, and SSL UID resolves to a connection in the same sensor's `conn.json`. Their source/destination tuples agree. Using a 10 ms comparison tolerance, protocol timestamps do not precede their connection opens or exceed their recorded closes. DNS RTTs do not exceed their associated connection durations beyond 10 microseconds. These are reassuring consistency checks, not proof of production origin and not evidence of being excessively complete.

### Proxy tunnel conservation

For the bounded proxy sample, I matched a client HTTP row by source address, CONNECT hostname, and a timestamp within 1.5 seconds of the whole-second access log. I matched the upstream SSL row by source `10.10.3.20`, SNI, and timestamp between 0.5 seconds before and three seconds after that log timestamp. I retained only unique matches. The resulting twenty associations include sixteen pairs with `SF` and `missed_bytes=0` on both legs; four show the discrepancy cited above.

The first example is particularly useful because the client TCP totals exactly equal the proxy's control-message counters plus its tunnel counters, while the upstream has different totals in both directions. The other three cited examples preserve response bytes but change the client stream by −326, +25, and +184 bytes respectively. TCP/IP header overhead cannot explain this comparison: the relevant Zeek fields are payload counts, not `orig_ip_bytes` or `resp_ip_bytes`.

The main alternate explanation is TLS termination/interception or another proxy operation that changes ClientHello or application data while retaining the label `proxy_action=tunnel`. The provided access record does not establish that behavior or define such transformed counters. Without packet capture or an explicit collection/counter contract I cannot exclude it, so I label this a contract gap rather than an unconditional hard contradiction. Independent capture loss is also possible in general; the zero-gap completed examples make it less satisfactory as an explanation for the entire repeated pattern.

### DNS and TLS

The DNS mix has positive and negative responses, internal authority flags, service discovery, reverse lookups, IPv6 NODATA, and variable TTLs and response times. No parsed A answer was an IPv6 literal, and no parsed AAAA answer was an IPv4 literal. I did not compare sanitized names to public DNS and did not assume every connection must have an immediately preceding fresh query when caching or literal-address use could explain it.

DMZ TLS includes 1,767 TLS 1.3 and 866 TLS 1.2 rows; core includes 157 TLS 1.3 and 129 TLS 1.2, plus two incomplete handshakes without a negotiated version. The small database TLS sample is entirely TLS 1.2. Negotiated cipher families and certificate public-key algorithms agree in the rows with visible certificate chains. TLS 1.3 records without visible certificate chains are not a missing-evidence defect, because those handshake details are encrypted in passive observation.

Across 1,172 X.509 rows there are 183 fingerprints. I found no same-fingerprint mutation of certificate identity, key, validity, or SAN fields. I did not verify DER signatures because certificate bytes are not supplied.

### File-level observations and limits

The HTTP files have a small number of unresolved file references: five of 301 HTTP FUID references in core have no row in the supplied core files log (HTTP lines 255, 675, 1388, 1480, and 1525). DMZ's 486 and database's four references resolve. Selective files-log export or observation filtering could explain this; absent a promise of complete file collection, I have not used it as an authenticity indicator.

Two HTTP flows have summed file `seen_bytes` slightly above their connection responder payload: core connection line 1996 (252,730 versus 251,826) and DMZ connection line 323 (162,795 versus 161,870). Both have nonzero missed-byte counts, and file reconstruction/content decoding can have different accounting from a TCP stream. Without encoding or capture details, these are unresolved accounting questions, not additional scored contradictions.

## Synthetic Indicator Summary

| Category | Affected source family | Observed scope | Effect on score |
|---|---|---|---|
| `contract_gap` | Proxy access + client-side Zeek HTTP/conn + upstream Zeek SSL/conn | Four of sixteen uniquely associated, completed, zero-gap pairs in the first 25 proxy lines | Repeated failure of expected pass-through payload conservation supports a likely-synthetic score. Conditional on tunnel semantics; unrecorded interception could explain it. |

No generator identity leak, unconditional impossible ordering, or demonstrated native-schema impossibility was established. The score is driven by the repeated proxy accounting issue, not by thin coverage, narrative compactness, or complete source matching.

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed network rows have plausible native field types, protocol values, and cryptographic relationships.
- **Temporal patterns:** 8 — Varied durations and hourly volumes; sampled source relationships fit flow lifetimes.
- **Cross-source correlation:** 6 — UID/tuple relationships are strong, but the repeated tunnel/upstream byte discrepancy is material.
- **Behavioral realism:** 8 — Mixed infrastructure, browsing, failures, denials, scans, and long-lived remote sessions.
- **Environmental consistency:** 8 — Sensor traffic mixes support distinct roles; the proxy's pass-through versus interception semantics remain unresolved.

## Recommendations

- If this were synthetic, derive both TCP legs of a pass-through tunnel from one encrypted stream, then add CONNECT control bytes only on the client leg. Apply capture effects afterward and preserve compatible gap accounting. Avoid adjusting TLS handshake byte budgets independently of the advertised tunnel totals.
- If the proxy is intended to intercept or transform TLS, expose that behavior and define its counters so the observed 819/1309 versus 620/3219 relationship can be explained from the logs themselves.
- For the two file-accounting questions, preserve relevant transfer/content-encoding and capture-accounting information so analysts can distinguish decoded file sizes from transport payload. This recommendation addresses interpretability; those cases did not independently raise the synthetic-confidence score.
