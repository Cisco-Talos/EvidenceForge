# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 63
**Synthetic-Confidence Score:** 24

## Executive Summary

The examined network evidence is mostly production-like: transport accounting, DNS response diversity, proxy semantics, certificate references, and protocol timing agree in the checked examples. I found no demonstrated impossible ordering, malformed native protocol value, or broken exact-identity join; the modest synthetic-confidence score reflects a narrow TLS distribution on the database observation path rather than a decisive defect. This is a bounded authenticity assessment, not proof of origin.

## Evidence For Synthetic

- [weak_signal] `zeek-db/ssl.json` contains only 19 TLS observations: 11 negotiate `TLSv12` / `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256` and eight negotiate `TLSv12` / `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`. This is a noticeably narrow, older-looking pool compared with the core and DMZ streams. A constrained server agent/service population is a sufficient real-world explanation, so this observation carries little weight and is not a protocol contradiction.
- No important `hard_contradiction`, `contract_gap`, or `schema_or_format` finding was demonstrated in the bounded sample and aggregate checks. I do not infer synthetic origin from complete joins, attack narratability, sanitized destinations, or absent optional sources.

## Evidence For Real

- The three observation paths have different traffic mixes. Core has 2,607 Kerberos and 1,105 LDAP service connections; DMZ has 3,152 SSL service connections; database has 231 MySQL service connections among 438 total connections. These are coherent with distinct visibility zones rather than one flat protocol mix.
- DNS contains successful and failed lookups and several query classes. Core's 3,265 DNS records include 2,398 A, 274 AAAA, 163 PTR, 100 SRV, 307 TXT, 16 NS, four SOA, and three MX observations; response codes include 222 NXDOMAIN, 14 SERVFAIL, and four REFUSED.
- TCP histories include both FIN orderings, resets, rejected attempts, incomplete connections, retransmission-related histories, and gaps. The core connection states are 10,406 SF, 1,768 S0, 442 OTH, 162 RSTO, 101 RSTR, 29 REJ, 15 S3, 11 S2, and nine S1. The other sensors have different proportions.
- The exact database TLS pivot preserves tuple, UID, certificate references, hashes, byte budget, and sequence. The exact proxy pivot preserves source port, CONNECT target, user agent, and separate control-message/tunnel byte accounting.
- All 2,339 TLS 1.3 observations across core and DMZ omit certificate chains. This is compatible with the encrypted certificate exchange on that protocol; visible certificate records are not indiscriminately attached to every TLS connection.

## Detailed Analysis

### Scope and collection limits

I read only the supplied briefing and assigned data tree. I examined approximately 20 representative records across the three sensors' `conn.json`, `dns.json`, `http.json`, `ssl.json`, `files.json`, and `x509.json`, with two exact pivots expanded below, plus bounded aggregate checks. The representative midpoint rows were selected by position rather than suspicious content. Proxy and firewall examples were included to check observation semantics. The connection-start window is approximately 2026-11-02 13:00–19:00 UTC; core starts at 13:00:00.006178 and its latest start is 18:59:44.793219. A connection's close may extend beyond its start-window boundary; this is not itself a lifecycle defect.

There is no packet capture, sensor configuration, or authoritative collection manifest in this review. I cannot verify cryptographic signatures, actual packet segmentation, overnight behavior, OS-specific traffic requirements, or whether every absent companion should have been observed. I did not treat sensor overlap as independent volume, and did not require each DNS query to be a fresh lookup for every subsequent connection.

### Exact pivot 1: database TLS, transport to certificate

In `zeek-db/conn.json`, UID `C86skU4nKOD3QEHD46` starts at Unix timestamp `1793629055.673433`, tuple `10.10.4.10:38574 → 10.10.2.40:443`, TCP/SSL, SF, duration `4.389016`, with `orig_bytes=4529` and `resp_bytes=4257`. Its history `ShADadFf` is compatible with a completed connection.

`zeek-db/ssl.json` preserves that exact UID and tuple at `1793629055.851207`, 177.774 ms after transport start. It reports established TLS 1.2, SNI `LOG-MON-01.meridianhcs.local`, and chain FUIds `F1y6ZBpE9OEFNANXB` and `FhweDGrsF69jISjfR`.

The matching `files.json` entries occur at `1793629055.857272` and `1793629055.868868`, each with the exact connection UID, sender `10.10.2.40`, receiver `10.10.4.10`, and depths zero and one. Their `seen_bytes` total is `1239+1673=2912`, within the 4,257 responder payload bytes. The intermediate FUID resolves in `x509.json` at `1793629055.875193` to a CA certificate with `basic_constraints.ca=true`; its fingerprint `853b235d5d54761f7b33ad0186600e0a7e0e1545` matches the corresponding file's SHA1. The subject is the Meridianhcs Enterprise Issuing CA and issuer is Enterprise Root CA. The visible order is transport, TLS, certificate-file observations, then certificate metadata, all within the connection interval. No impossible ordering was found.

### Exact pivot 2: proxy CONNECT, transport and access record

`zeek-core/conn.json` UID `CcWaxAYQjc7El3HI2J` starts at `1793635511.892404` (2026-11-02 16:05:11.892404 UTC): `10.10.1.22:38139 → 10.10.3.20:8080`, TCP/HTTP, SF, duration `0.990148`, `orig_bytes=2190`, `resp_bytes=4325`.

Its `http.json` record at `1793635511.965834` preserves UID and tuple and reports `CONNECT drive.google.com:443`, HTTP/1.1, status 200 `Connection Established`, zero request/response body length, and an Ubuntu Firefox user agent. Zero HTTP message-body length is compatible with tunnel traffic; it does not mean the TCP connection transferred zero bytes.

The exact access-log match in `PROXY-01.meridianhcs.local/proxy_access.log` at `[02/Nov/2026:16:05:11 +0000]` identifies `10.10.1.22`, `omar.haddad@meridianhcs.local`, the same CONNECT target and user agent, `client_src_port=38139`, and tunnel `PT-2eaa7484f8d1ecf0`. It reports `cs_bytes=224`, `wire_sc_bytes=186`, `tunnel_cs_bytes=1966`, `tunnel_sc_bytes=4139`, and `tunnel_duration_ms=745`. Control plus tunnel bytes equal the corresponding Zeek payload counts: `224+1966=2190`, `186+4139=4325`. The tunnel duration fits within transport duration. This is a concrete consistency check, not evidence that complete matching itself establishes authenticity.

### DNS, TLS, timing, and accounting checks

The representative core DNS row at `1793636451.985097`, UID `CMAK59U0DCnDtKGZmPx`, resolves `DC-02.meridianhcs.local` to `10.10.2.11`, with authoritative response, 300-second TTL, and 1.149 ms RTT. The DMZ row at `1793636022.889192`, UID `CuuOANKEncLPa8seDh`, has a nonauthoritative response for `cache.pagerduty.co`, TTL 43 seconds, and 28.996 ms RTT. Internal and external response behavior therefore differs plausibly. Sanitized names and real-world domain-to-IP ownership were not used as evidence.

All DNS, HTTP, and SSL UIDs resolved to a connection record within their respective sensor files: core 3,265/2,520/413, DMZ 1,165/2,776/3,038, and database 48/22/19. None of the 5,318 HTTP observations had `response_body_len` greater than the matching connection's responder payload bytes. None of 16,264 TCP connection rows had IP-byte counts below payload plus a conservative 20-byte minimum IP header per packet. These checks rule out particular contradictions; they do not establish packet-level fidelity.

Certificate fingerprints did not map to conflicting certificate properties within any sensor. SSL certificate-file byte sums fit responder payload counts for all 135 core, 588 DMZ, and 13 database connections checked by aggregation. Core TLS includes 214 TLS 1.3 and 199 TLS 1.2 observations; DMZ includes 2,125 TLS 1.3, 909 TLS 1.2, and four rows without a negotiated version/cipher. The role-specific mix and absent TLS 1.3 certificate chains support coherent observation semantics.

Hourly connection counts vary: core `1829,3443,1898,1769,2176,1828` and DMZ `1515,2916,1496,1534,1401,1401` for UTC hours 13 through 18. The visible 14:00 peak and unequal hourly counts do not support an overly smooth timing allegation. Six hours is insufficient to judge weekday, overnight, or business-cycle realism.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| weak_signal | Database Zeek TLS | 11 CBC and eight GCM TLS 1.2 observations; 19 total | Small upward influence for a narrow older-looking pool; service/agent homogeneity remains a plausible explanation. |
| No demonstrated hard finding | Sampled network/proxy evidence | Two exact pivots and aggregate consistency checks | No hard contradiction, contract gap, or native formatting error justified a high score. |

## Realism Score by Category

- **Field format accuracy:** 9 — Sampled Zeek types, histories, tuple fields, and certificate/file references are coherent; no packet capture was available.
- **Temporal patterns:** 8 — Variable hourly volumes and valid sampled protocol ordering; the six-hour slice limits broader inference.
- **Cross-source correlation:** 9 — Both exact pivots preserve identity, timing, and compatible byte budgets.
- **Behavioral realism:** 8 — Distinct infrastructure, database, DNS, proxy, and failed-connection patterns; application intent was not independently verified.
- **Environmental consistency:** 8 — Sensor-specific protocol mixes and TLS behavior are plausible; database TLS homogeneity is a weak uncertainty.

## Recommendations

- If this were synthetic, verify the database agents and services behind the 19 TLS observations against the intended environment before changing the cipher mix. Add diversity only where distinct clients or servers actually warrant it; blindly imposing a modern global distribution could reduce realism.
- Preserve the demonstrated transport-to-protocol ordering, certificate hash/reference consistency, and explicit distinction between CONNECT control bytes and tunnel bytes. No evidence-based repair to those contracts is indicated by this sample.
- For a stronger future authenticity assessment, provide a declared sensor/decryption scope and a longer time window. This is an assessment limitation, not a missing-source synthetic indicator.
