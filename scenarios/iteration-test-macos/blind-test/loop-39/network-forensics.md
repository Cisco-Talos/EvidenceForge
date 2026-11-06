# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 64
**Synthetic-Confidence Score:** 30

## Executive Summary

The network telemetry is mostly production-like: flow accounting, protocol timing, certificate relationships, and proxy routing withstand several checks that commonly expose generated data. My lean toward real is modest, because convincing synthetic telemetry could also satisfy these checks; the clearest reservation is an unusual concentration of iPhone user agents on an address identified as a Mac.

## Evidence For Synthetic

- [environment_or_collection_plausibility] A visibly Mac-associated address supplies predominantly mobile-browser user agents. `zeek-core/dhcp.json:1` assigns `10.10.1.41` to `MAC-MROSS-01`; among the 387 `zeek-core/http.json` records originating at that address, 295 contain `iPhone; CPU iPhone OS 17_2`, 61 contain desktop Safari `Version/26.0`, and 31 contain desktop Chrome `155.0.0.0`. Examples are `http.json:236` (`ts=1793627006.710412`, mobile UA, CONNECT to `outlook.office365.com`) and `http.json:52` (`ts=1793625365.354937`, desktop Safari, CONNECT to the EHR portal). This could reflect an overly broad UA pool, but browser emulation, an application override, or locally forwarded traffic are viable explanations. It is not a hard platform contradiction and receives only a small weight.
- [weak_signal] Browser version values form conspicuously separated cohorts: numerous Windows/Linux requests use Chrome 120 or Firefox 121, while the Mac addresses use Chrome/Edge 155 and Firefox 158. For example, the first record for `10.10.1.42` is `zeek-core/http.json:29`, with Firefox 158, whereas the Linux Chrome 120 cohort contributes 344 core HTTP rows across addresses. This is observable version-pool texture, not a claim that any stated release is impossible; pinned software or differing management policies can explain it. It contributes little independently.

## Evidence For Real

- Connection states have a sensible long tail. Core has 9,996 SF, 1,918 S0, 166 RSTO, 98 RSTR, 36 OTH, 23 REJ, and smaller S1/S2/S3 populations; DMZ has 2,620 S0 among 9,287 flows, consistent with the visible unsolicited probing rather than uniformly successful traffic.
- DNS includes address, service-discovery, reverse, and non-address queries, with negative and error responses. Core contains 2,270 A, 266 AAAA, 247 TXT, 142 PTR, 100 SRV, 8 NS, and 6 MX transactions; responses include 213 NXDOMAIN, 15 SERVFAIL, and 4 REFUSED. `zeek-core/dns.json:13` is an authoritative NXDOMAIN for `oldserver.meridianhcs.local`; line 70 is a non-authoritative NXDOMAIN for bare `wpad`.
- Proxy traffic has distinct client-to-proxy and proxy-to-destination transport identities. The first transaction is client `10.10.2.11` to proxy `10.10.3.20:8080` (`zeek-dmz/conn.json:4`, UID `CHG0dsSc51ZN4B3ceG`), followed by proxy-to-`13.107.21.200:443` (`conn.json:6`, UID `CIj4Ar0A5jQSCTqsF4`). DNS lookup, TLS SNI, CONNECT target, and the access record agree without conflating the transport legs.
- TLS has mixed TLS 1.2/1.3 negotiation, several appropriate cipher families, resumed sessions, and differentiated handshake histories. For example, `zeek-core/ssl.json:4` is a resumed TLS 1.2 connection with `ssl_history=CsiI`; `zeek-dmz/ssl.json:1` is a non-resumed TLS 1.2 handshake with a certificate chain and `CsxknGIi`.
- The checked flow/protocol relationships have no demonstrated impossible visible ordering, tuple mismatch, or file-payload accounting contradiction. This is positive evidence of coherent construction, not evidence that comprehensive coverage itself proves authenticity.

## Detailed Analysis

### Scope and method

I parsed all supplied Zeek JSON sources in `zeek-core`, `zeek-dmz`, and `zeek-db`, including 22,030 connection records, 3,993 DNS records, 4,825 HTTP records, 3,106 SSL records, 2,239 file records, and 1,120 X.509 records. I also sampled the perimeter ASA logs, proxy access logs, Snort alerts, and the Mac endpoint records to interpret address ownership. All citations below are relative to the supplied data directory and use physical, one-based line numbers.

The connection window is approximately 2026-11-02 13:00–19:00 UTC. It does not establish overnight behavior or a whole working-day curve. I did not penalize absent overnight traffic, out-of-window session closure, missing optional source families, sanitized domains, or source alignment completeness.

### Transport states, packet accounting, and lifecycle

For each sensor I joined DNS, HTTP, and SSL rows to conn rows by UID and checked the four endpoint tuple fields. Every joined row had a local conn record with the same tuple. With a 2 ms comparison tolerance, none of these protocol timestamps fell outside its connection's recorded interval. DNS RTT also stayed within the associated connection duration, allowing 5 ms for comparison/rounding.

I checked TCP/UDP IP-byte counters against transport payload and minimum headers; no row had fewer IP bytes than its payload plus minimum per-packet header budget. No extracted file's `seen_bytes` exceeded the associated direction's connection payload. TCP connections sharing an exact directional four-tuple did not have overlapping recorded intervals within a sensor. Fully established/closed SF TCP rows also had enough packets for a basic completed handshake and closure, and their histories included both FIN directions. These are bounded consistency checks rather than packet-level proof: a conn history string cannot establish every individual TCP sequence transition.

An instructive large transfer is `zeek-core/conn.json:4`, UID `CGGIhzcd1Hc4Y0cAlD`: SMB from `10.10.1.21:53916` to `10.10.2.21:445`, duration 1.549999 seconds, 2,335 originator bytes and 5,361,807 responder bytes. The responder file at `zeek-core/files.json:1` has 5,359,834 bytes, below that payload, and the mapping/open/file evidence occupies the connection interval. The payload direction is consistent with a client reading a spreadsheet from the server.

SSH also has plausible long-lived transport rather than only short web-like durations. `zeek-core/conn.json:39`, UID `CbbSE24VGD6dBhn8F9V`, carries an SF SSH flow from `10.10.1.21` to `10.10.2.30:22` lasting 3,420.626394 seconds, with 48,536/173,689 payload bytes. Core successful SSH durations range from approximately 0.591 seconds to 13,321.989 seconds. Short entries deserve contextual interpretation, but are not intrinsically impossible SSH transports.

### DNS and explicit proxy path

The first visible proxy exchange has useful ordering. `zeek-dmz/dns.json:1` asks for `www.bing.com` at `1793624461.689653`, RTT 0.040298 seconds. Its response therefore precedes the outbound TLS connection opening at `1793624461.738194` (`zeek-dmz/conn.json:6`). SSL starts at `1793624461.783240` (`ssl.json:1`) and uses the matching SNI and responder address. The client-side CONNECT is separately visible at the proxy interface (`http.json:1`) and in `PROXY-01.meridianhcs.local/proxy_access.log:1`.

The access log distinguishes CONNECT control-message bytes from tunnel bytes: line 1 records 314 client control bytes plus 1,728 client tunnel bytes, totaling the client-facing flow's 2,042 originator bytes. Its 148 control response bytes plus 32,246 tunnel response bytes equal that flow's 32,394 responder bytes. The server-facing TLS flow separately carries 1,728/32,246 payload bytes. This is a meaningful semantic consistency check rather than merely identical hostnames.

I did not require a fresh DNS query before every connection: cache use and proxy-side resolution are expected. Successful AAAA transactions without answers were treated as possible NODATA, not faulty IPv6 responses. Returned address literals did not conflict with their A/AAAA type in the checks performed.

### TLS and certificate evidence

DMZ contains 1,948 TLS 1.3 SSL records and 781 TLS 1.2 records; core has 194 TLS 1.3, 163 TLS 1.2, and three incomplete rows without negotiated version/cipher. The DB sensor's 17 SSL records are TLS 1.2. This can reflect a mix of Internet-facing clients and older internal service configurations; the legacy CBC cipher use is a security observation, not by itself an authenticity defect.

I checked repeated X.509 fingerprints for incompatible serial, subject, issuer, validity, key, or SAN values, and found none. Referenced certificate-chain FUIDs existed in the sensor's files records. TLS 1.2 ECDSA cipher rows with visible leaf certificates did not show RSA leaf-key mismatches in the checks performed. I did not demand passive certificate extraction from TLS 1.3 sessions.

### Distribution and host attribution

Traffic is not evenly distributed by sensor role: DB is dominated by TCP/3306 (314 of 464 conn rows), whereas core has substantial DNS, Kerberos, LDAP, SMB, and proxy traffic. DMZ combines proxy/outbound TLS with a substantial failed-probe population. The core hourly conn counts are 1,696, 3,149, 1,825, 1,785, 2,021, and 1,803; DMZ is 1,441, 2,530, 1,251, 1,352, 1,334, and 1,379. The second-hour uplift is not a flat artificial cadence, although a six-hour window is inadequate to characterize business-hour realism fully.

The most useful residual anomaly is the browser identity split at `10.10.1.41`. DHCP labels it as a Mac, and the supplied endpoint file has `hostname=MAC-MROSS-01` with macOS application paths. Nevertheless, its 295 mobile-UA core HTTP records dominate its 387 requests. That deserves explanation, but a User-Agent is client-supplied and cannot establish the actual client OS. I therefore do not elevate this to impossible field content or a hard contradiction.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| environment_or_collection_plausibility | Zeek HTTP plus DHCP/endpoint attribution | 295 of 387 HTTP rows for Mac-associated `10.10.1.41` advertise iPhone OS 17_2 | Small upward adjustment; possible UA-pool mismatch, but emulation/overrides/forwarding remain plausible |
| weak_signal | Zeek HTTP | Browser version cohorts differ sharply between Windows/Linux and Mac addresses | Very small adjustment; possible stale enumerables, equally compatible with pinned enterprise software |

No hard contradiction or demonstrated contract gap was found by the stated checks. The score remains in the mostly realistic band; it does not mean the source is known to be production data.

## Realism Score by Category

- **Field format accuracy:** 9 — JSON fields, connection accounting, protocol tuples, and visible certificate identities are coherent in the checks performed.
- **Temporal patterns:** 8 — Protocol observations fit their transport intervals and volumes vary; the short collection window limits daily-cycle assessment.
- **Cross-source correlation:** 9 — Proxy control/tunnel accounting, DNS-to-upstream ordering, files, and TLS references agree without observed semantic contradictions.
- **Behavioral realism:** 8 — Mixed discovery/authentication/file/service traffic, failed scans, and long-lived SSH are credible; browser identity texture remains a reservation.
- **Environmental consistency:** 7 — Sensor-role distributions are plausible, but the dominant mobile UA on a Mac-associated address requires contextual explanation.

## Recommendations

- If this were synthetic, tie the default HTTP UA to the visible client application and host platform. Retain mobile-UA emulation or forwarding only where there is supporting activity or a clear collection explanation; the concrete target is `10.10.1.41`'s 295 iPhone-UA records.
- If this were synthetic, review the observed browser version cohorts against each host's intended application inventory. Different management policies can justify different versions, so the objective would be consistency with visible application ownership rather than forcing every machine to use the same version.
