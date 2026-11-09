# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 28

## Executive Summary

The network records are mostly production-like: protocol-specific timing, proxy accounting, TLS visibility, certificate references, and connection/protocol relationships survive several whole-file consistency checks. I found modest packet-count and database-session texture worth examining, but no demonstrated impossible network relationship sufficient to distinguish sophisticated synthetic data from sanitized production telemetry.

## Evidence For Synthetic

- [weak_signal] Several unrelated application families share a compact packet-count relationship. Among successful TCP flows without `T/t/G/g` history flags, both directional packet counts equal `ceil(direction_bytes / 1400) + 3` in 99/161 MySQL connections at `zeek-db/conn.json`, 720/1,515 HTTP connections at `zeek-core/conn.json`, and 372/721 LDAP connections at the core sensor. Examples include database lines 12, 19, 26, and 30. This suggests a common packet-budget approximation, but ordinary segmentation, short transactions, and common MTUs can also create this relationship; it is not a contradiction or a sufficient authenticity test.
- [environment_or_collection_plausibility] Database traffic has a limited persistence tail. The 278 `service=mysql` records in `zeek-db/conn.json` have approximately 2.84-second median duration, 15.71-second 95th percentile, and 29.89-second maximum, mainly from `10.10.3.10` to `10.10.4.10:3306`. A six-hour application/database observation dominated entirely by short connections could reflect request-scoped database access, but deserves checking against the actual application's connection-management behavior. I give this little weight because connection pooling is not mandatory and the application implementation is unknown.

## Evidence For Real

- DNS is differentiated by query and response semantics rather than merely repeating successful A queries. The core sensor has 2,315 A, 282 AAAA, 160 PTR, 102 SRV, 301 TXT, and smaller MX/SOA/NS populations; its responses include 206 NXDOMAIN, 13 SERVFAIL, and three REFUSED. `zeek-core/dns.json:9` records an authoritative NXDOMAIN for `printer01.meridianhcs.local` at `1793624533.801215`, while line 10 records an empty successful AAAA response for an internal DC. These are distinct, plausible outcomes.
- Proxy control-message sizes are separated correctly from tunnel payloads. `PROXY-01.meridianhcs.local/proxy_access.log:2` reports 519 request/control bytes, 159 response/control bytes, and tunnel bytes of 4,473/24,266. The corresponding core connection at `zeek-core/conn.json:13` totals exactly 4,992/24,425 bytes, while `zeek-core/http.json:2` correctly gives the successful CONNECT response no HTTP body. This is a substantive accounting check, not a claim that completeness itself proves authenticity.
- TLS 1.3 records consistently avoid visible certificate chains. For example, `zeek-core/ssl.json:2` uses `TLSv13`, `TLS_AES_256_GCM_SHA384`, `ssl_history=Cs`, and no `cert_chain_fuids`; `zeek-dmz/ssl.json:3` has the same appropriate visibility distinction. TLS 1.2 full handshakes instead carry certificate references, and resumed TLS 1.2 handshakes use a different history.
- Connection outcomes are heterogeneous and generally agree with histories and counters. `zeek-core/conn.json:1746` has `REJ`, history `Sr`, zero application bytes, and one packet in each direction. Core line 4 has a one-way UDP syslog observation with `S0`, history `D`, and zero responder packets. Both are internally coherent rather than a blanket population of successful TCP sessions.
- Remote-session durations differ materially from web/database transactions. Core SSH connections range from fractions of a second to roughly 3.7 hours; `zeek-core/conn.json:5387` contains a 13,295.146780-second SSH connection, while the matching DMZ observation at line 4498 differs in observed missing bytes and responder packet count. That is compatible with independently situated sensors.

## Detailed Analysis

### Inputs and examination limits

I read the supplied neutral briefing and files under `/private/tmp/log-study-kg97anv_/data` only. I did not inspect project files, scenarios, prior assessments, or other reviewers' reports. Parsing used system Python with `/private/tmp` as its working directory. Generic inherited operating instructions were not treated as evidence about the dataset's origin. No external research was used.

I parsed every JSON record in all three Zeek sensor directories. I also inspected representative proxy, ASA, Snort, and normalized endpoint records to understand the observation path. The conclusions below principally concern the Zeek/proxy evidence; I did not perform a comprehensive endpoint audit or claim to validate every ASA/IDS record.

All line references are one-based physical lines in files relative to the supplied data directory. Timestamps are Unix UTC seconds unless specified otherwise.

### Scope, volume, and observation path

The connection files contain 12,251 core, 9,122 DMZ, and 432 database records. These are sensor observations, not necessarily 21,805 distinct physical connections: flows seen at multiple network positions can occur more than once with different UIDs. The core window runs from 2026-11-02 13:00:02.762275 UTC to 18:59:49.033428 UTC. Database and DMZ observations lie within substantially the same six-hour interval.

The database sensor is concentrated on the application/database path: 294 connections originate at `10.10.3.10`, and 294 target port 3306. The DMZ sensor has substantial proxy traffic originating at `10.10.3.20`, as well as inbound scan-like traffic. Core traffic includes 2,607 Kerberos-service records, 1,130 LDAP, 465 SMB, 50 SSH, 14 RDP, 334 syslog, and 60 DHCP observations. This distribution is compatible with distinct network observation zones. I do not infer missing NTP, QUIC, or any platform-specific discovery protocol to be an authenticity defect without a collection requirement.

Hourly connection counts are uneven rather than fixed: the core records 1,715, 3,224, 1,807, 1,677, 2,015, and 1,813 connections in successive hours. DMZ counts are 1,397, 2,739, 1,293, 1,165, 1,218, and 1,310. The six-hour slice cannot establish overnight, weekend, or full-day working patterns, so those remain untested rather than deficient.

### Connection states, counters, and lifecycles

Core connection states include 9,855 SF, 1,682 S0, 148 RSTO, 93 RSTR, 34 REJ, and smaller S1/S2/S3 populations; DMZ includes 6,154 SF and 2,439 S0. The S0 share must be interpreted alongside observed one-way UDP traffic and inbound probing rather than as a blanket failed-TCP rate.

I checked TCP/UDP byte counters against a conservative minimum of application bytes plus 40 TCP/IP or 28 UDP/IP bytes per observed packet. There were no failures among connections with `missed_bytes=0`. Apparent failures when missing bytes were nonzero were excluded: Zeek's sequence-derived payload totals need not equal captured wire payload when a sensor misses traffic. ICMP was excluded from this TCP/UDP check.

For successful TCP connections without retransmission/gap history flags, IP-byte minus payload-byte differences were multiples of four, consistent with IPv4/TCP header alignment. This is a useful plausibility check, although a generator can satisfy it too.

The packet-count clustering described above is the strongest remaining texture concern. For example, database line 12 has 1,161/47,989 payload bytes and 4/38 packets, and line 26 has 4,544/4,128 bytes and 7/6 packets. These follow the same 1,400-byte segmentation-plus-three relationship despite different sizes. However, many other connections deviate, and the offsets are not a dataset-wide invariant. I therefore classify this as weak evidence rather than an impossible packet budget.

The longest visible SSH flow begins at `1793632523.608978` and extends beyond the last connection-start timestamp. I do not penalize that: a timestamp slice is not complete boot-to-shutdown capture, and an output's latest connection start is not necessarily its capture stop. There is no demonstrated same-identity lifecycle inversion here.

### DNS semantics and timing

Across the three sensors there are 4,245 DNS records. Every DNS UID resolves to a connection within the same sensor, and every DNS timestamp is within that connection's reported interval. The same held for all 4,501 HTTP and 2,903 SSL records: no missing connection UID or protocol timestamp outside its corresponding connection interval, allowing a one-millisecond numerical tolerance.

That reference integrity is not itself a synthetic tell or proof of reality. Its value is that attempted contradiction checks did not expose a required companion tied to the wrong tuple or an application record occurring after its own connection had closed.

The records distinguish negative answers from no-data answers. Core DNS line 9 is NXDOMAIN with no answers, while line 10 is NOERROR for an internal AAAA query without an IPv6 answer. Core line 50 supplies a PTR answer for `10.2.10.10.in-addr.arpa` pointing to `DC-01.meridianhcs.local`, with TTL 3,600. Core line 23 supplies two DC targets for `_kerberos._tcp.meridianhcs.local`, each with TTL 86,400. DMZ line 6 shows a DNS suffix-expanded external-looking name ending in the internal domain and returning NXDOMAIN.

A conservative UDP DNS message-size check found no response smaller than the query section and its reported answer data could minimally require. This check intentionally used lower bounds for variable-length answer types rather than pretending the JSON contains full DNS wire encodings.

I do not require a DNS row immediately before every TCP connection: host/proxy caches, direct IP use, and collection boundaries can all eliminate that apparent pairing. The visible proxy failure at the beginning is coherent: DMZ DNS line 1 queries `dl.duosecurity.com` at `1793624420.969035` with RTT 0.084475; DMZ connection line 3 attempts the returned address at `1793624421.073955` and is rejected. The associated CONNECT returns 503. The outbound attempt therefore follows the visible DNS response rather than preceding it.

### HTTP and proxy accounting

CONNECT dominates the HTTP records: 1,913 of 2,122 core transactions and 1,949 of 2,361 DMZ transactions. This does not imply plaintext browsing dominates encrypted traffic: CONNECT is the proxy control protocol used to establish HTTPS tunnels. The DMZ SSL file contains 2,535 TLS records on outbound or other visible TLS paths.

Core HTTP status counts include 48 policy denials (403), 38 proxy-authentication challenges (407), 14 gateway timeouts (504), nine service-unavailable responses, and six bad-gateway responses. The mixture makes sense for an explicit proxy. CONNECT success rows use `Connection Established` and zero response body; failed CONNECTs can have an HTML error body and corresponding file-analysis reference, as at core HTTP line 1 and files line 1.

Every referenced HTTP response file began at or after the associated HTTP timestamp. Referenced files with connection information also fit inside their connection intervals, including their recorded duration where present. I found no HTTP file extracted before its own request or after its own connection ended.

### TLS, X.509, and certificate relationships

The TLS version mix varies with network role. The DMZ file has 1,689 TLS 1.3 records, 845 TLS 1.2 records, and one unsuccessful record without a negotiated version. The database file's 16 SSL records are TLS 1.2. Its internal-service use of CBC ciphers is dated but technically possible, and is not by itself a synthetic defect.

All referenced certificate FUIds resolve in the same sensor's X.509 file. Adjacent certificates in reported chains have matching issuer/subject names. No repeated fingerprint maps to conflicting certificate metadata within a sensor. TLS 1.2 ECDHE_RSA versus ECDHE_ECDSA cipher authentication agrees with the referenced leaf key type in every checked full handshake. An EC leaf signed by an RSA issuer is permissible; I did not confuse the leaf's public-key type with its issuer's signature algorithm.

TLS 1.3 handshakes have no visible certificate-chain references, matching the encryption of certificate messages after ServerHello in passive observation. TLS 1.2 full and resumed histories differ appropriately. These checks support source-native plausibility, though lack of raw packet capture prevents cryptographic verification of certificates or handshakes.

### Overall interpretation

No hard contradiction, source identity leak, or required network companion mismatch was demonstrated. The packet-count clustering and short database sessions justify a score slightly above the indistinguishable range, but neither identifies synthetic origin reliably. Domain sanitization, source matching completeness, absence of selected collectors, and the narratability of suspicious behavior did not contribute to the score.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| weak_signal | Zeek connection packet counters | 99/161 clean successful database MySQL flows; comparable clustering in core HTTP and LDAP | Modest concern that multiple protocols share an approximate packet-budget texture; possible with ordinary segmentation, so low weight |
| environment_or_collection_plausibility | Database sensor connection durations | 278 identified MySQL flows over about six hours; maximum roughly 30 seconds | Slight concern about lack of a persistence tail; request-scoped database access remains a plausible explanation |
| No confirmed hard contradiction or contract gap | Zeek DNS/HTTP/SSL/files/X.509 and sampled proxy | Whole-file UID, timing, byte-minimum, and certificate-reference checks described above | Keeps the score in the mostly realistic range; integrity alone does not establish real origin |

## Realism Score by Category

- **Field format accuracy:** 9 — Parseable source-native shapes and plausible counters, states, TLS fields, and certificate relationships; packet capture was unavailable for full verification.
- **Temporal patterns:** 8 — Uneven hourly volumes, varied durations, and plausible protocol timing; only a six-hour slice and a short database persistence tail were visible.
- **Cross-source correlation:** 9 — Protocol UIDs, file timing, certificate references, DNS-to-egress timing, and sampled proxy byte accounting agree without demonstrated impossible ordering.
- **Behavioral realism:** 8 — Proxy failures, negative DNS, infrastructure traffic, inbound probes, and long SSH sessions coexist; packet-count texture remains a small concern.
- **Environmental consistency:** 9 — Distinct core, DMZ, and database traffic populations fit their apparent observation paths; application connection-management details remain unknown.

## Recommendations

- If this were synthetic, validate packet-count populations against packet-derived examples for each application family. Preserve protocol-specific handshake, request/response, acknowledgement, segmentation, and idle behavior instead of relying disproportionately on a common payload-size-plus-overhead rule. The measured clustering is the reason for this recommendation, not a claim that every clustered row is wrong.
- If this were synthetic, choose database connection lifetimes to match the modeled application's actual access pattern. The observed 278 short MySQL connections are reasonable for per-request connection creation; an application intended to use persistent pools should instead yield some long-lived database connections with multiple transactions. Do not add pooling merely to satisfy a generic expectation.
- Preserve the demonstrated proxy control/tunnel accounting, TLS 1.3 certificate visibility distinction, DNS negative/no-data semantics, and sensor-local lifecycle consistency while changing any distributions.
