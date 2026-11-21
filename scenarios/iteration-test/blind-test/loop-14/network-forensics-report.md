# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 38

## Executive Summary

The network telemetry is mostly production-like: connection and protocol records agree on identifiers, endpoints, timing, TLS visibility, and certificate relationships. Short-lived proxy connections and concentrated browser versions provide modest distribution-level concerns, but I did not establish a hard contradiction; the network evidence alone does not justify a confident synthetic or real verdict.

## Evidence For Synthetic

- [distribution_texture] Established outbound proxy TLS connections have a conspicuous short-duration concentration. In `zeek-dmz/conn.json`, joining `ssl.json` for established sessions from `10.10.3.20` to external TCP/443 yields 2,264 connections: none shorter than 0.8 seconds, 1,786 (78.9%) between 0.8 and 5 seconds, only 56 longer than 30 seconds, and none longer than 120 seconds. This could reflect bounded connection-lifetime sampling. A proxy policy that closes or rotates upstream connections remains a credible alternative, so this is a modest distribution concern rather than an impossible behavior.
- [weak_signal] Browser version vocabulary is concentrated in a few conspicuously separated generations. `zeek-dmz/http.json` contains 504 Linux Chrome/120 user agents, 252 Windows Chrome/120, 192 Windows Firefox/121, 190 Ubuntu Firefox/121, and 384 Mac Chrome/155 records. Similar concentrations occur in `zeek-core/http.json`. Platform-specific management policies can explain this; it only weakly suggests reusable user-agent pools. The Mac compatibility string `Intel Mac OS X 10_15_7` is not itself an OS-version contradiction.

## Evidence For Real

- Protocol records consistently fit their visible transport intervals. Across all three sensors, every DNS, HTTP, SSL, SMTP, and SMB file record checked has a corresponding connection UID and matching four-tuple. No protocol timestamp fell before the connection start or after its end with a 1 ms tolerance. One SMB mapping UID lacks a connection row, which I do not treat as a defect in a sliced collection.
- TLS visibility respects encryption boundaries: TLS 1.3 rows have no certificate-chain FUIDs, while observed certificate chains occur on non-resumed TLS 1.2 sessions. Resumed sessions omit chains. No TLS 1.2 RSA/ECDSA cipher-to-leaf-key mismatch was found.
- The DNS mix is varied and role-sensitive. Core DNS includes A, AAAA, TXT, PTR, SRV, NS, MX, and SOA queries, plus 207 NXDOMAIN and nine SERVFAIL responses. Database-segment DNS is predominantly internal and successful. I found no literal IPv4 answers incorrectly presented as AAAA answers, or IPv6 answers incorrectly presented as A answers.
- Connection state diversity includes completed, rejected, reset, one-sided, and interrupted connections, rather than treating all traffic as successful. In core TCP records, for example, there are 5,082 SF, 1,369 S0, 151 RSTO, 102 RSTR, and 41 REJ connections, alongside smaller S1/S2/S3/OTH populations.
- The explicit-proxy observation path is coherent. The first DMZ HTTP request is client-to-proxy; the proxy then resolves and contacts the upstream host. HTTP authentication and policy failures are present alongside successes, and readable HTTP metadata is not conflated with decrypted TLS application payloads.

## Detailed Analysis

### Scope and method

I examined only supplied files under the data directory, primarily all JSON rows in the three Zeek sensor directories, with a limited ASA sample for observation-path context. Counts below are sensor observations, not deduplicated network-wide transactions: core has 12,080 connection records, DMZ 9,839, and database 489. Their combined 22,408 rows include overlapping observations of some traffic.

The core connection-start window is 2026-11-02 13:00:00.617179 through 18:59:38.780581 UTC. DMZ runs from 13:00:22.331684 through 18:58:13.486715, and database from 13:03:31.284513 through 18:56:38.149970. This six-hour slice cannot establish a daily business-hours curve, overnight activity, or complete session lifecycles. I did not penalize missing events outside that window.

I joined protocol UIDs to connection UIDs per sensor, checked endpoint and port equality, tested timestamps against visible connection intervals, checked TCP tuple reuse for overlapping lifetimes, examined byte/packet accounting, and compared SSL chains to files/X.509 records. I found no overlapping TCP connections reusing the same directed four-tuple within any sensor. All checked HTTP response-body lengths fit within their connection responder byte counts. Visible certificate-chain file bytes also fit inside responder byte counts.

### Connection behavior and observation paths

Port distributions support different sensor positions. Core prominently observes DNS (3,157 connection rows), proxy access on TCP/8080 (2,276), Kerberos/88 (2,016), LDAP/389 (1,253), and SMB/445 (727). The database sensor sees 331 MySQL/3306 connections, 39 DNS connections, and smaller monitoring, proxy, and SSH populations. DMZ sees 3,549 TCP/443 destinations, 2,486 port-8080 connections, and external probing mixed with proxy and service traffic.

Core hourly connection-start counts are 1,759, 3,147, 1,833, 1,613, 1,957, and 1,771 for UTC hours 13 through 18. DMZ also peaks in hour 14. This is visibly uneven, although a six-hour sample and mixed scan/application traffic do not establish human work rhythms by themselves.

In `zeek-dmz/http.json`, UID `CYlSoCl10fbArTpljN` at epoch `1793624472.768378` carries a GET from `10.10.1.36:50234` to proxy `10.10.3.20:8080`, with absolute URI `http://20-205-68-81.microsoft.com/api/v2/data`. DNS UID `C3bVtz5wEhVskuIt0W` begins at `1793624472.772933`, from proxy `10.10.3.20` to resolver `10.10.2.11`, and has RTT `1.608179`. The upstream HTTP connection `CdYXWCNOhGhsQRPIbzQ` produces its file observation at `1793624474.4864`, consistent with DNS resolution preceding upstream retrieval. I do not infer an error from the domain/IP mapping, since domains may be sanitized.

The ASA sample independently represents client-to-proxy and proxy-to-outside legs with interface and NAT context, rather than presenting every original client as directly connected to the Internet. Complete matching is positive correlation evidence, not a synthetic tell.

Some connection IP-byte totals are smaller than application sequence-byte estimates plus minimum per-packet headers. These instances carry missed-byte/gap evidence; Zeek TCP sequence-space accounting can exceed captured payload in that situation. I therefore excluded the apparent arithmetic discrepancy from synthetic evidence.

### DNS

There are 3,147 core DNS records, 1,051 DMZ, and 39 database records. Core qtypes include 2,392 A, 284 AAAA, 216 TXT, 139 PTR, and 95 SRV queries; DMZ includes 876 A, 117 AAAA, and 50 PTR. Internal discovery is represented explicitly: at `1793624402.649837`, UID `Cy7bKJVXGBLSw4N5M0b` queries `_ldap._tcp.meridianhcs.local`, returns both DC names, and carries two matching 300-second TTLs.

Core DNS RTT quartiles are approximately 1.048 ms, 3.726 ms, and 41.719 ms. DMZ quartiles are 1.344 ms, 23.572 ms, and 58.393 ms. This mixture of fast internal answers and slower resolution is plausible. I checked DNS query wire-size lower bounds against connection originator payload bytes and found no too-small UDP query payloads. Negative responses did not carry contradictory positive answer lists.

### TLS, certificates, and HTTP

DMZ SSL comprises 2,107 TLS 1.3 rows, 887 TLS 1.2 rows, and four rows without a negotiated version. Core has 212 TLS 1.3, 200 TLS 1.2, and two without a version. Modern AES-GCM and ChaCha20 suites coexist with TLS 1.2 CBC traffic; the latter is not automatically an authenticity defect in a mixed estate.

For a concrete certificate-authentication example, DMZ UID `CZCV7ySvwpWz0AZuswl` at `1793625262.771628` negotiates `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` for `upload.wikimedia.org` and references a leaf/intermediate chain. Joining its leaf to X.509 yields an ECDSA public key, consistent with the cipher authentication type. All checked TLS cipher/leaf-key combinations agree. Files SHA-1 values agree with corresponding X.509 fingerprints, and represented adjacent chain issuer/subject names agree.

HTTP shows meaningful proxy error variation. Core CONNECT responses include 2,065 successes, 47 policy denials, 45 authentication challenges, 19 service-unavailable, 16 bad-gateway, and ten gateway-timeout results. GET responses include redirects, conditional 304 responses, and partial-content 206 responses. These are plausible operational distinctions. The short-duration concentration described above remains the principal network-only concern, tempered by the possibility of an explicit proxy connection policy.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | DMZ Zeek conn/SSL | 2,264 established proxy-to-external TLS/443 sessions; 78.9% last 0.8–5 seconds; no sessions exceed 120 seconds | Modest upward pressure: unusually concentrated connection lifetimes, but proxy policy could explain them |
| weak_signal | Core and DMZ Zeek HTTP | Large Chrome/120 and Firefox/121 populations alongside Mac Chrome/155 | Small upward pressure: resembles a narrow version pool, while managed platform cohorts remain plausible |
| No demonstrated hard contradiction | Zeek protocol and connection joins | All three sensors | Limits the score: tested timing, tuples, TLS visibility, key types, and body/certificate byte bounds remain coherent |

## Realism Score by Category

- **Field format accuracy:** 9 — Valid structured protocol fields, coherent DNS types, TLS keys, fingerprints, and byte bounds in the checks performed.
- **Temporal patterns:** 7 — Uneven activity and plausible protocol ordering; proxy TLS lifetimes have a suspicious concentration.
- **Cross-source correlation:** 9 — Protocol UIDs, tuples, and visible transport intervals agree; no tested impossible ordering.
- **Behavioral realism:** 8 — Plausible service separation, infrastructure protocols, proxy failures, and varied flow outcomes; browser version variety is limited.
- **Environmental consistency:** 8 — Sensor-specific traffic profiles and explicit proxy/NAT context form a coherent observation model.

## Recommendations

- If this were synthetic, derive proxy connection reuse and lifetime from destination, client application, and an explicit proxy policy. Recheck the observed 0.8-second floor, 78.9% concentration below five seconds, and lack of proxy TLS sessions longer than two minutes against that policy.
- If this were synthetic, make browser version distributions reflect host-specific managed cohorts and update histories, rather than relying on the small version vocabulary visible here. Preserve stable versions on managed hosts where justified.
- Preserve the demonstrated TLS 1.3 visibility limits, resumed-handshake behavior, certificate-key matching, and DNS/proxy sequencing. These checks found coherent evidence and do not warrant changes merely to introduce imperfection.
