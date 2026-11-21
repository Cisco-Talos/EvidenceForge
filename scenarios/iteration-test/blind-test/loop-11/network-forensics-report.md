# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 74
**Synthetic-Confidence Score:** 62

## Executive Summary

The network telemetry is largely coherent, with credible protocol diversity, internally consistent byte counts, and sensible DNS, TLS and proxy relationships. I judge it likely synthetic primarily because repeated observations of the same HTTP file transfer have materially different file durations across sensors even where the enclosing connection durations and packet counts agree extremely closely. This is a bounded timing-consistency finding, not a claim that the overall intrusion sequence or collection completeness is suspicious.

## Evidence For Synthetic

- [contract_gap] The same visible HTTP upload has inconsistent transfer intervals in `zeek-core/files.json` and `zeek-dmz/files.json`. At 2026-11-02 16:32:14 UTC, file `mhs-support-48217.tar.gz`, 1,572,864 observed bytes, travels from `10.10.1.21:34585` to `10.10.3.20:8080`. Core FUID `FvMxR8meMayuRb9AdJ` has `ts=1793637134.577101`, `duration=9.723180`; DMZ FUID `FPqgyRXqG8Wcz1Ko8M` has `ts=1793637134.524511`, `duration=10.994234`. Both report zero missing/overflow bytes and no timeout. Their corresponding connections, `CKV0KbfYEdT7ejz0Bm` and `CBM3SEJ5mMbxKIJHe9`, have durations 19.649629 and 19.649788 seconds, identical directional packet counts (1,162/539), identical payload bytes (1,573,700/288), and zero missed bytes. A stable sensor clock offset can explain different absolute timestamps but does not explain a 1.271054-second difference in file duration within otherwise matching packet intervals.
- [contract_gap] This is repeated outside that upload. The 151,293,700-byte HTTP response on `10.10.2.11:64560 -> 10.10.3.20:8080`, SHA1 `b4a620828cdc65e254de3f32355f9150de6cb9d5`, appears at approximately 18:15:48 UTC with file durations 1.792268 seconds in core (`FwkFrcCDjNnOZRZrCTH`) and 2.344185 seconds in DMZ (`FKtLmNUS1UdWsXmNc3i`). Both sensors show zero file and connection loss, identical 34,542/111,527 packet counts, and enclosing connection durations 8.884730/8.884979 seconds. The 0.551917-second file-duration disagreement is substantially larger than the 0.000249-second connection-duration difference.
- [contract_gap] A broader pairing check found 266 HTTP file pairs with nonzero duration, matching endpoint four-tuples, direction, observed size, hash where present, and connection starts within one second. Of these, 43 file-duration differences exceeded 10 ms and 23 exceeded 100 ms; the median enclosing connection-duration difference was only 0.227 ms and its maximum was 1.624 ms. These are repeated measurements of common physical transfers, not separate proxied upstream/downstream connections. I count this as one recurring timing issue rather than three independent defects. Exporter buffering or differing file-analysis semantics remain possible explanations; packet captures and collector configuration were not supplied.

## Evidence For Real

- The three sensors contain distinct and credible traffic mixes: core has extensive DNS, Kerberos, LDAP and SMB; the DB sensor is dominated by MySQL; the DMZ sensor includes substantial HTTPS, HTTP proxy and unsuccessful inbound traffic. This is compatible with the host addresses and service roles visible in the logs.
- Every one of the 4,352 DNS, 5,625 HTTP and 3,756 SSL records has a local connection UID match, with matching endpoint tuples. Their timestamps fall within the corresponding visible connection intervals under the stated small checking tolerance. This supports consistency; completeness itself is not an authenticity indicator against the data.
- DNS includes A, AAAA, PTR, SRV, MX, NS, SOA and TXT queries, negative answers, failures, variable TTLs and substantial RTT variation. Core alone has 260 NXDOMAIN, 16 SERVFAIL and one REFUSED response among 3,165 records.
- TLS 1.3 rows do not expose certificate-chain FUIDs; TLS 1.2 resumed rows also omit those chains. Visible certificate keys agree with their RSA/ECDSA cipher authentication choices. Repeated certificate fingerprints retain consistent certificate metadata.
- Byte accounting checks found no HTTP bodies or directional HTTP file observations exceeding their associated TCP payload bytes, no impossible minimum DNS question lengths, and no TCP five-tuple overlap within a sensor under the conservative check used here.
- Long SSH and RDP sessions coexist with short service traffic, failed SYNs, resets, partial sessions, retransmission histories and sensor loss. The data is not simply a set of identical successful connections.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory. I parsed all JSON records in the three `zeek-*` directories, checked associated HTTP/file/certificate/OCSP records, and inspected the firewall, proxy and Snort source shapes and alert distributions. Network connection starts span approximately 2026-11-02 13:00–18:59 UTC. Totals are observations per sensor, not a count of unique network transactions: overlapping sensors see some of the same traffic.

| Sensor | Connections | DNS | HTTP | SSL | Files |
|---|---:|---:|---:|---:|---:|
| zeek-core | 12,434 | 3,165 | 2,644 | 438 | 704 |
| zeek-dmz | 10,347 | 1,140 | 2,948 | 3,292 | 1,986 |
| zeek-db | 413 | 47 | 33 | 26 | 30 |

I did not infer authenticity from filesystem timestamps, domain registration or resolution, missing Sysmon families, absent out-of-window lifecycle events, or the narrative shape of suspicious activity.

### Connections, state and packet accounting

Core contains 7,029 TCP, 4,952 UDP and 453 ICMP observations. Its connection states include 9,993 SF, 1,636 S0, 477 OTH, 155 RSTO, 89 RSTR and smaller REJ/S1/S2/S3 populations. DMZ has 2,311 S0 observations among 10,347 connections, consistent with the visible rejected/unanswered traffic against several services; this concentration is not evidence of artificiality by itself. The DB sensor has 242 TCP/3306 connections and a median duration around 2.703 seconds for that port.

For loss-free observations, the aggregate IP-byte counts cover reported payload plus minimum network/transport headers. All rows also pass basic nonnegative packet/payload relationships. DNS request sizes accommodate the logged question names. I found no established TLS row associated with an S0 or REJ connection. These are conservative consistency checks rather than a reconstruction of individual packets.

SSH example core UID `CkZB5oIxcFRXBCT6lH` is `10.10.1.35:59751 -> 10.10.2.30:22`, starts at `1793624411.856262`, and lasts 3,635.624092 seconds with 25,172 originator and 179,205 responder bytes. RDP example `CDRgfepU9iLGuDy1R0m`, `10.10.1.31:64451 -> 10.10.2.10:3389`, lasts 3,402.060158 seconds. These differ appropriately from short authentication/database transactions. I do not penalize a connection for extending beyond the final connection-start timestamp or the collection boundary.

### DNS behavior

Core's type distribution is A 2,381; AAAA 298; TXT 207; PTR 162; SRV 102; MX 7; NS 6; SOA 2. Its median RTT is 3.419 ms, versus 18.401 ms in DMZ and 1.103 ms in DB. The ranges include submillisecond internal replies and responses longer than two seconds. Common internal TTLs of 300, 1,800, 3,600 and 86,400 seconds coexist with shorter external/cache values and 1-second TXT answers.

For example, the first core DNS record, UID `Cy7bKJVXGBLSw4N5M0b`, queries `_ldap._tcp.meridianhcs.local` from `10.10.1.31` to `10.10.2.10` at `1793624402.649837`, reports both DC names and a 1.111 ms RTT, and matches its UDP connection. The file-server discovery at `1793624405.271397` includes a NOERROR AAAA response without answers, a plausible IPv4-only result. The TXT sequence around `1793641501.671874` has long varying subdomains, variable RTTs, short TTLs and occasional SERVFAIL; this is suspicious network behavior but not in itself synthetic evidence.

I did not require a fresh DNS query before every connection because caching, proxies, literal addresses and pre-window state can legitimately remove that requirement.

### HTTP, proxies and file timing

CONNECT dominates HTTP: core has 2,318 successful CONNECT transactions, while DMZ has 2,367. There are also 403, 407, 502, 503 and 504 CONNECT responses. This makes the large HTTP count compatible with a modern TLS-heavy network using an explicit HTTP proxy; it should not be read as thousands of cleartext browsing sessions.

The initial proxy-access entry at 13:00:17 describes a cleartext GET, while the following 13:01:41 CONNECT to `pypi.org:443` distinguishes control-message byte scope from tunneled byte counts. Client-to-proxy and proxy-to-server connections have different tuples and UIDs, as expected. Directional upload accounting is also correct: a file marked `is_orig=true` must be compared with originator payload, not responder payload. The 1.5 MiB upload above passes that check.

The material concern is the file interval, not its size or UID. For the 16:32 upload, subtracting the connection-start timestamp from each file timestamp gives approximately 0.181 and 0.241 seconds. Adding the file durations yields file completion at approximately 9.904 and 11.235 seconds after their respective connection starts: a roughly 1.33-second disagreement that remains after removing the sensor clock offset. The enclosing connections differ by only 0.159 ms in duration and share the packet accounting. Similar disagreements recur for fully observed large response files. This suggests file timing was assigned independently of the common transport timeline, although different collector/file-analyzer behavior cannot be conclusively excluded from logs alone.

No checked file interval extended beyond its connection close by more than the 10 ms tolerance used in that check. This limits the finding: the data has coherent broad ordering but inconsistent finer-grained repeated observations.

### TLS, certificates and infrastructure

DMZ SSL contains 2,131 TLS 1.3 and 1,159 TLS 1.2 rows, plus two rows without a negotiated version. Ciphers include AES-GCM, ChaCha20-Poly1305 and a smaller TLS 1.2 CBC population. Core has a larger internal-service share; DB is predominantly TLS 1.2. These differences are plausible for the visible service roles.

Core UID `CLuJRjRrOybfV1vBtC` connects to `LOG-MON-01.meridianhcs.local`, negotiates TLS 1.2/ECDHE-RSA/AES-256-GCM and references an RSA-2048 internal-CA certificate. The DB sensor independently observes the same log-monitoring certificate identity consistently. OCSP rows have ordered update intervals and do not claim `thisUpdate` later than observation time in the checked records. I found no certificate fingerprint describing conflicting serials, keys, subjects or validity intervals.

The Snort files contain 97 perimeter and 65 core alerts, including DNS TLD policies, user-agent policies, scans, P2P and ICMP signatures. These are plausible alert categories, but signatures without packets provide limited independent authentication. The six-hour daytime slice does not justify conclusions about overnight traffic or weekly business cycles, and absent QUIC or other optional source families is not scored.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| contract_gap | Zeek HTTP files versus connection observations at core/DMZ | 23 of 266 matched file pairs differ in duration by over 100 ms; concrete loss-free examples differ by 0.55–1.27 seconds while their connection durations differ by fractions of a millisecond | Primary reason for a score just inside the likely-synthetic band; suggests independently assigned file timing |

This is one recurring mechanism. I found no demonstrated generator identity leak, impossible TLS cipher/certificate combination, impossible DNS question size, overlapping live TCP tuple, or impossible payload-versus-IP-byte relationship. Collector behavior could explain part of the timing issue, so a very high synthetic score would overstate the evidence.

## Realism Score by Category

- **Field format accuracy:** 9 — Consistent parseable source shapes, plausible protocol fields and certificate/cipher combinations.
- **Temporal patterns:** 6 — Broad session and protocol ordering is coherent, but repeated file-duration discrepancies weaken fine timing fidelity.
- **Cross-source correlation:** 7 — Strong tuple, UID, body-size and certificate alignment; common physical file transfers have inconsistent measured intervals.
- **Behavioral realism:** 9 — Varied states, failures, service durations, proxy outcomes and DNS behavior fit the visible network roles.
- **Environmental consistency:** 9 — Core, DMZ and DB traffic distributions support differentiated collection points and host functions.

## Recommendations

- If this were synthetic, derive each HTTP file's first/last observed-byte times from a common transfer timeline shared by sensors. Apply sensor clock and observation effects coherently to that timeline and the enclosing TCP connection.
- If this were synthetic, validate same-transfer file intervals across sensors using tuple, direction, size and content hash, explicitly distinguishing repeated physical observations from separate proxy legs. Include the 16:32 upload and 18:15 MSI response as regression examples.
- If the supplied export intentionally changes file-analyzer timing, retain collector/version or transformation metadata explaining those semantics. That would allow an assessor to distinguish a representation effect from a network-timing defect without assuming missing telemetry.
