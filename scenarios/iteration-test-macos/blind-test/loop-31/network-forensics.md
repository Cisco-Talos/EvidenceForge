# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 84
**Synthetic-Confidence Score:** 64

## Executive Summary

The network evidence is largely coherent, with plausible protocol diversity, connection lifetimes, proxy behavior, and certificate handling. My synthetic verdict rests on a repeated source-native contradiction in TCP syslog connection records: the responder-data history flag occurs alongside zero responder payload bytes. This is a localized but reproducible defect; I did not find broad failures in UID integrity or protocol timing, and a faulty exporter remains a possible real-data explanation.

## Evidence For Synthetic

- [hard_contradiction] TCP syslog rows claim observed responder payload in `history` while setting `resp_bytes=0`. For example, `zeek-core/conn.json:209`, UID `CLRAOqVlQrrMmo1c4A`, at `1793625001.347807` (2026-11-02 13:10:01.347807 UTC), describes `10.10.2.30:50779 -> 10.10.2.40:514`, `proto=tcp`, `conn_state=SF`, `history=ShADadfF`, `orig_bytes=3497`, `resp_bytes=0`, and `missed_bytes=0`. Lowercase `d` denotes responder data, not a pure acknowledgment. A unidirectional syslog payload is plausible; reporting responder data and zero responder payload in the same flow is the defect.
- [hard_contradiction] This repeats in 44 core-sensor rows and 9 database-sensor rows, all TCP destination port 514; 42 and 8 respectively also report `missed_bytes=0`. Examples include `zeek-core/conn.json:250` (`2557/0` payload bytes, `ShADadfF`) and `:345` (`3820/0`, `ShADadFf`), and `zeek-db/conn.json:86` (`4342/0`, `ShADadfF`). These are one defect family, not independent indicators or 53 independent flows: some rows are observations of the same traffic at different sensors.
- [hard_contradiction] The same issue affects a failed/reset syslog connection, so it is not confined to one normal-close history spelling. `zeek-core/conn.json:10352`, UID `CVe4VF0U1b3qoMSST0`, at `1793642982.633141`, reports `10.10.4.10:56689 -> 10.10.2.40:514`, `RSTR`, `history=ShAdr`, `orig_bytes=0`, `resp_bytes=0`, `missed_bytes=0`. Its database-sensor counterpart is `zeek-db/conn.json:339`, UID `CKFEUepgFR04gudOOe`, with the same tuple and counters. The responder data flag again contradicts the payload accounting.

## Evidence For Real

- Flow/protocol identities are consistent. All 4,002 DNS, 2,947 SSL, and 4,573 HTTP rows reference a connection UID present on their own sensor. Tests found no protocol timestamp outside its connection interval using a 0.2-second tolerance.
- DNS is varied rather than A-only: the core sensor has 242 AAAA, 144 PTR, 105 SRV, and 290 TXT records in addition to 2,233 A records. It includes NOERROR, NXDOMAIN, SERVFAIL, and REFUSED responses; `zeek-core/dns.json:16` queries `wpad` unsuccessfully, while `:2` supplies domain-controller SRV records.
- TLS handling reflects visibility differences between protocol versions. No TLS 1.3 row references certificate FUIds; TLS 1.2 rows do. Every referenced certificate FUID resolves locally, and visible TLS 1.2 RSA/ECDSA cipher authentication agrees with the linked leaf certificate key type.
- `zeek-dmz/ssl.json:50` records a nonresumed TLS 1.2 ECDSA session to `cdn.newrelic.com` with certificate FUID `FLOSP2hZeHkUS9Ji8q`; the linked certificate has an ECDSA key. Conversely, resumed TLS sessions can omit certificate references, as in `zeek-db/ssl.json:1`.
- The data contains successful, unanswered, rejected, reset, half-closed, and midstream TCP observations, with long-lived SSH/RDP sessions and much shorter DNS transactions. This is more convincing than a successful-connection-only corpus.
- The first DMZ TCP scan observation, `zeek-dmz/conn.json:1`, is a zero-payload SYN to port 8080 with `S0/history=S`. `fw-perimeter/cisco_asa.log:1` records its build at 13:00:06, and `:3` records a 30-second SYN timeout at 13:00:36. These observations have compatible meanings.

## Detailed Analysis

### Scope and method

I examined only the supplied data. The three Zeek directories contain 21,473 connection records covering approximately 2026-11-02 13:00–19:00 UTC: 11,927 core, 379 database, and 9,167 DMZ rows. I parsed all of their JSON records and checked protocol references, timestamps, counters, certificate references, and file-to-flow relationships, then inspected representative firewall and proxy rows. Line references are one-based physical lines in the named data files.

The bounded window limits conclusions about overnight activity and session initiators or closures beyond the edges. Different sensor UIDs for the same traffic are expected. I did not treat sanitized domain names, completeness of collection, or attack-sequence neatness as authenticity evidence.

### Connection state and byte accounting

Core states include 9,774 SF, 1,837 S0, 134 RSTO, 95 RSTR, and 28 REJ records. DMZ states include 6,178 SF and 2,771 S0 records, consistent with a noisier exposed segment. Database traffic has 236 connections identified as MySQL and a smaller number of administrative and infrastructure flows. These differences fit the visible placement of the sensors.

Packet accounting generally passes useful bounds: no direction has positive payload bytes with zero packets, no IP-byte counter is below its payload counter, and the checked TCP records without retransmission/gap history do not require impossible header overhead. This makes the syslog history defect particularly specific. The payload values can represent legitimate one-way syslog; the history string incorrectly supplies a responder-data observation.

There are 82 TCP/514 connections on core and 21 on the database sensor. Of these, 61 and 12 respectively have zero responder payload. The contradictory lowercase `d` appears in 44 and 9 of those rows. The core contradictions span 39 SF, 4 RSTR, and 1 S2 records; database contradictions span 7 SF and 2 RSTR records. Therefore, this is a repeated protocol-field consistency failure, not merely one unusual session. Counts across sensors must not be added as independent network activities.

A production exporter or transformation bug could produce this same artifact. I therefore place the score in the lower part of the “likely synthetic” range, rather than claiming dataset-wide impossibility.

### DNS and connection causality

I found no DNS response RTT exceeding the corresponding connection duration by more than 1 millisecond, and answer/TTL list lengths agree throughout. Internal SRV responses identify two domain controllers; internal AAAA queries can return no answer, while public AAAA responses contain IPv6 addresses. NXDOMAINs include short-name and suffix-search-like requests.

A representative explicit-proxy chain is visible near 13:01:30 UTC. `zeek-dmz/http.json:1` records a CONNECT request to `20-205-195-86.microsoft.com:443`; `zeek-dmz/dns.json:1` records the proxy resolving that name, with `rtt=0.086179`; and `zeek-dmz/ssl.json:1` records the subsequent outbound TLS session at `1793624491.182604`, with matching SNI and the DNS answer `23.72.51.162`. The proxy access log's first row reports the corresponding CONNECT transaction. I regard this as coherent; I do not require the client itself to resolve an origin reached through an explicit proxy.

### TLS, certificates, HTTP, and files

TLS versions and suites are compatible in the inspected corpus. Core includes both TLS 1.2 and 1.3; the database sensor's small TLS sample is TLS 1.2; DMZ traffic is predominantly TLS 1.3. Certificate identity is stable: a repeated fingerprint does not change subject, serial, validity start, or key length in these records. No observed certificate falls outside its stated validity period.

The absence of certificate references on TLS 1.3 sessions is appropriate for an ordinary passive sensor. Certificate references on TLS 1.2 resolve to the local X.509 records, and leaf key types agree with cipher authentication. For example, `zeek-db/x509.json:1` has the same fingerprint and internal certificate identity as `zeek-core/x509.json:1`, while using a sensor-local FUID.

Most visible HTTP is explicit CONNECT traffic; that explains why the HTTP count cannot be read as a direct measure of unencrypted origin browsing. CONNECT outcomes include 200, 403, 407, 502, 503, and 504. Across all HTTP records, request/response body lengths remain within their respective TCP payload totals, and 304 responses do not claim nonzero response bodies.

I also checked all 2,210 file rows. None was timestamped outside its referenced connection interval by more than 0.2 seconds. For single-connection files, no individual observed file exceeded that flow's payload counter in its stated direction. `zeek-core/files.json:1`, for example, records an SMB spreadsheet transfer tied to UID `CHobQaXTd62NpmDvAm`; `zeek-core/smb_mapping.json:1` and `smb_files.json:1` provide compatible share and file-path evidence.

### Temporal and environmental interpretation

The observed window is only six daytime hours. Core connection counts range from 1,428 to 3,087 per UTC hour, and DMZ counts from 1,121 to 2,624; there is no exact flat-rate hourly pattern. I cannot infer a full business-day rhythm from this sample, and I do not penalize missing overnight or weekend behavior.

The long SSH durations, visible MySQL concentration at the database sensor, port-8080 explicit proxy, domain-controller DNS/SRV traffic, and external SYN probes form a plausible network environment. I found no sufficiently strong independent distribution or host-role defect to add to the score.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| hard_contradiction | Zeek TCP connection history and byte counters | 44 core and 9 database observations, all destination port 514; overlapping observations are not independent flows | Repeated responder-data flags with zero responder payload are the decisive synthetic indicator. |
| hard_contradiction | Same defect family, reset lifecycle variant | Core line 10352 and database line 339, same tuple | Shows the inconsistency persists in a reset/zero-payload shape; included in the preceding counts, not scored separately. |

## Realism Score by Category

- **Field format accuracy:** 7 — JSON and most native fields are plausible, but TCP syslog history contradicts payload counters repeatedly.
- **Temporal patterns:** 9 — Varied connection lengths and hourly volume; protocol timestamps and DNS RTT bounds are coherent within the visible window.
- **Cross-source correlation:** 9 — Local UIDs, certificate references, proxy chaining, file references, and representative firewall lifecycle agree.
- **Behavioral realism:** 9 — Plausible proxy-heavy browsing, infrastructure traffic, database activity, scans, and administrative sessions.
- **Environmental consistency:** 9 — Distinct core, DMZ, and database traffic profiles fit their visible network roles.

## Recommendations

- If this were synthetic, derive Zeek history from the same directional payload and lifecycle facts as the byte counters. One-way TCP syslog can have responder acknowledgments and FINs without lowercase `d`; zero-response reset shapes likewise must not assert responder payload.
- If this were synthetic, validate this relationship across every sensor observation and close state, including the `ShAdr` reset shape. Preserve legitimate one-way syslog payload accounting instead of adding fabricated response bytes solely to satisfy the history string.
- If this were real, inspect the exporter or normalization path for a TCP syslog history construction defect before drawing conclusions from these history flags.
