# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 92
**Synthetic-Confidence Score:** 82

## Executive Summary

The network corpus is unusually strong in Zeek field shape, UID integrity, multi-sensor agreement, DNS variety, and TLS/X.509 semantics. I nevertheless assess it as synthetic because independent HTTP and TLS populations contain sharp, repeated timing constants—especially exact 0.600-second HTTP asset spacing and a broad 1.200-second TLS duration mode—while UDP syslog flows exhibit source-port churn and missing duration behavior that do not resemble packet-derived telemetry.

## Evidence For Synthetic

- `[distribution_texture]` In `zeek-core/http.json`, 33 of 78 consecutive transactions on multi-transaction UIDs are separated by 0.600 seconds to microsecond precision. For UID `CzDS0E0ejZBWlN2skne`, transactions 2 through 7 occur at `12:40:24.389005`, `12:40:24.989004`, `12:40:25.589004`, `12:40:26.189004`, `12:40:26.789004`, and `12:40:27.389004` UTC. The same fixed cadence recurs on unrelated page loads and is independently visible in `zeek-dmz/http.json`.
- `[distribution_texture]` In `zeek-dmz/conn.json`, 113 of 2,045 SSL-classified connections fall within two milliseconds of exactly 1.200 seconds. The mode spans unrelated inbound and outbound endpoints, TLS versions, and byte volumes: `10.10.3.20 -> 54.230.129.181` has 11,535 response bytes and duration `1.200512` at `12:04:21.938184`, while `98.0.66.118 -> 10.10.3.10` has 390,614 response bytes and duration `1.200278` at `12:07:11.069023`. No common network timeout plausibly explains the same narrow duration across both populations.
- `[schema_or_format]` `zeek-core/conn.json` contains 192 UDP syslog rows with two to five originator packets but no `duration` field. For example, UID `CVSGTrtAPORovtcaWA` at `12:04:47.943792` records 2,462 originator bytes in two packets, and UID `CQOawPGBUGiaZOPgCW` at `12:10:40.188145` records 2,853 bytes in three packets; both have `history:"D"`, `conn_state:"S0"`, and no duration. Repeated multi-packet datagrams cannot all be packet-capture-coincident across this many flows.
- `[distribution_texture]` UDP syslog socket behavior is also too stateless. Every repeated source/destination series inspected uses a new ephemeral source port for every row: `10.10.1.36 -> 10.10.2.40` has 15 rows and 15 source ports, `10.10.2.20 -> 10.10.2.40` has 13/13, and `10.10.4.10 -> 10.10.2.40` has 7/7. Production syslog daemons normally retain a socket/source port across many messages, even when Zeek later splits idle UDP pseudo-connections.
- `[distribution_texture]` Public DNS answer structure lacks a normal alias-chain long tail. Across 663 successful public A-query rows in `zeek-core/dns.json`, representing 360 unique queried names, every answer is one to three IPv4 addresses and none contains a CNAME. This is implausibly uniform for the visible mix of cloud, CDN, update, collaboration, and SaaS names.
- `[weak_signal]` Six HTTP response FUID references have no corresponding `files.json` record across the core and DMZ sensors, including core FUID `FPTCwlQQcSTgz2SjS` at `14:14:50.374561` and DMZ FUID `FNdzYDi7TNu9JdNk3v` at `17:18:16.893866`. Selective file-log filtering or loss could explain this small gap, so it had little effect on the verdict.

## Evidence For Real

- The connection-state mix is credible for the apparent topology. Core has 8,543 `SF`, 1,933 `S0`, 144 `RSTO`, 77 `RSTR`, 32 `REJ`, and smaller `OTH`/`S1`/`S2`/`S3` populations; DMZ has 4,781 `SF` and 2,583 `S0`. The elevated DMZ `S0` rate is explained by visible Internet scanning and a rapid internal `/24` sweep rather than being uniformly spread across benign traffic.
- Internet background noise is irregular and source-specific. For example, `185.220.233.25` makes 175 unanswered attempts to five web-facing ports over almost six hours, while `185.220.88.13` concentrates on Windows administration ports and `185.220.163.140` on database/cache ports. Interarrival times are highly variable rather than fixed.
- DNS has a realistic protocol and error mix: core contains 2,050 A, 252 AAAA, 131 PTR, 97 SRV, 336 TXT, and six MX/NS/SOA records, with 217 NXDOMAIN, 21 SERVFAIL, and five REFUSED responses. Visible `wpad`, `isatap`, stale-host, suffix-appended, and reverse-lookup failures are characteristic enterprise residue.
- DNS transport accounting is coherent. All 2,873 core DNS rows resolve to a `conn.json` UID; request/response tuples match; DNS RTT tracks the associated UDP connection duration; and successful AAAA NODATA responses are represented with `NOERROR` and no answers rather than incorrectly forced to NXDOMAIN.
- TLS behavior is source-aware. DMZ traffic is 1,279 TLS 1.3 versus 645 TLS 1.2 sessions with modern AES-GCM and ChaCha20 suites, while internal/database paths retain more TLS 1.2 and CBC. TLS 1.3 sessions appropriately lack passively visible certificate chains, whereas non-resumed TLS 1.2 sessions carry them.
- Certificate relationships are internally sound. Across all joined SSL/X.509 records, I found no leaf-to-intermediate issuer mismatch, no certificate outside its validity period, and no SNI/SAN mismatch. Reused certificates retain stable fingerprints and metadata across sessions and sensors.
- Cross-source timing and identity are strong without visible impossible ordering. Every DNS, HTTP, SSL, SMTP, SMB mapping, and SMB file UID tested had a parent connection, and no child record preceded its connection or appeared after its close. No overlapping reuse of an identical TCP five-tuple was found.
- Multi-sensor observations resemble separate clocks rather than copied rows. There are 3,896 core/DMZ five-tuple matches within two seconds with distinct Zeek UIDs, mostly identical byte accounting, and an approximately 114 ms sensor offset with small variation. Core/database observations show a different approximately 63 ms offset and occasional plausible `missed_bytes` differences.
- DHCP renewals show stable identity and lease-aware jitter. Six clients retain consistent address/MAC/hostname mappings, and renewals occur near T1 for 3,600-, 7,200-, and 14,400-second leases rather than on one universal interval.

## Detailed Analysis

### Scope and traffic profile

The Zeek telemetry covers approximately `2024-03-18 12:00:32` through `17:59:53` UTC. I counted 10,794 core, 7,588 DMZ, and 427 database connection rows. Core traffic is split among TCP (5,532), UDP (4,866), and ICMP (396), with DNS, Kerberos, HTTP/proxy, LDAP, SMB, TLS, syslog, SSH, DHCP, SMTP, and RDP all visible. The service placement is coherent from the logs alone: `10.10.2.10/11` act as DNS/Kerberos/LDAP infrastructure, `10.10.3.20` as a forward proxy, `10.10.3.10` as the public web tier, `10.10.4.10` as a MySQL system, and `10.10.2.40` as a logging/monitoring destination.

State transitions and packet accounting generally pass basic network checks. TCP `SF` rows normally carry bidirectional packet counts and plausible histories such as `ShADadfF`; unanswered scans use `S0`/`S`; rejects use `REJ`/`Sr`; and no negative byte or packet fields were found. I found no overlapping identical five-tuple lifetimes and no source-port reuse that would require two simultaneous identical TCP sockets.

The visible internal sweep from `10.10.3.10` is operationally credible: 1,482 core `S0` rows span 253 targets and ICMP plus TCP ports 22, 80, 443, 445, and 3306 between `13:40:13.258284` and `13:40:34.722688`. That compactness is not itself an authenticity defect; it is compatible with a fast scanner. External scanners likewise show uneven timing and distinct port preferences.

### Temporal behavior

At coarse scale, hourly volume is believable: core connection counts are 1,424, 2,974, 1,480, 1,444, 1,850, and 1,622 across the six UTC hours, with the 13:00 UTC peak explained by the visible sweep. SSH durations range from fractions of a second to more than 13,000 seconds, RDP sessions extend into thousands of seconds, and LDAP/SMB/MySQL durations have broad distributions.

At fine scale, however, the HTTP and TLS timing distributions expose templates. Only 33 core UIDs contain multiple HTTP transactions, yielding 78 consecutive transaction intervals; 33 intervals are exactly 0.600 seconds within 0.0001 seconds. These are not periodic API polls: the records are browser assets such as JavaScript bundles, CSS, favicon, SVG, JPEG, and WebP objects on unrelated page loads. A real browser waterfall would show concurrency, TCP/application scheduling variance, response-size dependence, and heterogeneous think time rather than the same serial 600 ms step.

The TLS duration spike is broader in scope. The 113 DMZ SSL connections within `1.198-1.202` seconds include 72 local-to-external, 40 external-to-local, and one internal connection; 108 are TLS 1.2 and five are TLS 1.3. Response payloads range from a few kilobytes to hundreds of kilobytes. Sensor jitter around a shared canonical close time explains the tiny residuals but not why unrelated applications and directions share that canonical 1.200-second lifetime.

### DNS

The DNS content is one of the strongest realistic areas. Internal authoritative answers use sensible private addresses and TTLs, SRV replies list both directory servers, and public recursive replies include varied residual TTLs. NXDOMAINs include `wpad`, `wpad.local`, `isatap`, stale internal names, suffix-appended public names, random-looking failed domains, and failed PTRs. The TXT burst from `10.10.2.30` beginning around `16:45:09` has varied subdomain labels, short TTLs, positive responses, SERVFAIL, REFUSED, and NXDOMAIN outcomes consistent with a DNS application channel rather than a single repeated canned query.

The main DNS authenticity problem is structural diversity. Of 663 successful non-local A queries at the core sensor, 335 have one IPv4 answer, 324 have two, and four have three; zero include an alias. The DMZ independently shows the same absence across 594 public A responses. Domain sanitization would explain changed labels, but it would not ordinarily remove every CNAME RR from hundreds of answer sections while retaining terminal IPs and TTL arrays.

### HTTP and proxy behavior

The proxy topology is convincing. Core HTTP is dominated by 1,190 CONNECT transactions, while direct cleartext HTTP is concentrated on internal web browsing, OCSP/CRL retrieval, and update traffic. Successful CONNECT responses use status 200 with zero body; 403, 407, 502, 503, and 504 failures carry bounded HTML bodies and corresponding MIME/FUID fields. Body lengths remain within connection byte accounting once visible `missed_bytes` are considered.

Application vocabulary is also diverse: 37 user-agent strings appear on internal proxy traffic, including browsers, OS update components, security clients, package managers, and language runtimes. Persistent internal HTTP connections correctly increment `trans_depth`, and response FUIDs generally resolve to file records with matching direction and size. These details make the fixed 0.600-second asset scheduling more conspicuous because it cuts across otherwise realistic request construction.

### TLS, certificates, and OCSP

The protocol-version and cipher distributions fit a mixed enterprise. DMZ has a majority of TLS 1.3 using `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, and `TLS_CHACHA20_POLY1305_SHA256`, plus TLS 1.2 ECDHE RSA/ECDSA suites. Core and database segments retain older TLS 1.2 CBC use on internal services. Resumed sessions omit chains, TLS 1.3 passive observations omit encrypted certificates, and visible TLS 1.2 chains connect leaf issuer to intermediate subject correctly.

There are 185 unique X.509 fingerprints in the DMZ log, reused consistently by SNI. Validity windows cover the observation time, SANs cover the logged SNI, and internal enterprise certificates chain to a stable enterprise issuing CA. OCSP records use file IDs linked to HTTP OCSP response objects, with plausible `thisUpdate`/`nextUpdate` windows. I found no certificate hard contradiction.

### Syslog transport and collection behavior

The UDP syslog rendering is the weakest source-native family. Core has 249 service-identified syslog flows. Of these, 192 contain two to five datagrams yet omit duration, even though their aggregate payload and IP-byte fields explicitly model multiple packets. The exact identity `orig_ip_bytes - orig_bytes = 28 * orig_pkts` shows that these are intended as distinct UDP packets, not one oversized logical message.

The tuple lifecycle is also implausibly disposable. Hosts repeatedly send to `10.10.2.40` and `10.10.2.21`, but every pseudo-connection gets a fresh source port. A long-running rsyslog/syslog-ng/NXLog-style sender ordinarily reuses a UDP socket; after Zeek's inactivity timeout, later records may receive new UIDs but retain the source port. The combination of packet aggregation, absent duration, and per-row port allocation looks like event-to-flow synthesis rather than passive flow observation.

### Cross-sensor consistency and bounded-window considerations

Core, DMZ, and database sensors use independent UIDs and distinct clock offsets while preserving five-tuples, service identity, byte counts, and packet histories on shared paths. Protocol logs remain inside their parent connection intervals, and long-lived SSH/RDP connections are not penalized for potentially crossing the bounded window. I found no visible dependent event whose same-identifier initiator occurs later.

The dataset includes credible imperfections: nonzero `missed_bytes`, small packet-accounting differences across sensors, and six unresolved HTTP FUIDs. Those imperfections are production-like and prevent me from treating high correlation as evidence of synthesis. They do not, however, explain the repeated exact timing constants or the UDP syslog socket model.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the synthetic-confidence score |
|---|---|---|---|
| `distribution_texture` | Zeek HTTP | 33 of 78 within-UID transaction gaps; repeated across core and DMZ | Exact 0.600-second serial asset scheduling is a strong generator-like timing fingerprint. |
| `distribution_texture` | Zeek conn/SSL | 113 of 2,045 DMZ SSL flows within ±2 ms of 1.200 seconds | The same close-time mode spans unrelated directions, endpoints, protocols, and byte volumes. |
| `schema_or_format` | Zeek conn/syslog | 192 multi-packet core syslog flows | Multiple modeled UDP packets systematically have no duration, weakening packet-derived plausibility. |
| `distribution_texture` | Zeek conn/syslog | Repeated across many senders and two collectors | Every row receives a new ephemeral source port instead of showing persistent sender sockets. |
| `distribution_texture` | Zeek DNS | 663 successful public A responses / 360 unique core names | Zero CNAME-bearing answer sections removes an expected public-DNS long tail. |
| `weak_signal` | Zeek HTTP/files | Six unresolved FUIDs | A small reference gap exists, but filtering or collection loss is a credible alternative explanation. |

## Realism Score by Category

- **Field format accuracy:** 9 — Zeek field names, types, histories, UIDs, TLS fields, X.509 chains, and protocol records are overwhelmingly source-native and valid.
- **Temporal patterns:** 4 — Coarse activity and session lengths are good, but exact 0.600-second HTTP spacing and the 1.200-second TLS mode are strong synthetic fingerprints.
- **Cross-source correlation:** 9 — Protocol children, connection parents, certificates, files, and multi-sensor views align with only minor explainable gaps.
- **Behavioral realism:** 7 — Scanning, proxying, directory traffic, web use, DNS tunneling, DHCP, and lateral-service activity are plausible, while browser waterfalls and syslog socket behavior are not.
- **Environmental consistency:** 8 — Host roles, routing, service placement, sensor visibility, and protocol mix form a coherent enterprise topology.

## Recommendations

- If this were synthetic, generate HTTP page loads from a browser-style waterfall model: allow parallel connections or streams, vary dependency discovery and response completion by object size/RTT, and eliminate the universal 0.600-second serial asset step.
- Derive TLS connection close time from handshake latency, transfer size/rate, connection reuse, application think time, FIN behavior, and idle timeout. Avoid a shared 1.200-second default across inbound web clients, proxy-origin flows, and internal TLS.
- Model UDP syslog as a sender socket lifecycle. Reuse source ports per host/process, let Zeek idle timeout split pseudo-connections naturally, and assign nonzero packet spacing/duration whenever a row contains multiple datagrams.
- Preserve realistic public DNS answer sections, including CNAME chains, varying chain depth, mixed one/many terminal addresses, and TTL arrays aligned with every returned RR.
- When file-log observation drops a record, either omit the corresponding HTTP FUID from the rendered view or model/document a coherent source-local collection-loss mechanism so references do not appear selectively orphaned.
