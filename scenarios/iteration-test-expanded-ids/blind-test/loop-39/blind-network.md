# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive  
**Verdict Confidence:** 76  
**Synthetic-Confidence Score:** 43

## Executive Summary

The network telemetry is source-native and internally coherent: 11,558 Zeek connections across a six-hour window have credible state/history, byte, protocol, DNS, TLS, file, and UID relationships, including consistent collection-loss artifacts. Two measurable distribution patterns prevent a Real verdict: all high-volume SMB and LDAP sessions terminate within 45 seconds, and unsolicited DMZ scanning is unusually concentrated into a small fixed source population.

## Evidence For Synthetic

- `[distribution_texture]` In `zeek-core/conn.json`, all 896 SMB connections are shorter than 45 seconds (maximum 44.710872 seconds), despite 861 successful sessions and 896 total observations over six hours. All 594 LDAP connections are likewise below 45 seconds (maximum 44.960180 seconds). The absence of any persistent or reused multi-minute SMB/LDAP channels creates a visible service-specific ceiling.
- `[distribution_texture]` Of 989 external-origin DMZ `S0` connections, only 14 source IPs are represented. Six sources account for 827/989 (83.6%): `37.75.195.175` (186), `145.78.103.167` (161), `45.33.74.51` (141), `38.186.148.245` (121), `74.172.69.175` (116), and `156.32.3.55` (102). The source specialization is conspicuous: some repeatedly probe Telnet/SSH, others Windows administration ports, and others mail ports.
- `[weak_signal]` For 1,923 exact cross-sensor five-tuple matches, the DMZ timestamp is always later than the core timestamp by 41.652–66.433 milliseconds. The hourly mean offset rises smoothly from 45.041 milliseconds in the first hour to 62.663 milliseconds in the sixth. This can represent genuine sensor clock drift, but its universal direction and exceptionally smooth progression look deliberately modeled.

## Evidence For Real

- Connection semantics are strong. Core states are `SF` 5,885/6,111, with realistic minorities of `RSTO` (84), `RSTR` (49), `REJ` (38), `S0` (23), and partial/other states. The DMZ appropriately differs because of unsolicited traffic: `SF` 4,037/5,447 and `S0` 1,182.
- State/history combinations are plausible and varied. Examples include `SF/ShADadfF`, `SF/ShADaDadfF`, `REJ/Sr`, `S0/S`, `RSTR/ShADadr`, and several retransmission/content-gap variants. No `S0` flow had response packets or bytes.
- Basic connection accounting was clean: no negative durations or byte counts, no IP-byte totals below payload-byte totals, and no successful TCP connection without response packets. Missing durations were confined to `S0` and `REJ`.
- All connection UIDs are unique within each sensor. Every DNS, HTTP, TLS, SMTP, DHCP, and file connection reference tested resolves to a local `conn.json` record.
- All 2,171 core and 773 DMZ DNS records occur within their referenced connection intervals. DNS contains a credible mix of A, AAAA, PTR, SRV, TXT, MX, NS, and SOA traffic, with 376 NXDOMAINs and 21 SERVFAIL/REFUSED responses. Suffix-search noise includes `wpad`, `isatap`, `oldserver`, and names with `.meridianhcs.local`.
- DNS timing shows cache-like behavior rather than mandatory lookup-before-every-flow behavior. Among DMZ TLS sessions with a local origin and resolvable SNI/address combination, 685 had a prior matching DNS answer, with intervals ranging from subsecond to multiple hours.
- TLS is modern but heterogeneous. DMZ TLS contains 1,142 TLS 1.3 and 550 TLS 1.2 sessions; core TLS is nearly even at 51 TLS 1.3 and 50 TLS 1.2. Cipher diversity includes AES-128/256-GCM, ChaCha20-Poly1305, RSA and ECDSA suites, plus a small CBC legacy tail.
- Certificate relationships are convincing. Checked leaf SANs match SNI, certificate validity brackets capture time, issuer/subject chains align, and both RSA and ECDSA material occur. Missing X.509 parser rows are coherently explained by corresponding `files.json` records with missing certificate bytes and absent analyzers—for example core UID `CopoQu6jSulEbeHjkG` at `2024-03-18T12:48:24Z`.
- Protocol timestamps are causally sound. Across both sensors, no DNS, HTTP, SSL, or SMTP record preceded its parent connection or appeared after its visible close.
- The explicit-proxy path is plausible. At `2024-03-18T12:02:11Z`, core HTTP UID `CSjmT8FTdUnutlVwWa` shows a client `CONNECT sdk.split.io:443` to `10.10.3.20:8080`, while the DMZ sensor observes the corresponding tuple independently with UID `CrIPAJbFdeF0IdnWkd`. Successful proxy-origin traffic produces predominantly TLS, while denied and gateway-error transactions terminate without requiring origin TLS.
- DHCP texture is credible: 69 REQUEST/ACK renewals, stable MAC/IP/hostname identity, lease times of 3,600, 7,200, and 14,400 seconds, and per-client renewal jitter rather than exact synchronized ticks.
- Long-lived interactive protocols exist where expected. Core SSH has a median duration of 1,158.79 seconds and a maximum of 15,209.02 seconds; RDP has a median of 1,820.33 seconds. This contrasts appropriately with short DNS, Kerberos, HTTP, and mail transactions.

## Detailed Analysis

### Scope and volume

The Zeek connection window spans `2024-03-18T12:00:10Z` through `2024-03-18T17:59:54Z`.

- Core: 6,111 connections, 2,171 DNS, 1,057 HTTP, 101 SSL, 82 X.509, 315 files, 69 DHCP, and 66 SMTP records.
- DMZ: 5,447 connections, 773 DNS, 1,228 HTTP, 1,692 SSL, 519 X.509, and 627 files records.
- Total principal records: 11,558 connections, 2,944 DNS, 2,285 HTTP, 1,793 SSL, 601 X.509, and 942 file observations.

Core hourly connection volume ranges from 859 to 1,216; DMZ volume ranges from 730 to 1,077. The variation is believable for a bounded daytime slice.

### Connection states and services

Core traffic is split between 3,165 TCP, 2,879 UDP, and 67 ICMP connections. Its service mix is infrastructure-heavy: DNS 2,182, HTTP 984, Kerberos 939, SMB 896, LDAP 594, SSH 112, DHCP 69, SMTP 67, SSL 61, and RDP 15.

DMZ traffic contains 4,596 TCP, 805 UDP, and 46 ICMP connections. The leading services are SSL 1,782, HTTP 1,168, DNS 776, MySQL 313, SSH 49, SMB 24, and LDAP 17.

Durations are protocol-sensitive:

- DNS median: 3.561 ms core and 5.222 ms DMZ.
- HTTP median: 2.866 seconds core and 2.648 seconds DMZ.
- SMB median: 3.572 seconds core.
- LDAP median: 3.206 seconds core.
- SSH median: 1,158.787 seconds core.
- RDP median: 1,820.334 seconds core.

The long SSH/RDP tail is compelling. The SMB/LDAP ceiling is the notable exception: 1,490 service records without one duration above 45 seconds.

### DNS

Core DNS is 1,363 A, 264 AAAA, 184 PTR, 66 SRV, 283 TXT, and 11 miscellaneous records. DMZ DNS is 596 A, 98 AAAA, 68 PTR, five SRV, and six TXT. The response mix and query vocabulary fit a Windows domain with Linux and proxy infrastructure.

Core’s 248 unique TXT queries from `10.10.2.30` to `ns1.westbridge-services.cloud` form a conspicuous DNS-tunneling pattern. At `2024-03-18T16:44:58Z`, query `95ead0cb31c699664159b305.ns1.westbridge-services.cloud` receives TXT answer `xx89e24e3dabfcacde4c` with TTL 1. Subsequent queries vary labels, answer encoding, RTT, TTL, and response status; this looks like credible suspicious traffic, not an authenticity defect by itself.

Resolver behavior includes PTR, suffix expansion, NXDOMAINs, low TTLs, long cached intervals, and occasional SERVFAIL. I found no DNS record outside its parent UDP/TCP connection interval.

### HTTP and proxy behavior

Core HTTP contains 832 CONNECT, 217 GET, and eight POST requests; DMZ has 868 CONNECT, 346 GET, and 14 POST requests. Transaction depth reaches seven, so the corpus does not reduce every HTTP connection to one request.

Status distributions include 200, 206, 301, 302, 304, 403, 404, 407, 502, 503, and 504. User-agent diversity is moderate—38 unique values core and 39 DMZ—with only one missing value in each sensor. HTTP/1.1 throughout is reasonable because most visible encrypted web traffic is represented by CONNECT control traffic or SSL metadata rather than HTTP/2 decoding.

### TLS and certificates

Every emitted SSL record is established, while some `conn.json` records classified as SSL lack an SSL row. This is consistent with Zeek only obtaining enough handshake material for the logged sessions.

Core certificate chains are commonly two elements for internal mail TLS; DMZ includes zero-, one-, and two-element visible chains because of resumption and collection gaps. All 601 X.509 records are valid at capture time. Leaf SAN checks found no SNI mismatch among parseable chains.

The missing X.509 references are not dangling inventions. Ten core and 57 DMZ certificate references lack a parsed X.509 row, but their file records show small, explicit capture gaps. For example, core UID `CopoQu6jSulEbeHjkG` has leaf and intermediate files missing seven bytes each, no analyzers, and therefore no X.509 rows. This is a convincing collection-imperfection relationship.

### Multi-sensor consistency

I matched 1,923 connections across sensors by exact origin/destination IP, origin/destination port, protocol, and subsecond time proximity. UIDs differ across sensors, as real independent Zeek instances would assign them. Connection state matched in all 1,923; 229 had byte-count differences, consistent with independent observation and packet loss.

The clock relationship is unusually orderly: every DMZ observation is 41.652–66.433 ms later, and the offset grows smoothly by hour. A stable skew plus oscillator drift is technically plausible, so I treat this only as a weak signal.

### Lateral and unsolicited activity

Internal sensitive-port traffic includes varied short and long SSH sessions, successful SMB traffic to file/domain infrastructure, limited RDP, and a small WinRM presence. Source ports are not reused in overlapping TCP four-tuples; no impossible concurrent tuple reuse was found.

DMZ `S0` traffic has correct SYN-only semantics: zero response packets/bytes and history `S`. The targets and ports are believable—22, 23, 2323, 25, 445, 3389, 5985, and related services—but 989 SYN-only attempts arising from only 14 external IPs is a narrow source population for a broadly exposed DMZ.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Score effect |
|---|---|---:|---|
| `distribution_texture` | Zeek core SMB/LDAP | Dataset-wide: 1,490 records, none above 45 seconds | High; suggests bounded duration generators and insufficient persistent connection reuse |
| `distribution_texture` | Zeek DMZ unsolicited scans | Repeated: 989 `S0` flows from only 14 sources; six sources produce 83.6% | Medium; unusually concentrated external background |
| `weak_signal` | Cross-sensor Zeek timing | Repeated: all 1,923 matched tuples have a one-directional, smoothly increasing offset | Low; plausible clock drift, but unusually clean |

## Realism Score by Category

- **Field format accuracy:** 9 — Zeek schemas, state/history combinations, protocol fields, hashes, certificate fields, and byte accounting are highly credible.
- **Temporal patterns:** 7 — Protocol ordering and long-lived SSH/RDP are strong, but SMB/LDAP exhibit a conspicuous 45-second ceiling.
- **Cross-source correlation:** 9 — UID/reference integrity, independent sensor UIDs, protocol intervals, file/X.509 loss, and proxy-path relationships are coherent.
- **Behavioral realism:** 8 — DNS cache behavior, infrastructure traffic, web/TLS mix, DHCP renewal, and unsolicited scans are plausible; scanner-source diversity is thin.
- **Environmental consistency:** 8 — Host roles and internal/external flow placement are credible, with no impossible topology or service placement observed.

## Recommendations

If this were synthetic, the highest-impact improvement would be to model persistent SMB and LDAP channels in addition to short transaction sessions. A realistic corpus should include connection reuse, idle periods, keepalive behavior, and some multi-minute or window-spanning sessions, while preserving short authentication and file-operation flows.

Broaden unsolicited internet background across a longer-tailed source population. Retain repeat scanners, but mix in more one-off and low-frequency sources, less rigid source-to-port specialization, and varied scan cadences.

If the cross-sensor timing drift is intentional, vary clock behavior by realistic synchronization episodes: stable skew, gradual drift, occasional correction, and independent loss. Avoid making every duplicated flow inherit the same one-directional timing relationship for the full collection window.
