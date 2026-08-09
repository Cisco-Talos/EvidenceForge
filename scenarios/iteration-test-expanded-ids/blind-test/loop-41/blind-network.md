# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Real  
**Verdict Confidence:** 68  
**Synthetic-Confidence Score:** 36

## Executive Summary

The dataset is mostly production-like: connection-state diversity, proxy routing, DNS behavior, TLS version/cipher pairing, cross-sensor timing, firewall accounting, and IDS tuple alignment form a coherent network. The strongest synthetic indicator is a repeatable Zeek TLS/X.509 referential-integrity gap affecting 53 full TLS 1.2 handshakes; a second, weaker concern is the complete absence of NTP traffic in an otherwise densely observed Active Directory environment.

## Evidence For Synthetic

- `[contract_gap]` Zeek `ssl.json` contains dangling `cert_chain_fuids`. In `zeek-core`, 5 of 44 chain-bearing TLS sessions reference 10 certificate FUIDs absent from both `x509.json` and the corresponding `files.json`; in `zeek-dmz`, 48 of 380 chain-bearing sessions reference 69 absent FUIDs. For example, the `2024-03-18T13:34:09.809683Z` core TLS 1.2 session UID `CDT5N9CcGaDXmhenMw` to `mail-fin.meridianhcs.com` references `FDH3wbZ2R4YGhI0TRj` and `FYjHNoO7xZj8mDGR32N`, neither of which exists in the X.509 or file log. DMZ examples include UID `C9mdfXQd1rYlnAMEvJ` at `2024-03-18T12:13:32.515272Z`, whose chain FUID `FYEgznUsaDAiavRqC8` is absent.
- `[environment_or_collection_plausibility]` Across 12,301 core/DMZ Zeek connections over roughly six hours, there are zero UDP/123 connections and no NTP records. This stands out against dense domain-infrastructure telemetry in the same capture: 986 Kerberos, 563 LDAP, 926 SMB, 2,361 core DNS, and 69 DHCP connections. Hypervisor time synchronization or an unusual collection boundary could explain it, so this is not a hard contradiction, but the protocol mix is atypical for the visible multi-host AD environment.
- `[weak_signal]` The X.509 gaps are distributed across internal mail services, the public EHR portal, and numerous unrelated external services rather than one damaged connection or host. Selective downstream loss remains possible in real operations, but source-local Zeek output normally should not publish certificate FUID references without the corresponding file/X.509 rows at this frequency.

## Evidence For Real

- The connection-state populations are heterogeneous and service-appropriate. Core has 6,239 `SF`, 82 `RSTO`, 50 `RSTR`, 21 `REJ`, 20 `S0`, plus smaller `OTH` and partial-close states; DMZ has 4,482 `SF`, 1,152 `S0`, 98 `RSTO`, 62 `RSTR`, and smaller tails. The high DMZ `S0` population is explained by randomized Internet scanning against ports such as 23, 25, 445, 22, 3389, 8080, and 443.
- External scanning has realistic entropy. Major scanner sources vary in TCP option-derived SYN sizes, source ports, target-port preferences, and inter-arrival times. For example, `37.75.195.175` generated 166 unanswered SYNs with a median interval near 85 seconds, while `45.33.74.51` generated 137 with a median near 95 seconds; neither follows a fixed cadence.
- DNS is convincing: core contains A, AAAA, PTR, SRV, TXT, NS, and MX traffic with `NOERROR`, `NXDOMAIN`, `SERVFAIL`, and `REFUSED` outcomes. Windows-like artifacts include `wpad`, `isatap.meridianhcs.local`, AD SRV discovery, reverse lookups, and suffix-expanded names. Empty `NOERROR` responses are limited to AAAA/NODATA cases rather than malformed A answers.
- TLS protocol semantics are internally correct. All TLS 1.3 sessions use TLS 1.3 suites (`TLS_AES_*` or `TLS_CHACHA20_POLY1305_SHA256`), while TLS 1.2 sessions use ECDHE RSA/ECDSA suites. Certificate chains appear only on non-resumed TLS 1.2 full handshakes; TLS 1.3 and resumed sessions are correctly chainless for passive observation. Observed certificates are valid at capture time and include plausible RSA/ECDSA key sizes, public CA diversity, enterprise issuance, SANs, and validity periods.
- Explicit-proxy sequencing is strong. At approximately `2024-03-18T12:01:10Z`, client `10.10.2.26:58228` connects to proxy `10.10.3.20:8080`, issues `CONNECT px.ads.linkedin.com:443`, the proxy resolves the destination through `10.10.2.10`, and then opens TLS from `10.10.3.20:58001` to `104.16.1.112:443`. The proxy access record independently reports the tunnel byte totals and 4,768 ms duration.
- Cross-vantage observations look like separate sensors rather than copied rows. I matched 2,113 core/DMZ connections by five-tuple within one second; UIDs differ by sensor, timestamps differ by roughly 14–66 ms, states agree, and some duration or packet accounting changes by vantage while most payload totals remain stable.
- Firewall accounting is source-native and consistent. The inbound web connection from `195.157.166.202:54897` to `10.10.3.10:80` at `12:00:40Z` has 1,882 total IP bytes in Zeek (`603 + 1,279`), exactly matching the ASA teardown byte count at `12:00:45Z`. ASA messages also show plausible NAT translations, build/teardown lifecycles, and 30-second SYN timeouts.
- Every parsed TCP/UDP Snort alert had a matching Zeek five-tuple within one second: 58/58 core alerts and 105/105 perimeter alerts. The observed timing offsets were small but variable rather than identical.
- Protocol volume fits a modern proxied enterprise: core HTTP is dominated by 969 `CONNECT` requests but still includes 150 GETs and four POSTs; DMZ has 1,907 TLS sessions, 1,334 HTTP transactions, inbound web traffic, proxy egress, MySQL application traffic, and background Internet scanning.
- UID relationships are otherwise strong: all DNS, HTTP, SSL, SMTP, and file connection references resolve to a local `conn.json` UID; all recorded X.509, OCSP, and PE identifiers resolve to `files.json`. This makes the certificate-chain omissions a bounded defect rather than general referential collapse.
- Temporal volume is nonuniform across the six visible UTC hours. Core hourly counts range from 939 to 1,419 and DMZ counts from 865 to 1,215, with user/proxy bursts mixed with continuous infrastructure and perimeter activity.

## Detailed Analysis

### Connection Patterns and State Semantics

The core sensor records 6,446 connections and the DMZ sensor 5,855, spanning approximately `2024-03-18T12:00:14Z` through `18:00:00Z`. Core traffic is balanced between TCP and UDP because of substantial DNS and Kerberos activity; DMZ traffic is TCP-heavy because of TLS, proxy, web, database, and unsolicited perimeter traffic.

State and history combinations are coherent. UDP response-bearing DNS/DHCP predominantly uses `SF` with `Dd`; unanswered perimeter TCP attempts use `S0` with `S`; rejected connections use `REJ` with `Sr`; established connections show varied `ShAD...` histories and natural reset/partial-close tails. Failed Internet scans generally have one observed SYN and no response, while the ASA retains them until its 30-second SYN timeout, which is normal cross-product behavior.

Service durations are varied rather than quantized. Core HTTP has a median duration near 3.33 seconds and a maximum near 144 seconds; SSH has a median near 1,184 seconds and a 15,508-second long-lived session. SMB and LDAP range from subsecond operations to roughly 45 seconds and include FIN, reset, and partial-close outcomes. DMZ MySQL has 332 observed sessions with a 2.18-second median, a 26.76-second maximum, and a realistic mix of `SF`, reset, and partial-close states.

### DNS

Core DNS has 2,343 rows: 1,455 A, 298 AAAA, 173 PTR, 68 SRV, 337 TXT, seven NS, and five MX queries. Response codes include 2,081 `NOERROR`, 242 `NXDOMAIN`, 14 `SERVFAIL`, and six `REFUSED`. Query RTTs have 1,747 distinct values and span local submillisecond responses through slower recursive lookups.

AD behavior is visible in `_kerberos._tcp.meridianhcs.local`, `_ldap._tcp.meridianhcs.local`, domain-controller lookups, reverse DNS, and authoritative internal answers. Windows resolver texture appears in `wpad`, `isatap`, printer queries, and public names expanded with `.meridianhcs.local`. AAAA NODATA responses correctly use `NOERROR` with no answer; populated AAAA answers are syntactically valid.

The high TXT count is concentrated in a structured `ns1.westbridge-services.cloud` exchange with short TTLs and varying labels/answers, while ordinary SPF/DKIM/DMARC-style TXT traffic supplies benign context. That activity is suspicious but not itself an authenticity defect: its timings, UDP accounting, response codes, and connection fan-out are internally coherent.

### HTTP, Proxy, and TLS

Core HTTP contains 1,123 rows and DMZ HTTP 1,334. Status distributions include successes, redirects, authentication failures, denies, cache-related responses, and upstream errors (`407`, `403`, `503`, `504`, and `502`), which avoids an unrealistically all-successful proxy.

The explicit proxy path is especially persuasive. Client-to-proxy CONNECT records appear at both core and DMZ vantage points with sensor-specific UIDs and clock offsets. Proxy-side DNS and origin TLS then occur in the correct order. I found 906 proxy CONNECT-to-origin-TLS sequences within ten seconds; the delay ranged from about 88 ms to 3.27 seconds with a median of 454 ms.

TLS contains a credible mix of TLS 1.2 and 1.3, several current cipher suites, resumed and full sessions, SNI-bearing and SNI-less connections, and different SSL history strings. TLS 1.3 correctly lacks visible certificate chains; non-resumed TLS 1.2 supplies chains. X.509 records include public and enterprise issuers, leaf and CA constraints, RSA and ECDSA keys, SANs, and valid observation-time windows.

The defect is the 53 full TLS 1.2 sessions whose `cert_chain_fuids` are not resolvable. Because every actual `x509.json` identifier does resolve through `files.json`, these are explicit dangling references rather than merely absent certificate collection on an otherwise chainless handshake.

### Infrastructure and Lateral Traffic

Core traffic includes 986 Kerberos, 563 LDAP, 926 SMB, 122 SSH, and 20 RDP service-classified connections. Their state and duration distributions are varied, and there is no visible dependent-before-transport ordering in the network records examined. DMZ traffic includes expected app-to-database MySQL, proxy DNS/egress, inbound web access, and restricted internal reachability mixed with failed probes.

DHCP contains 69 REQUEST/ACK renewal transactions across eight named clients with one-, two-, and four-hour leases. Per-client renewal intervals are stable around their negotiated T1 timing with small jitter. The lack of visible DISCOVER/OFFER pairs is not penalized because the capture is a bounded window and these are renewals.

NTP is the environmental outlier. Given the visible domain services and DHCP clients, zero UDP/123 flows over six hours is unusual. It remains explainable by hypervisor synchronization, off-sensor timing infrastructure, or filtering, so it is weighted below the X.509 contract gap.

### IDS, Firewall, and Web-Server Correlation

All parsed TCP/UDP Snort alerts correlate to Zeek tuples within one second. Examples include suspicious DNS TLD rules, scan detections, CONNECT policy alerts, user-agent rules, BitTorrent, Telegram, and TLS fingerprint alerts. The alerts are not emitted on a rigid schedule and occur against both background and suspicious traffic.

ASA records show correct build/teardown distinctions for TCP and UDP, inside/DMZ/outside interface semantics, dynamic source translations for proxy egress, static translations for inbound web traffic, byte totals, FIN teardown reasons, and SYN timeouts. Web access records agree with Zeek HTTP request method, path, user agent, and status for sampled traffic.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Score effect |
|---|---|---:|---|
| `contract_gap` | Zeek SSL / files / X.509 | 53 TLS sessions; 79 dangling certificate FUIDs across core and DMZ | High: explicit source-local referential failure on otherwise complete TLS 1.2 handshakes |
| `environment_or_collection_plausibility` | Zeek conn / infrastructure protocols | Dataset-wide absence of UDP/123 over six hours | Medium-low: atypical AD protocol mix, but operationally explainable |
| `weak_signal` | Zeek TLS collection | Missing chain artifacts span multiple unrelated services | Low independently; reinforces that the FUID problem is systematic rather than a single corrupt row |

## Realism Score by Category

- **Field format accuracy:** 8 — Zeek, Snort, ASA, proxy, DNS, TLS, and X.509 fields are broadly source-native; dangling certificate FUIDs are the main exception.
- **Temporal patterns:** 8 — Business-hour bursts, infrastructure continuity, scanning entropy, varied durations, and cross-sensor clock offsets are convincing.
- **Cross-source correlation:** 7 — Flow, proxy, firewall, IDS, and web correlations are strong, but 79 certificate references fail within the Zeek source family.
- **Behavioral realism:** 8 — User proxy traffic, Internet scanning, AD services, mail, web, database, DHCP, and lateral protocols form a credible mixed workload.
- **Environmental consistency:** 7 — Segmentation, NAT, proxy placement, and service roles agree; total absence of NTP is the notable plausibility gap.

## Recommendations

- If this were synthetic, make TLS observation decisions coherent across `ssl.json`, `files.json`, and `x509.json`. Either emit every file/X.509 row named by `cert_chain_fuids`, or omit the entire chain reference for a source-locally dropped certificate group; do not leave dangling FUIDs.
- Add low-volume, per-host or per-role NTP behavior consistent with a domain time hierarchy, including UDP/123 connection evidence and response-bearing NTP records where the sensor would observe them. Use realistic poll intervals and observation loss rather than identical hourly ticks.
- Preserve the current proxy chain, sensor-specific UIDs, variable cross-vantage delays, firewall byte accounting, DNS NODATA behavior, and TLS-version/cipher constraints; these are among the strongest production-like characteristics.
