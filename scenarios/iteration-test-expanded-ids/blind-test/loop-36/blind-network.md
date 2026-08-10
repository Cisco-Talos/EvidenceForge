# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 67

## Executive Summary

The collection is technically strong: Zeek connection state, protocol fan-out, TLS, DNS, proxy, firewall, and file-transfer records correlate unusually well without obvious impossible ordering. I nevertheless judge it synthetic because the public-facing traffic has a pronounced generated-address and generated-client texture—completed TLS sessions arrive from an implausibly broad set of unrelated address blocks, including numerous U.S. Department of Defense /8 ranges, while 67 external HTTP clients collapse to only eight exact User-Agent strings—and the otherwise broad six-hour collection contains no NTP traffic at all.

## Evidence For Synthetic

- `[distribution_texture]` The public EHR service’s TLS traffic uses 180 distinct client IPs spanning 123 distinct /8s, with all 180 also in distinct /16s and /24s. That near-uniform address-space spread looks like independent random IPv4 selection rather than the clustered carrier, enterprise, cloud, and scanner prefixes normally seen at a real public service.
- `[environment_or_collection_plausibility]` Successful, stateful TLS sessions to `10.10.3.10:443` occur from an exceptional collection of U.S. DoD-owned address space: `22.233.251.234` at `2024-03-18 12:15:22 UTC`, `11.21.177.243` at `13:23:50`, `7.48.103.123` at `14:24:17`, `25.130.85.29` at `14:32:42`, `19.178.50.101` at `14:44:04`, `26.62.52.73` at `15:06:42`, `6.80.129.45` at `16:07:51`, and `55.230.42.171` at `16:43:26`. These are established TLS records, not spoofable SYN-only scans; ASA teardown records also show bidirectional byte counts and FIN closure, such as 40,147 bytes for `22.233.251.234`.
- `[distribution_texture]` External cleartext HTTP has 73 requests from 67 client IPs but only eight exact User-Agent strings. Six fixed Windows browser strings account for 66 of the 73 requests, with only `zgrab` and Bingbot adding variation. A real Internet-facing healthcare portal would ordinarily show materially greater OS, mobile, browser-build, library, and bot diversity.
- `[environment_or_collection_plausibility]` Across 11,776 Zeek connection records, 18 visible internal addresses, DHCP, DNS, Kerberos, LDAP, SMB, mail, SSH, RDP, proxy, and Internet traffic, there are zero UDP/TCP port 123 records. Complete absence of time synchronization is difficult to reconcile with the otherwise broad internal collection profile.
- `[distribution_texture]` DHCP behavior is unusually categorical by endpoint: eight clients always receive one fixed lease class—3,600, 7,200, or 14,400 seconds—and all 69 transactions are exactly `["REQUEST","ACK"]`. The one-hour clients produce 10–13 renewals in six hours, the two-hour client produces six, and the four-hour clients produce three. This is operationally possible but reads like per-host parameter assignment rather than a naturally shared subnet policy.
- `[weak_signal]` Public HTTP response behavior has a somewhat pool-driven texture. For the same `ehr-portal.meridianhcs.com` host, `/` alternates only between 301 and 404, `/favicon.ico` between 200 and 302, `/api/v2/data` between 200 and 301, and `/login` between 200 and 302, while client diversity is otherwise extremely narrow. Authentication and routing state could explain this, so it is not decisive alone.

## Evidence For Real

- Zeek connection-state texture is strong. Core traffic contains 5,966 `SF`, 76 `RSTO`, 46 `RSTR`, 20 `OTH`, 20 `REJ`, 12 `S0`, and smaller `S1`/`S2`/`S3` populations. The DMZ sensor has a credible perimeter mix: 4,223 `SF`, 1,161 `S0`, 111 `RSTO`, 65 `RSTR`, and 26 `REJ`.
- TCP histories are varied and compatible with their states. DMZ examples include `S0/S`, `REJ/Sr`, `RSTO/ShADaR`, `RSTR/ShADadR`, and multiple completed histories such as `ShADadfF`, `ShADaDadfF`, and histories containing retransmission and content-gap markers.
- Cross-source byte accounting is excellent. UID `CSjmT8FTdUnutlVwWa` is a `10.10.1.36:51127 -> 10.10.3.20:8080` proxy connection beginning at `12:02:10.905356`, lasting `1.085003` seconds. Zeek reports 635 and 1,941 IP bytes, totaling 2,576; ASA connection `1218059` reports exactly 2,576 bytes, and the proxy log reports the same CONNECT request for `sdk.split.io:443`.
- Protocol fan-out is coherent. UID `CGKXzbgQSCV1I60nb5` connects `10.10.3.20:54650` to `151.101.60.52:443` at `12:06:08.323268`; the TLS record follows at `12:06:08.741319` with SNI `analytics.netscaler.com`, TLS 1.2, an ECDSA GCM cipher, and two certificate FUIDs. The matching certificate file SHA-1 values equal the corresponding `x509.json` fingerprints.
- TLS characteristics are modern and internally sensible: 1,241 TLS 1.3 and 622 TLS 1.2 sessions, seven plausible cipher suites, 577 resumed sessions, and no certificate chains on TLS 1.3 observations while non-resumed TLS 1.2 sessions carry one- or two-certificate chains.
- DNS has credible heterogeneity: 1,376 A, 313 AAAA, 282 TXT, 185 PTR, 65 SRV, plus MX/NS/SOA; response codes include 230 NXDOMAIN, 18 SERVFAIL, and 8 REFUSED. RTTs range from `0.000101` to `2.405` seconds rather than occupying a narrow fixed band.
- The collection includes convincing anomalous network behavior rather than only benign templates. Beginning at `16:44:48`, `10.10.2.30` emits rapid TXT queries under `ns1.westbridge-services.cloud` with varied labels, answers, and TTLs of 1–14 seconds, consistent with DNS tunneling.
- Hourly core connection volumes are not flat: 859, 1,002, 992, 911, 1,255, and 1,133 records across the six hours. Durations and ephemeral ports also have high entropy; core has 5,556 distinct durations and 5,336 distinct source ports across 6,152 records.

## Detailed Analysis

### Collection scope and traffic mix

The visible window is `2024-03-18 12:00:10` through `17:59:53 UTC`. Core Zeek records comprise 6,152 connections, 2,232 DNS transactions, 1,084 HTTP records, 102 TLS records, 66 SMTP records, 297 file records, and 69 DHCP transactions. DMZ Zeek adds 5,624 connections, 822 DNS, 1,280 HTTP, 1,761 TLS, and 655 file records. The perimeter ASA contains 12,665 lines, with 227 combined IDS alerts and 2,056 explicit-proxy access records.

Core service distribution is plausible for an Active Directory enterprise: 2,241 DNS, 978 Kerberos, 865 SMB, 565 LDAP, 105 SSH, 69 DHCP, 67 SMTP, 62 TLS, and 19 RDP connections. DMZ traffic is appropriately more Internet-heavy: 1,856 SSL, 1,239 HTTP, 831 DNS, and 343 MySQL observations, plus large unaffiliated/SYN-scan populations.

### Connection states and timing

The state populations include both healthy sessions and failure texture. For example, `10.10.1.33:52978 -> 137.177.241.1:3478` at `12:36:07.762575` is UDP `S0` with history `DD`, two origin packets, zero responses, and a 1,707-byte request side. Internal LDAP and SMB sessions terminate with varied `RSTO`, `RSTR`, `S2`, and `S3` patterns rather than one universal close state.

Perimeter scan traffic is believable at the individual-flow level. The DMZ has 1,151 `S0/S` SYN-only connections spread across ports 23, 25, 445, 443, 8080, 3389, 22, 2323, 80, 587, 465, 135, and others. ASA logs turn these into 30-second SYN timeouts; for example, `185.249.5.220:18070 -> 10.10.3.10:22` is built at `12:00:51` and torn down at `12:01:21` with zero bytes and `SYN Timeout`.

Completed sessions show varied duration by service. Proxy TCP/8080 connections range from roughly 0.31 to 128.96 seconds, while SSH includes long-lived sessions up to 15,209 seconds. The latter is feasible in a bounded six-hour slice because sessions can begin early and remain active across much of the observation period.

### DNS

The DNS layer is one of the stronger portions. Initial records include a PTR request for `10.4.10.10.in-addr.arpa`, an authoritative A response mapping `DB-PROD-01.meridianhcs.local` to `10.10.4.10`, and an NXDOMAIN for `wpad.meridianhcs.local`, all with distinct RTTs. AAAA behavior is also plausible for IPv4-only operation: all 313 AAAA requests return NOERROR, but 226 have empty answer sets.

TTL texture is varied: common values include 300, 30, 1, 1,800, 3,600, 600, 7,200, and 86,400 seconds, with a long tail of residual values. The DNS-tunnel burst from `10.10.2.30` is particularly convincing: labels change per request, TXT answer sizes vary, query intervals are irregular, and very short TTLs occur without being one repeated constant.

One limitation is that no NTP traffic exists anywhere in either Zeek connection set. Given the rich observation of DHCP, AD infrastructure, internal applications, proxy egress, endpoint flows, and perimeter traffic, that absence affects environmental plausibility.

### HTTP and explicit proxy

The explicit-proxy path is well modeled. Core HTTP contains 886 CONNECT requests, while the DMZ contains 932, reflecting both client-to-proxy and proxy-origin visibility. The first visible client CONNECT, UID `CSjmT8FTdUnutlVwWa`, receives `502 Bad Gateway`; the proxy access line carries `proxy_action=gateway-error`, `ssl_bump=terminate`, control-message bytes, tunnel bytes, and a 1,085 ms tunnel duration. Successful transactions similarly expose tunnel byte counts and durations rather than treating CONNECT as an ordinary web body.

HTTP methods and statuses are reasonably varied: core includes GET, POST, and CONNECT with 200, 403, 407, 304, 504, 502, 503, 301, 206, and 302 results. Public web paths include ordinary pages and assets, API calls, bots requesting `security.txt` and `sitemap.xml`, and probes for `/wp-admin/`, `/wp-login.php`, and `/xmlrpc.php`.

The public-client distribution is less convincing. Sixty-seven external cleartext clients reduce to eight exact User-Agent values, predominantly a small pool of Windows Chrome, Edge, and Firefox builds. Combined with the near-uniform IP-prefix spread, this is the collection’s clearest generator-like texture.

### TLS and certificates

TLS fields are source-plausible. The TLS 1.3 ciphers are `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, and `TLS_CHACHA20_POLY1305_SHA256`; TLS 1.2 uses credible ECDHE RSA/ECDSA suites, including a small legacy CBC population. All 1,863 TLS observations are marked established.

Certificate lifetimes, key algorithms, SANs, issuer chains, and fingerprints are coherent. For `analytics.netscaler.com`, the leaf certificate uses ECDSA P-256 with a GlobalSign issuer, while the intermediate is RSA; their file-analysis SHA-1 hashes exactly equal their `x509.json` fingerprints. OCSP records reference matching serial-number forms and plausible `thisUpdate`/`nextUpdate` windows.

The questionable part is not TLS protocol mechanics but client provenance. Numerous successful EHR TLS sessions originate from address blocks that would represent an extraordinary concentration of U.S. military networks among only 180 distinct public clients. Because TCP handshakes, TLS negotiation, ASA byte accounting, and FIN closures are present, this cannot be dismissed as spoofed scan traffic.

### Firewall, IDS, and flow correlation

ASA correlation is consistently good. Connection build direction, inside/DMZ/outside interfaces, NAT address, source port, service port, duration, teardown cause, and byte count correspond to Zeek tuples. The 2,576-byte ASA total for the first proxy session exactly equals Zeek’s combined IP bytes.

IDS alerts also map to visible traffic types, including STUN on UDP/3478, BitTorrent on TCP/6881, suspicious TLD DNS queries, ICMP, and HTTP CONNECT tunneling. They do not appear to be free-floating alerts disconnected from flows.

No core/DMZ Zeek UID collisions were found, which is correct for independent sensor namespaces. Individual UID reuse within each sensor is coherent across `conn`, protocol, file, SSL, and certificate records.

### External traffic distribution

The public EHR endpoint has 782 TLS records from 180 unique clients. One source, `185.70.41.45`, generates 371 EHR TLS sessions and 424 total connections, consistent with a concentrated load test, automated client, or attack. That dominant burst is plausible on its own.

The remaining address population is the concern: each of the 180 unique clients occupies a unique /16 and /24, and the sample spans 123 /8s. The appearance of completed sessions from `6/8`, `7/8`, `11/8`, `19/8`, `22/8`, `25/8`, `26/8`, `33/8`, and `55/8` suggests address generation from a broad numeric pool without autonomous-system, geography, carrier, or institutional weighting. This weighs materially toward synthetic even though no single one of those addresses is an impossible packet value.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `distribution_texture` | Zeek DMZ TLS/conn | 180 EHR client IPs; 180 unique /16s and 123 /8s | Strong evidence of uniform random IPv4 selection rather than provider-prefix clustering |
| `environment_or_collection_plausibility` | Zeek TLS + ASA | Completed sessions from many DoD-owned /8 ranges | Bidirectional TLS and FIN closure make the unusual source population substantive, not spoofed SYN noise |
| `distribution_texture` | Zeek DMZ HTTP | 67 external IPs but only eight exact User Agents | Public client software diversity is much too narrow for the IP diversity |
| `environment_or_collection_plausibility` | Zeek conn | Zero port 123 records among 11,776 connections | Inconsistent with the otherwise broad infrastructure collection profile |
| `distribution_texture` | Zeek DHCP | 69 REQUEST/ACK-only transactions with endpoint-fixed 1h/2h/4h lease classes | Possible configuration, but categorical per-client policy and renewal counts look parametrically generated |
| `weak_signal` | Zeek/web HTTP | Small response-state pools per URI | Could be explained by authentication or routing, so only minor weight |

## Realism Score by Category

- **Field format accuracy:** 9 — Zeek, TLS, x509, file, ASA, IDS, and proxy fields are consistently source-plausible.
- **Temporal patterns:** 8 — Microsecond timing, state-dependent duration, hourly variation, DNS bursts, and long-lived sessions are convincing.
- **Cross-source correlation:** 9 — UID, tuple, certificate, proxy, and firewall byte/timing relationships are exceptionally coherent.
- **Behavioral realism:** 6 — Protocol behavior is strong, but public client-address and User-Agent populations are conspicuously pool-like.
- **Environmental consistency:** 5 — The DoD-heavy Internet source mix and complete absence of NTP are difficult to reconcile with the depicted environment.

## Recommendations

- If this were synthetic, generate public source IPs from weighted ASN/provider pools with realistic prefix reuse, geography, carrier clustering, cloud/scanner concentration, and explicit exclusion or very low weighting of institutionally implausible blocks such as multiple DoD /8s.
- Couple public IP personas to a larger, weighted User-Agent population, including mobile devices, macOS, Linux, browser patch drift, HTTP libraries, security scanners, crawlers, malformed clients, and internally consistent repeat-client behavior.
- Add NTP flows appropriate to the environment: Windows clients and members synchronizing through the domain hierarchy, Linux systems polling configured servers, realistic poll intervals, UDP/123 response accounting, and occasional timeout/jitter texture.
- Make DHCP policy derive from shared scopes, reservations, or client classes visible in the address plan rather than assigning a lease duration independently per endpoint. Include occasional acquisition/rebind behavior when appropriate while retaining normal REQUEST/ACK renewals.
- Preserve the existing network contracts: the Zeek-to-ASA byte agreement, proxy control/tunnel separation, TLS 1.2 certificate extraction, TLS 1.3 visibility behavior, DNS timing, and varied TCP state histories are all strong and should not be simplified.
