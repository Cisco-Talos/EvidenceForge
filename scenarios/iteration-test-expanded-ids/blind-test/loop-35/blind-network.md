# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 72
**Synthetic-Confidence Score:** 28

## Executive Summary

The six-hour collection is strongly production-like at the network layer: Zeek state semantics, DNS and TLS diversity, sensor-placement differences, NAT perspectives, proxy transactions, IDS alerts, firewall accounting, and endpoint flows form a coherent whole without a hard contradiction. The principal reservations are a conspicuously deterministic DHCP-renewal texture and the absence of any visible NTP traffic despite otherwise broad infrastructure coverage; both are plausible deployment choices and keep the synthetic-confidence score in the “mostly realistic” range.

## Evidence For Synthetic

- `[distribution_texture]` DHCP renewals are unusually stable at a host-specific cadence. In `zeek-core/dhcp.json`, client `10.10.1.22` renews 13 times from `12:01:43.244100` through `17:59:14.312659`, with every interval between 1,786.378 and 1,788.572 seconds. Client `10.10.1.21` similarly has ten consecutive gaps between 1,939.264 and 1,941.780 seconds, and `10.10.1.31` has ten gaps between 1,968.835 and 1,970.754 seconds. Stable DHCP timers are normal, but the repeated per-client cadence with only roughly one second of variation resembles a deterministic periodic-plus-small-jitter model.
- `[environment_or_collection_plausibility]` Neither `zeek-core/conn.json` nor `zeek-dmz/conn.json` contains UDP/123 traffic across 11,776 connection observations, even though the same six-hour view includes 69 DHCP transactions, 2,290 Kerberos-service connections, 1,402 LDAP-service connections, and broad visibility across 18 endpoint identities. Zero NTP in a collection this otherwise infrastructure-rich is odd, although centralized time synchronization outside the observed path remains a credible explanation.
- `[weak_signal]` Internal ICMP payload sizes have a somewhat curated diagnostic texture. Among 68 locally originated ICMP observations in `zeek-core/conn.json`, only 19 request sizes appear, concentrated at values such as 32, 48, 56, 64, 84, 120, 256, 512, 1,024, and 1,472 bytes. These are all valid and commonly selected diagnostic sizes, so this has little weight by itself.

## Evidence For Real

- Zeek connection-state texture is differentiated by sensor placement. `zeek-core/conn.json` contains 5,966 `SF`, 76 `RSTO`, 46 `RSTR`, 20 `REJ`, and only 12 `S0` records, while the exposed DMZ view contains 4,223 `SF`, 1,161 `S0`, 111 `RSTO`, 65 `RSTR`, and 26 `REJ`. The DMZ’s large unsolicited-SYN population is exactly where it belongs.
- State/history combinations are source-native and coherent: DMZ `S0` traffic is overwhelmingly `history:"S"`; rejected TCP connections use `Sr`; originator resets include `ShADaR`/`ShAR`; responder resets predominantly use `ShADadR`; and completed traffic has varied FIN/data histories rather than a single template.
- DNS has realistic breadth in `zeek-core/dns.json`: 1,376 A, 313 AAAA, 185 PTR, 65 SRV, 282 TXT, plus NS/MX/SOA records. Responses include 230 NXDOMAIN, 18 SERVFAIL, and 8 REFUSED outcomes, with 1,678 distinct RTT values and a broad TTL distribution rather than one global constant.
- Suspicious DNS activity remains protocol-coherent. From `16:44:48.714022` to `16:59:44.151936`, `10.10.2.30` makes 194 TXT queries to varied subdomains under `ns1.westbridge-services.cloud`; intervals range from 0.007 to 47.413 seconds, answers vary, and each response has TTL 1. This looks like observable DNS tunneling rather than a mechanically fixed beacon.
- TLS is modern but varied. Across the two `ssl.json` files, TLS 1.2 and 1.3 coexist with appropriate suites such as `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`, and ECDHE RSA/ECDSA suites. All 697 referenced certificate records resolve to `x509.json`, all sampled certificates are valid at connection time, and repeated fingerprints retain consistent subject, issuer, and serial data.
- Proxy layering is particularly convincing. At `12:02:17`, `10.10.1.21:41974` connects to `10.10.3.20:8080`: core UID `CJq0KPsTnsAOo1XG3` starts at `1710763337.026956`, while DMZ UID `CDhrmEDLyoCsWoqPl` sees the same tuple about 44 ms later. Both observe a successful `CONNECT fonts.pixeltrack.org:443`; `proxy_access.log` records user `lina.nguyen@meridianhcs.local`, 4,187/17,113 tunnel bytes, and 1,538 ms duration. The proxy’s separate origin flow `10.10.3.20:43546 -> 104.18.142.134:443` then produces TLS 1.3 SNI `fonts.pixeltrack.org`.
- NAT and byte accounting agree without collapsing source perspectives. For the STUN exchange at `12:07:23`, Zeek core UID `CrzxNAwOaVOavORkUp2` records `10.10.2.25:38321 -> 87.136.158.10:3478`, two packets each way and IP-byte totals of 271 + 266 = 537. The ASA records translation to `203.14.220.1:47105` and a teardown byte count of exactly 537, while Snort alerts on the original internal tuple at `12:07:23.166401`.
- All 2,232 core DNS, 1,084 core HTTP, 102 core TLS, 66 SMTP, 822 DMZ DNS, 1,280 DMZ HTTP, and 1,761 DMZ TLS records resolve to a connection UID at the same sensor. No inspected protocol record begins before its connection or occurs after that connection’s close.
- Endpoint-flow direction is internally consistent for all 18 observed hosts: outbound records use the host’s own address as source and inbound records use it as destination. For example, the `WS-AJOHNSON-01` eCAR DNS flow at `1710763405076` has `10.10.1.35:50548 -> 10.10.2.10:53`; Zeek core records the matching connection and DNS query at `1710763405.110415`.
- Traffic is not overly smooth. Core per-minute connection volume ranges from 1 to 54 with coefficient of variation about 0.55; DMZ ranges from 0 to 59 with coefficient about 0.64. Half-hour DNS and TLS volumes show pronounced bursts rather than constant quotas.
- The exposed service mix is plausible for the visible environment: DNS, Kerberos, SMB, LDAP, DHCP, SMTP, SSH, RDP, proxy HTTP, external TLS, and MySQL are all represented. External scan traffic concentrates on ports 23, 25, 445, 3389, 22, 2323, 80, and 443 against the DMZ web host, with irregular source timing rather than fixed scan intervals.

## Detailed Analysis

### Connection and Sensor Semantics

`zeek-core/conn.json` contains 6,152 records and `zeek-dmz/conn.json` contains 5,624, covering exactly `12:00:10.733374` through approximately `17:59:53`. Core traffic is roughly balanced between TCP and UDP because of DNS and Kerberos, while DMZ is TCP-heavy owing to proxy-origin TLS and unsolicited Internet probing.

The two sensors do not merely duplicate one file. I found 1,997 same-tuple flows visible at both placements. They preserve distinct UIDs and typically differ by roughly 40–90 ms, while retaining compatible states, byte accounting, and durations. This is credible independent observation delay. Sensor-specific visibility is also sensible: the core sees large SMB/Kerberos/LDAP volumes, while the DMZ sees 1,979 destination-port-443 connections and 1,161 `S0` records.

Long sessions are service-appropriate. Core UID `Cq7ao4ESdOmgP68ngX`, an SSH session from `10.10.1.36` to `10.10.3.10`, lasts 15,209.025 seconds and terminates `SF`; UID `CrHk49680A9F2Nh8j7`, SSH from `10.10.3.10` to `10.10.2.30`, lasts 13,304.48 seconds. RDP and SSH also supply multiple roughly 45–60 minute sessions. Short HTTP, DNS, reset, and scan connections remain short.

### DNS

DNS tuples, timestamps, and UIDs align exactly with their connection records. The mixture includes ordinary client A/AAAA lookups, reverse lookups, AD SRV discovery, mail MX/TXT/SOA/NS activity, suffix-search NXDOMAINs, and the concentrated TXT tunnel. Internal authoritative answers such as `DC-01.meridianhcs.local -> 10.10.2.10` use `AA:true` and TTL 300; Internet-facing answers use heterogeneous TTLs and non-authoritative recursion.

The DMZ resolver view is correctly scoped to `10.10.3.20` and `10.10.3.10`, whereas the core sees requests from the wider client/server estate. Some TLS destinations lack a DNS query in the preceding ten minutes, but that is compatible with cache state predating this bounded window and is not an authenticity defect. No visible DNS-dependent connection was demonstrably ordered before the only possible resolution for the same identity.

### HTTP, Proxy, and TLS

Core HTTP is dominated by 886 CONNECT transactions; DMZ has 932 CONNECT plus 348 GET/POST transactions. Proxy access records add 1,089 SSL-inspected GETs, 41 POSTs, and 926 CONNECTs, with tunnel, deny, authentication-required, gateway-error, forward, and SSL-inspection actions. Statuses include 200, 304, 403, 407, 502, 503, and 504, avoiding an unrealistically all-successful profile.

The client-to-proxy and proxy-to-origin split is preserved. CONNECT control-plane bytes differ appropriately from tunnel bytes, and origin TLS has its own source port, UID, packets, SNI, cipher, and certificate evidence. TLS resumptions occur in both sensor views, and certificate material is absent on many resumed/otherwise cached observations rather than being regenerated for every connection.

### Firewall, IDS, and Endpoint Correlation

ASA records include 4,248 TCP builds and 4,245 TCP teardowns; the three unmatched builds are long SSH connections still open when the collection ends at `17:59`, an appropriate bounded-window condition. Teardown reasons include 3,073 `TCP FINs`, 1,027 `SYN Timeout`, 110 `TCP Reset-O`, and 35 `TCP Reset-I`. The 1,027 SYN timeouts consistently use 30 seconds, while established traffic has varied durations.

Every one of the 87 core and 140 perimeter Snort alerts maps to a corresponding Zeek connection at the appropriate sensor and tuple. This does not count as synthetic simply because it correlates; importantly, the source perspectives remain realistic. Alerts occur on successful, timed-out, reset, rejected, and one-way flows rather than only on hand-selected successful sessions.

Endpoint eCAR flow records preserve NAT/pre-NAT perspective appropriately. Public mail address `203.14.220.11`, for example, appears as the endpoint destination, while ASA logs translate it to inside host `10.10.2.25`; this explains why post-NAT Zeek tuples do not always textually match eCAR and is a mark of realism, not a gap.

### Temporal and Environmental Texture

Per-minute traffic is bursty, with no zero-minute gaps in core and one in DMZ, but substantial count variance. User proxy bursts, DNS-tunnel activity, inbound scans, long-lived administration, DHCP, mail, authentication, and application/database traffic overlap organically.

The DHCP cadence is the clearest synthetic-looking texture. Each client repeatedly renews at a highly stable, client-specific interval, including intervals above and below half of the stated lease time. A server-supplied client-specific T1 can explain this, but the near-constant cadence across every subsequent ACK is unusually tidy.

The only notable service-family omission is NTP. Given the broad connection capture and multiple server/workstation subnets, at least some UDP/123 would normally be expected within six hours. This remains an environmental-plausibility concern, not a contradiction, because time may be synchronized through a path or mechanism outside these sensors.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `distribution_texture` | Zeek DHCP | Repeated across all eight DHCP clients; strongest for the five clients with 6–13 renewals | Moderate: client-specific renewal periods vary by only about 1–2 seconds across hours, giving the periodic model a deterministic texture |
| `environment_or_collection_plausibility` | Zeek connection/service mix | Dataset-wide across both network sensors | Moderate-low: zero UDP/123 is unusual beside broad DHCP, AD, mail, proxy, and endpoint-flow visibility, but alternate time-sync placement is plausible |
| `weak_signal` | Zeek ICMP | 68 internally originated core flows | Low: payload sizes cluster around a compact diagnostic-size pool, but every value is valid and operationally explainable |

## Realism Score by Category

- **Field format accuracy:** 9 — Zeek, ASA, Snort, proxy, TLS/X.509, and eCAR fields are source-appropriate, with no invalid tuple, state, cipher, certificate-time, or UID relationship found.
- **Temporal patterns:** 8 — User/network activity is bursty and sensor delays are credible, offset by highly stable per-client DHCP renewal periods.
- **Cross-source correlation:** 9 — NAT, IDS, firewall byte counts, proxy legs, Zeek UIDs, protocol timing, and endpoint direction agree while retaining source-specific viewpoints.
- **Behavioral realism:** 9 — Scanning, browsing, mail, AD, SMB, SSH/RDP, proxy errors, DNS tunneling, and long-lived sessions have credible protocol behavior and varied outcomes.
- **Environmental consistency:** 8 — Subnets, host roles, routing, proxying, and exposed services are coherent; total absence of NTP is the main unresolved environmental oddity.

## Recommendations

- If this were synthetic, make DHCP renewal scheduling less fingerprintable across repeated leases. Either align renewals with an explicit, source-visible T1 policy or introduce realistic scheduler and lease-negotiation variation so each client does not repeat essentially the same non-half-lease interval for the entire six-hour window.
- If this were synthetic and the sensors are intended to represent broad east-west and perimeter visibility, add low-volume UDP/123 activity from servers and clients, with stable server selection, long polling intervals, small observation jitter, and occasional source-specific gaps.
- If this were synthetic, broaden internal ICMP behavior modestly by tying payload sizes to recognizable tools or operating-system defaults and using unusual 256/512/1,024/1,472-byte probes only for a smaller diagnostic subset.
- Preserve the existing source-specific correlation model: independent Zeek UIDs across sensors, endpoint pre-NAT versus firewall post-NAT views, proxy client/origin separation, protocol lifecycle timing, and firewall byte accounting are the strongest realism features in the collection.
