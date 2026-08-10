# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 76
**Synthetic-Confidence Score:** 66

## Executive Summary

The Zeek, ASA, proxy, and IDS evidence is technically coherent and often impressively source-native, with realistic connection states, protocol fan-out, NAT records, TLS metadata, and cross-sensor timing. My synthetic verdict is driven instead by dataset-wide texture: a small, persistent set of neatly service-specialized scanners supplies most failed perimeter connections, while internal infrastructure traffic is unusually sparse and scheduled DHCP renewals are almost clockwork.

## Evidence For Synthetic

- `[distribution_texture]` Eight recurring external sources account for 1,043 of the 1,225 external `S0` records in `zeek-dmz/conn.json`, and each behaves like a stable scanner archetype for almost the entire six-hour window. For example, `37.75.195.175` produces 179 `S0` connections from 12:01:49.652329 through 17:51:41.484882, concentrated on 23/2323/22/80/8080, while `38.186.148.245` produces 166 from 12:05:30.019149 through 17:51:29.166976, concentrated on 25/587/465/143/110. The paired specialization and sustained all-window presence look more like a curated generator population than organic Internet background.
- `[distribution_texture]` DHCP renewals in `zeek-core/dhcp.json` are extremely smooth per client. `10.10.1.22` renews a 3,600-second lease 13 times with every interval between 1,786.61 and 1,788.56 seconds; `10.10.1.31` renews every 1,968.90-1,970.83 seconds; and `10.10.1.35` renews its 7,200-second lease every 3,840.70-3,842.16 seconds. The small jitter is better than exact periodicity, but the persistence of a fixed host-specific interval over the full window is conspicuously mechanical.
- `[environment_or_collection_plausibility]` The core sensor records 6,306 connections and clearly observes broad internal traffic, including DHCP, DNS, Kerberos, LDAP, SMB, proxy traffic, ICMP, SSH, and RDP, yet has no UDP/123 NTP traffic and essentially no ambient discovery tail such as mDNS/LLMNR. Given the mixed Windows/Linux population visible in network behavior, the traffic family mix looks unusually curated rather than like an unfiltered internal Zeek deployment.
- `[distribution_texture]` Core traffic is dominated by a short enumerable set: 2,211 DNS, 1,059 Kerberos, 960 HTTP, 949 SMB, and 585 LDAP service-labeled connections. Those five labels represent 91.4% of all 6,306 core records. The lack of a larger low-frequency protocol/application tail reinforces the modeled feel.
- `[weak_signal]` Several background families rise and fall together by hour. The service-specialized external scanners all become markedly busier after 14:00 UTC (for example, `38.186.148.245` has 16/11/35/30/36/38 `S0` connections by hour from 12:00-17:59). This is possible for coordinated scanning, but the shared envelope across otherwise separate scanner identities adds to the synthetic impression.

## Evidence For Real

- Zeek connection semantics are strong. In `zeek-dmz/conn.json`, all 1,225 one-sided TCP attempts are represented as `S0` with history `S`, zero payload bytes, and one originator packet; successful traffic has varied `SF`, `RSTO`, `RSTR`, `S1`, `S2`, `S3`, `OTH`, and `REJ` states with plausible histories and durations.
- DNS is substantially more realistic than a simple A-record generator. Across both sensors it includes A, AAAA, PTR, SRV, TXT, NS, MX, and SOA questions; NOERROR, NXDOMAIN, SERVFAIL, and REFUSED outcomes; suffix-search noise such as `wpad`, `isatap`, and `ctldl.windowsupdate.com.meridianhcs.local`; variable RTTs; and varied TTL vectors.
- TLS behavior is coherent. `zeek-dmz/ssl.json` contains a credible TLS 1.2/1.3 mixture (505/1,170), modern cipher suites, 579 resumed sessions, and 1,096 full sessions. TLS 1.2 resumed sessions do not incorrectly carry certificate chains, and every emitted certificate-chain FUID resolves through both `files.json` and `x509.json`; sampled SNI values match certificate SANs.
- Explicit proxy traffic correlates naturally across observation points. At 12:04:49, client `10.10.1.21:52336` opens CONNECT traffic for `assets.adobedtm.com` to `10.10.3.20:8080`; the core and DMZ sensors see the client leg with identical byte/packet accounting and small sensor delay, while the proxy separately opens `10.10.3.20:55619` to `151.101.1.46:443`. Proxy control bytes plus tunnel bytes reconcile exactly with the client-side Zeek connection totals.
- Firewall evidence is convincing. `fw-perimeter/cisco_asa.log` uses appropriate build/teardown pairs, NAT translations, connection IDs, directions, public-to-private mappings, SYN timeout outcomes, durations, and byte totals. For example, the 12:00:44 inbound SYN from `45.33.74.51:53321` to public `203.14.220.10:80` maps to `10.10.3.10:80` and tears down 30 seconds later as a zero-byte SYN timeout, agreeing with Zeek's `S0` view.
- IDS alerts have believable sensor-specific timing and placement. The perimeter Snort record at 12:06:34.282671 for a `.top` query precedes the DMZ Zeek DNS timestamp 12:06:34.331707 by about 49 ms, while the core alert at 12:06:34.287460 observes the same tuple from its own location. Such offsets are preferable to identical timestamps copied between sources.

## Detailed Analysis

### Scope and connection-state behavior

The visible network window runs from 2024-03-18 12:00:11.890089 UTC through approximately 17:59:57 UTC. The core sensor contains 6,306 connections (3,239 TCP, 2,985 UDP, 82 ICMP); the DMZ sensor contains 5,424 (4,594 TCP, 792 UDP, 38 ICMP). Core state distribution is dominated by 6,087 `SF`, with 93 `RSTO`, 52 `RSTR`, 20 `S0`, 19 `REJ`, 18 `OTH`, 11 `S2`, and 6 `S3`. DMZ traffic appropriately contains much more failed perimeter activity: 3,985 `SF` and 1,241 `S0`, plus smaller reset/reject/partial-state populations.

The state-to-history relationships survived spot checking. DMZ `S0` connections use history `S`, one origin packet, no responder packets, and no payload. Completed flows use varied histories such as `ShADadfF`, `ShADaDadfF`, and forms containing retransmission or teardown variations. I found no zero-byte `SF` flows and no overlapping reuse of a live TCP five-tuple. ICMP's type/code representation in the pseudo-port fields is also consistent.

### DNS

`zeek-core/dns.json` has 2,206 records: 1,401 A, 298 AAAA, 294 TXT, 134 PTR, 69 SRV, with a small NS/MX/SOA tail. Response codes are 1,953 NOERROR, 229 NXDOMAIN, 18 SERVFAIL, and 6 REFUSED. The DMZ sensor adds 765 DNS observations. UIDs match their respective `conn.json` records throughout both files.

The query vocabulary includes credible Windows domain discovery (`_ldap._tcp.meridianhcs.local`, `_kerberos._tcp.dc._msdcs.meridianhcs.local`), reverse lookups, ordinary Internet services, negative suffix-search artifacts, and suspicious high-volume TXT activity from `10.10.2.30`. RTTs range from sub-millisecond internal responses to 2.486 seconds, and TTLs are not collapsed to one constant. DNS timing generally precedes corresponding outbound TLS; cases without an in-window lookup are compatible with resolver caching or the bounded collection window, so I did not score them as contradictions.

### HTTP, proxying, and TLS

Core HTTP consists of 846 CONNECT, 162 GET, and 9 POST records; DMZ HTTP contains 884 CONNECT, 294 GET, and 20 POST. Statuses include 200, 301, 302, 304, 403, 404, 407, 502, 503, and 504, and user agents span Windows and Linux browsers, Python requests, CryptoAPI, Wget, Go, Zscaler, Cisco, and other software. The two-sensor proxy model is coherent: the client-to-proxy leg appears on both sensors with sensor-local UIDs, while proxy-origin TLS/HTTP is a separate connection with its own source port, DNS, firewall/NAT, and certificate evidence.

TLS metadata is especially convincing. DMZ TLS has 1,675 sessions across a realistic modern cipher set. All 483 referenced certificate objects resolve in both file and X.509 logs, repeated fingerprints retain stable certificate identity, and sampled SNI/SAN pairs agree. Certificate timing follows TLS start, and resumed sessions omit certificate transfers as expected. The internal/mail TLS population is smaller but similarly coherent.

### Perimeter, lateral traffic, and volume texture

The ASA records track inbound scanner attempts, ICMP, outbound proxy traffic, and NAT state with believable ordering. Snort alerts align with Zeek tuples while retaining independent timestamp offsets. Internal sensitive ports are present in credible roles: 964 core connections to 445, 139 to 22, 16 to 3389, and only a few direct 3306 attempts, while DMZ shows the expected web-to-database flow volume to `10.10.4.10:3306`.

The main weakness is not individual flow plausibility but population design. Nearly all failed perimeter SYNs come from a handful of long-running, service-specialized source identities. Simultaneously, broad internal capture has almost no protocol long tail beyond the major modeled families. Real small networks can be quiet and perimeter scans can persist, but the combination is unusually tidy.

### Timing

Traffic volume varies by hour rather than being perfectly flat: core counts are 971, 1,005, 1,027, 975, 1,293, and 1,035 from 12:00 through 17:59; DMZ counts are 968, 842, 973, 833, 874, and 934. Individual user/proxy activity is bursty, and connection duration has a broad tail, including a multi-hour session. The principal temporal tell is therefore confined to scheduled baseline families, especially DHCP, rather than all traffic.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `distribution_texture` | Zeek DMZ connection population | Dataset-wide perimeter background | A small set of durable, service-specialized scanner archetypes accounts for most failed inbound SYNs and persists through nearly the whole window. |
| `distribution_texture` | Zeek DHCP | Repeated across all dynamic clients | Host-specific renewal periods vary by only roughly one second over many successive cycles, producing mechanical baseline timing. |
| `environment_or_collection_plausibility` | Zeek core protocol mix | Dataset-wide internal capture | Broad collection includes many internal families but no NTP and almost no ambient discovery/protocol tail. |
| `distribution_texture` | Zeek core connection population | Dataset-wide | Five major service labels account for 91.4% of core connections, leaving an unusually short application/protocol tail. |
| `weak_signal` | Perimeter scanning | Repeated across several sources | Separate scanner identities share a similar hourly activity envelope, including a collective post-14:00 increase. |

## Realism Score by Category

- **Field format accuracy:** 9/10 — Zeek, ASA, proxy, X.509, and IDS structures are source-native and internally plausible with no hard field contradiction found.
- **Temporal patterns:** 6/10 — User and session traffic is varied, but DHCP renewal cadence and coordinated scanner activity are conspicuously smooth.
- **Cross-source correlation:** 9/10 — UIDs, tuples, byte counts, proxy legs, NAT records, certificates, and sensor-local timestamp offsets correlate cleanly without impossible ordering.
- **Behavioral realism:** 6/10 — Individual flows look credible, while the small palette of scanner archetypes and short protocol tail make the overall population feel modeled.
- **Environmental consistency:** 6/10 — Host roles and routing are coherent, but comprehensive core visibility combined with no NTP and little ambient discovery traffic is hard to reconcile with a mixed endpoint estate.

## Recommendations

- If this were synthetic, broaden perimeter background into a larger, churn-heavy population: vary source lifetimes, overlap botnet service interests less neatly, include more one-off and short-lived scanners, and avoid having the same small set remain active throughout the entire window.
- Add realistic client-specific DHCP timer behavior with wider bounded jitter, occasional delayed/missed renewals, lease changes, and less stable recurrence across every cycle while preserving valid REQUEST/ACK semantics.
- Add a low-volume infrastructure tail consistent with the observed collection profile, especially UDP/123 time synchronization and plausible mDNS/LLMNR or explicitly modeled suppression evidence. The goal is not more sources for their own sake, but a protocol distribution that fits broad internal packet visibility.
- Expand the low-frequency application and transport tail so internal `conn.log` is not overwhelmingly explained by five service families. Preserve the strong existing tuple, lifecycle, and source-observation correlation when doing so.
