# Network Forensics Analyst — Feature-Branch Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 69

## Executive Summary

The network telemetry is unusually strong in protocol accounting, dual-sensor correlation, DNS cache behavior, proxy traversal, and Zeek UID lifecycle integrity. However, the ASA ICMP records contain a concrete semantic contradiction: identical source/destination paths alternate between `inbound` and `outbound`, while TCP and UDP apply a stable zone-direction rule. The firewall connection-number allocation also shows pronounced family-like, nonchronological blocks, supporting a synthetic origin despite otherwise high realism.

## Evidence For Synthetic

- **hard_contradiction — inconsistent ASA ICMP direction:** For the identical visible path `faddr 10.10.3.10` to `laddr 10.10.2.10`, `%ASA-6-302020` labels five sessions `outbound` and one `inbound`. For `10.10.3.10` to `10.10.2.20`, it labels four `outbound` and three `inbound`. The matching Zeek records consistently identify `10.10.3.10` as the originator with ICMP type 8 and the 10.10.2.x host as responder/type 0. A slice boundary cannot change the direction of the same routed path.

- **schema_or_format — contradiction with the firewall’s own zone semantics:** TCP and UDP are internally consistent: all 1,292 DMZ-to-inside TCP builds and all 836 DMZ-to-inside UDP builds are `inbound`; inside-to-DMZ, DMZ-to-outside, and inside-to-outside are consistently `outbound`. Only ICMP varies according to apparent activity family, suggesting the direction field was selected by separate generation paths rather than derived from topology.

- **distribution_texture — connection IDs look allocated by event family rather than device chronology:** All 6,994 TCP/UDP build IDs are unique, but 1,302 adjacent build records decrease and 5,528 IDs fall below a previously observed maximum. Rollbacks reach 4,456 IDs. Multiple increasing subseries are interleaved—for example, early inbound-scan IDs around 1,686,107 coexist with later-recorded DNS/proxy IDs around 1,685,742. Hardware concurrency can cause limited ordering noise, but this much structured block interleaving is generator-like.

- **distribution_texture — deterministic external address preference:** Repeated multi-answer DNS responses preserve exactly the same answer order throughout the six-hour window, and high-volume TLS clients always select the first IPv4 answer. Examples include 79 `ctldl.windowsupdate.com` TLS sessions to only `52.114.132.73`, 69 `na139.salesforce.com` sessions to only `13.110.54.9`, and 39 `pypi.org` sessions to only `151.101.0.223`, despite each name repeatedly returning two addresses. Resolver caching explains some stickiness, but universal first-answer selection across unrelated services is overly deterministic.

- **environment_or_collection_plausibility — no visible NTP:** Neither of 14,861 Zeek connection rows includes UDP/123, despite domain controllers, Windows clients, Linux hosts, mail systems, application/database servers, and six hours of broad internal/interzone visibility. This is a moderate absence, not a standalone verdict driver.

- **weak_signal — excessively clean TLS analyzer outcomes:** All 2,253 SSL rows across both sensors are `established:true`; none records a failed or partial handshake. S0 port-443 scans appropriately lack SSL rows, so this is not a contract violation, but real enterprise TLS observations commonly include at least a small failed-handshake tail.

## Evidence For Real

- The Zeek connection mix has credible breadth and long tails: core contains 5,330 `SF`, 1,500 `S0`, plus `RSTO`, `RSTR`, `REJ`, `OTH`, `S1`, `S2`, and `S3`; DMZ contains 5,051 `SF`, 2,607 `S0`, and similar secondary states. Durations are highly varied rather than fixed.

- Shared traffic is rendered realistically from two sensor positions. I matched 3,918 five-tuples within two seconds. The sensors use no common UIDs, yet all 3,918 agree on `conn_state`; most byte and packet counts agree while histories and durations show plausible observation differences. Their clocks exhibit a stable approximately 114 ms offset.

- Protocol fan-out is temporally valid. All 1,870 core and 838 DMZ DNS rows, 1,529 core and 1,744 DMZ HTTP rows, and 102 core and 2,151 DMZ SSL rows reference a connection UID. None precedes its connection or falls after the visible connection interval. File UIDs also resolve without missing or post-close records.

- DNS behavior is especially credible. It includes A, AAAA, PTR, SRV, TXT, NS, MX, and SOA traffic; NOERROR, NXDOMAIN, SERVFAIL, and REFUSED outcomes; suffix-search failures such as `wpad.local` and `isatap`; and RTTs from roughly 0.1 ms to 2.01 seconds. Every DNS RTT fits within its connection duration.

- DNS TTLs preserve recursive-cache texture. For `ctldl.windowsupdate.com`, TTL 3,069 at 08:28:30 declines to 367 at 09:13:32—exactly consistent with roughly 2,702 elapsed seconds—then refreshes after expiry. This is much more realistic than independently randomized TTLs.

- TLS has plausible protocol-era composition and parser behavior: core has 56 TLS 1.3 and 46 TLS 1.2 rows; DMZ has 1,451 TLS 1.3 and 700 TLS 1.2. Cipher selection varies by version, resumption occurs in 784 sessions, and TLS 1.3 sessions lack visible certificate chains while TLS 1.2 full handshakes provide them, consistent with encrypted TLS 1.3 certificate messages.

- Every one of 897 certificate-chain references resolves to an X.509 row; none is unreferenced, and no certificate is outside its validity interval at observation time.

- HTTP proxy behavior is structurally sound. Core sees client `CONNECT` traffic to `10.10.3.20:8080`, while DMZ sees high-volume proxy-origin TLS from `10.10.3.20`. Statuses include 200, 301, 302, 304, 403, 404, 407, 502, 503, and 504, and persistent connections have correct sequential transaction depths.

- Apparent HTTP body/accounting discrepancies are explained by packet loss fields. Two core flows have summed HTTP response bodies larger than `resp_bytes`, but their `missed_bytes` values cover the difference and corresponding file records consistently divide `total_bytes` into `seen_bytes + missing_bytes`.

- Firewall byte accounting correlates tightly with Zeek. For the outbound TLS flow `10.10.3.20:50464` to `172.217.234.234:443`, ASA reports 36,672 bytes, exactly equal to Zeek’s combined originator and responder IP-byte totals.

- All 61 parsable core Snort TCP/UDP alerts and all 85 parsable perimeter alerts match a visible Zeek five-tuple within five seconds. Sensor-relative timing offsets are bounded and consistent rather than identical.

- External scanning has realistic lifecycle evidence: Zeek S0/SYN-only states correspond to ASA built records followed by 30-second `SYN Timeout` teardown messages with zero bytes. Successful application/database, SMB, SSH, SMTP, IMAP, proxy, and web traffic coexist with that background noise.

- DHCP renewal timing is jittered rather than clockwork. Active clients show intervals near T1 with meaningful variation, and less-complete clients exhibit plausible observation gaps.

## Detailed Analysis

The six-hour interval spans approximately 12:00–18:00 UTC and contains 6,980 core and 7,881 DMZ Zeek connections. Core visibility is dominated by DNS, proxy HTTP, Kerberos, LDAP, SMB, and internal infrastructure traffic, while DMZ visibility is dominated by proxy-origin TLS, HTTP, DNS, inbound scanning, and 580 application-to-database connections on TCP/3306. This division is coherent with the observed network roles.

Connection-state and byte contracts are generally excellent. No `SF` connection has zero responder packets or zero bidirectional payload, no `S0` connection has responder packets, and all DNS RTTs fit inside their parent connection durations. TCP header/accounting values vary with packetization; UDP and ICMP exhibit the expected fixed per-packet IPv4/transport overhead. HTTP and file logs preserve transaction depths, body sizes, missing-byte accounting, and connection intervals.

The proxy model is also convincing. Client-facing `CONNECT` rows occur primarily from workstation and server addresses to the proxy on 8080. The DMZ sensor then sees 1,534 TLS sessions originated by the proxy. The two sensor perspectives do not simply duplicate records: they generate distinct UIDs, stable clock offsets, and small packet/history variations while preserving state and tuple identity.

The decisive problem is the ASA ICMP direction field. At 13:43:47, a sweep from `10.10.3.10` across 10.10.2.x is labeled `inbound`; routine pings over the same DMZ-to-inside path are often labeled `outbound`. Later traffic on the exact same source/destination pair flips back again. The corresponding TCP and UDP paths never exhibit this ambiguity. This looks like one code path labeling scan-origin ICMP as inbound and another labeling routine-origin ICMP as outbound, rather than both consulting one canonical interface/security-zone decision.

Connection-number sequencing reinforces that concern. The values are unique and broadly increase over the full interval, but they repeatedly jump backward into lower, internally increasing ranges. This resembles identifiers reserved during independent event-family planning and later emitted in timestamp order. It is less conclusive than the ICMP direction defect because a multithreaded appliance may allocate ranges per worker, but the scale and repeated subseries are atypical.

The fixed DNS answer ordering and universal first-address use are another generator texture. The TTL cache decay itself is very good, so this is not simplistic DNS generation; the defect is specifically the lack of endpoint-selection diversity after repeated cache refreshes across unrelated multi-address services.

Overall, the telemetry is substantially more realistic than ordinary synthetic logs. Most contracts that frequently expose generators—UID joins, conn/protocol ordering, missed-byte accounting, dual-sensor differences, TLS certificate handling, NAT byte totals, and IDS tuple matching—hold. The verdict rests on a narrow but concrete firewall semantic inconsistency plus two dataset-wide distribution patterns.

## Synthetic Indicator Summary

- **hard_contradiction | ASA ICMP direction derivation | repeated identical DMZ-to-inside paths | +20**
- **schema_or_format | ICMP direction conflicts with stable TCP/UDP zone semantics | firewall-wide ICMP family | +8**
- **distribution_texture | nonchronological connection-ID block allocation | 6,994 ASA TCP/UDP builds | +9**
- **distribution_texture | fixed multi-answer DNS order and universal first-IP use | popular external TLS services | +6**
- **environment_or_collection_plausibility | absent UDP/123 | both Zeek sensors and ASA, six hours | +3**
- **weak_signal | no failed SSL analyzer outcomes | 2,253 SSL rows | +2**
- **realism offset | dual-sensor and source-native correlation fidelity | 3,918 shared tuples plus ASA/Snort | -8**
- **realism offset | protocol lifecycle and accounting integrity | DNS/HTTP/SSL/files/X.509 | -6**
- **realism offset | cache-aware DNS TTL and broad behavioral texture | collection-wide | -5**

## Realism Score by Category

- **Field format accuracy:** 8/10 — Zeek, Snort, and ASA syntax is generally strong, but ASA ICMP direction semantics are internally inconsistent.
- **Temporal patterns:** 8/10 — Durations, DNS RTTs, TTL decay, DHCP jitter, scan timeouts, and sensor offsets are credible; connection-ID chronology is suspicious.
- **Cross-source correlation:** 9/10 — UIDs, tuples, bytes, files, certificates, IDS alerts, NAT, and two Zeek viewpoints correlate exceptionally well.
- **Behavioral realism:** 8/10 — Proxy use, AD traffic, application-to-database activity, mail, scanning, web clients, and failure states form a convincing enterprise mix.
- **Environmental consistency:** 7/10 — Roles and routing are mostly coherent, but inconsistent ICMP direction and absent time synchronization reduce confidence.

## Recommendations

- Derive ASA ICMP `inbound`/`outbound` from the same canonical interface/security-zone routing decision used for TCP and UDP. Add a test asserting that identical origin/destination zone pairs cannot change direction merely because one event belongs to a scan and another to baseline activity.

- Allocate ASA connection IDs at chronological firewall-observation time, or model a documented appliance allocation strategy. Avoid reserving identifier blocks in independent activity families before final timeline merge.

- Rotate multi-address DNS answer order across cache refreshes and let endpoint selection vary by client/address-family policy, while preserving the otherwise excellent TTL countdown behavior.

- Add low-volume UDP/123 activity appropriate to Windows domain time hierarchy and Linux infrastructure if the collection is intended to represent broad interzone telemetry.

- Include a small, source-native tail of TLS handshake failures, version intolerance, client aborts, or certificate-validation failures where the visible packet lifecycle supports them.
