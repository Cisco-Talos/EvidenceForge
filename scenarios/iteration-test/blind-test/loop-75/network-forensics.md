# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive  
**Verdict Confidence:** 68  
**Synthetic-Confidence Score:** 57

## Executive Summary

The Zeek records contain a coherent, varied network picture over roughly six hours: ordinary DNS and directory traffic, proxied web access, TLS, mail, SMB, database sessions, failed connection attempts, and inbound probing. Companion DNS, HTTP, and TLS rows join to connection records by UID without dangling references in all three observed sensor sets. Service-specific behavior, DNS answers, byte counts, states, and protocol mix are mostly credible.

The strongest synthetic-looking feature is a highly regular internal fan-out from `10.10.3.10`: it probes roughly 254 addresses across the same small set of common service ports and ICMP, with many unanswered SYNs. That pattern could represent a genuine vulnerability or inventory scan, so it is not decisive by itself. The six-hour window also contains unusually dense, patterned enterprise traffic, but the network evidence does not establish whether that density or the scan is implausible for the observed environment. Overall, the network evidence supports a mixed assessment rather than a confident real or synthetic verdict.

## Evidence For Synthetic

- **[distribution_texture] Near-subnet-wide, repeated probe set.** In both broad and DMZ connection records, `10.10.3.10` reaches roughly 254 distinct internal addresses. Its destinations cluster on TCP 22, 80, 443, 445, and 3306, plus ICMP (represented with destination port 0); the broad sensor records 1,528 distinct destination-address/port pairs from this source. The broad view shows 1,240 `S0` attempts and 22 rejects among its 1,702 connections from this source. This looks like a deliberately bounded scan template. Real inventory or vulnerability scanning can produce the same shape, so it is a moderate signal, not a contradiction.
- **[distribution_texture] Very high but orderly record volume in a short interval.** The broad sensor has 12,386 connections, 3,087 DNS rows, 2,189 HTTP rows, and 389 TLS rows in about six hours; the DMZ sensor has 9,094 connections, 1,018 DNS rows, 2,408 HTTP rows, and 2,670 TLS rows over a matching interval. A busy enterprise and different sensor vantage points can explain this volume, but the high, cleanly populated activity deserves scrutiny alongside the scan pattern.
- **[weak_signal] Repeated proxy and application destinations.** The broad and DMZ HTTP logs are dominated by successful `CONNECT` requests through `10.10.3.20:8080` (1,990 and 2,021 respectively), with repeated common services such as Windows Update, Microsoft sign-in, Salesforce, package registries, and related sites. Repetition is expected for managed clients and a proxy; by itself it is weak evidence and does not imply fabricated records.

## Evidence For Real

- **Protocol and service mix is plausible.** The broad sensor includes DNS, Kerberos, LDAP, SMB, HTTP, TLS, syslog, SMTP, SSH, RDP, and DHCP; the database view is centered on MySQL; the DMZ view contains public TLS/HTTP, internal web and database traffic, DNS, and inbound attempts. The roles implied by the traffic are mutually coherent: clients query directory services and use a proxy, application traffic reaches MySQL, and servers exchange syslog.
- **Connection states and lifecycles vary credibly.** The broad view has 9,935 `SF` completed connections, 1,700 `S0` attempts, and smaller counts of resets, rejects, and partial states. The DMZ view likewise mixes 6,324 `SF` with 2,211 `S0`, resets, and rejects. Successful flows have varied durations and packet/byte counts; many unanswered SYN attempts have no duration, consistent with an incomplete handshake. No completed `SF` connection in these sets has both byte counters at zero.
- **DNS records carry useful, internally consistent answers.** For example, `_ldap._tcp.meridianhcs.local` returns both directory-controller names with matching 300-second TTLs, and an internal hostname query maps `LOG-MON-01.meridianhcs.local` to `10.10.2.40`. The observed query types, response codes, resolver behavior, and varied latency are consistent with ordinary DNS, including a modest number of `NXDOMAIN`, `SERVFAIL`, and refused responses.
- **TLS and HTTP companions agree with transport.** Every DNS, HTTP, and TLS UID examined in each sensor set has a corresponding connection UID. A sample TLS row shares its UID and tuple with a completed TCP connection, carries a plausible TLS version/cipher, and has a handshake timestamp shortly after connection start. HTTP `CONNECT` rows use the proxy endpoint and report `200 Connection Established`; external TLS rows appear in the DMZ view where that traffic is visible.
- **The database view has a coherent specialized workload.** It records 262 MySQL-service connections, chiefly between `10.10.3.10` and `10.10.4.10:3306`, with successful flows showing nonzero bidirectional data and varied durations. Its smaller DNS, syslog, TLS, HTTP, and administrative traffic is consistent with a server-specific vantage point rather than an identical copy of the broad sensor.
- **External probing is not automatically evidence of fabrication.** The DMZ records include external sources making unsuccessful attempts toward exposed internal services, including RDP. Such scan noise and failures are common at a perimeter and coexist with successful public-facing web/TLS activity.

## Detailed Analysis

### Visible collection scope

The three Zeek sets cover about six hours on the same day. The broad set sees many internal addresses and enterprise services; the database set is narrowly centered on a database host; the DMZ set sees external addresses and public-facing service traffic. The differing TLS counts (389 broad, 21 database, 2,670 DMZ) and the differing source/destination populations fit distinct vantage points. They do not look like three interchangeable exports of one identical sensor stream.

### Connections, states, and duration

Connection states are varied rather than uniform. `SF` dominates the successful broad and DMZ records, while `S0` is concentrated among unanswered attempts; the database sensor has mostly successful MySQL connections. The broad connection-duration median is about 0.029 seconds, with a 90th percentile around 4.36 seconds and a maximum around 13,342 seconds. DMZ's median is about 1.01 seconds, its 90th percentile about 5.06 seconds, and it has similarly long-lived records. Zero or absent duration is concentrated in states such as `S0` and `OTH`, not successful zero-byte sessions. These values are plausible for a mix of DNS, web, scanning, and long-running TCP traffic.

Total counted application bytes are substantial in the broad view (about 767 MB from origins and 1.29 GB from responders) and DMZ view (about 61 MB and 1.54 GB). That asymmetry is consistent with download-heavy web/TLS traffic and a proxy-heavy environment. It is not possible to infer wire utilization precisely from these counters alone.

### DNS, HTTP, and TLS

Broad DNS has 798 distinct query names among 3,087 rows, with 2,849 `NOERROR`, 219 `NXDOMAIN`, 17 `SERVFAIL`, and 2 `REFUSED`. DMZ has 513 distinct names among 1,018 rows, also with mostly successful responses and some misses. Frequent internal names and service-discovery queries coexist with external package, identity, and content services. Sanitized or modeled names are not treated as synthetic evidence.

HTTP is mostly proxy `CONNECT`, with smaller numbers of `GET` and `POST`. Status codes include normal success and redirects as well as authentication (`407`), access denial (`403`), and occasional server errors. The small error population adds realistic variation. TLS uses both TLS 1.2 and 1.3 and a mixture of common AES-GCM, ChaCha20, and older CBC suites; most TLS rows report an established session. The database sensor's all-TLS-1.2 subset is small (21 rows) and is not by itself suspicious.

UID checks found no missing connection parents for DNS, HTTP, or TLS records in any of the three sensor sets. Endpoint tuples and timestamps also align in inspected examples. This is a strong internal consistency signal, although it cannot prove the records came from a real capture.

### Lateral movement and scan-like traffic

Most internal flows follow recognizable service relationships: clients and servers query the two directory controllers, hosts use SMB, clients reach the proxy, and the application server reaches the database service. The standout deviation is the broad fan-out from `10.10.3.10` to almost an entire internal address range on a tightly bounded group of common service ports, accompanied by many unanswered attempts. The same general fan-out is visible from the DMZ-side sensor. This could be planned scanning, discovery, or a compromised host; because the destinations and ports form such a tidy repeated set, it raises synthetic confidence. It remains behaviorally possible and has no log-visible impossibility such as a completed handshake with no packets or an incompatible service tuple.

## Synthetic Indicator Summary

| Indicator | Category | Strength | Assessment |
|---|---|---:|---|
| `10.10.3.10` probes roughly 254 internal addresses over a repeated, narrow service-port set; many attempts are `S0` | distribution_texture | Moderate | Scan-like and unusually regular, but a real scanner could produce it |
| Thousands of proxy and TLS events in a six-hour window | weak_signal | Weak | High volume, but credible for distinct enterprise and DMZ vantage points |
| Frequent repeated destinations in proxied web traffic | weak_signal | Weak | Expected for managed clients and shared services |

No hard contradiction or source-format defect was found in the inspected network records.

## Realism Score by Category

| Category | Score (1-10) |
|---|---:|
| Field format accuracy | 9 |
| Temporal patterns | 7 |
| Cross-source correlation | 9 |
| Behavioral realism | 7 |
| Environmental consistency | 7 |

## Recommendations

- If the scan-like fan-out is meant to be a real administrative or security scan, preserve the broad target and port coverage but ensure its cadence and outcome mix reflect the intended scanner; if it is not intentional, reduce its near-subnet regularity.
- Keep the differentiated sensor coverage: proxy `CONNECT` and endpoint-side TLS visibility, database-specific MySQL activity, and external DMZ scan noise form a coherent network picture.
- Retain the varied DNS response codes, transport outcomes, TLS versions, packet/byte counts, and successful versus failed sessions. They provide useful texture without introducing network-level contradictions.
