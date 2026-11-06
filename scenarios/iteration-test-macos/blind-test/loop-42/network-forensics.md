# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 32

## Executive Summary

The network data is mostly production-like: transport states, protocol companions, explicit proxy routing, certificate identity, and packet accounting are coherent across three sensor locations. I found a mild DNS caching texture and a small number of locally unresolved HTTP file references, but neither establishes synthetic origin given the unspecified collection/filtering policy; I found no demonstrated impossible network relationship.

## Evidence For Synthetic

- [weak_signal] Repeated successful domain-controller address queries often disregard an apparently usable five-minute answer: in `zeek-core/dns.json`, 1,014 successful A queries for `DC-01.meridianhcs.local` or `DC-02.meridianhcs.local` form 972 successive same-client/same-name pairs, of which 307 recur within 300 seconds. Lines 956–957 show `10.10.2.20` requesting `DC-01.meridianhcs.local` twice 12.724120 seconds apart, obtaining `10.10.2.10` with TTL 300 both times, through different DNS servers. This is a possible per-activity resolution texture, but separate applications, bypassed client caches, and resolver changes are viable explanations. It modestly affects the score rather than proving a protocol violation.
- [weak_signal] Seven HTTP file references lack a matching `fuid` in that sensor's supplied `files.json`: core HTTP lines 242, 739, 1163, 1579, 1871, and DMZ HTTP lines 167, 1753. For example, core line 242 reports response file `F3C6uHUYNC8TOxDznFH` for a successful 13,861-byte SVG response, but the local files log has no such ID. This is a concrete local reference-resolution limitation, although independent file-log filtering or export loss can explain it. I do not interpret it as evidence that a whole missing source should have been collected.

## Evidence For Real

- `zeek-core/conn.json:3` and `dns.json:1` agree on UID `CjDNb6JkkB4AVNEsy7r`, the full UDP tuple, and duration/RTT `0.001043`; the SRV answer names two domain controllers on LDAP/389. The packets and IP-byte totals also agree with the DNS payload sizes.
- Explicit proxy use is represented as separate client-to-proxy and proxy-to-destination connections. Core HTTP line 1 is a CONNECT to `10.10.3.20:8080`; DMZ DNS line 1 resolves its hostname; DMZ conn line 13 and SSL line 1 show the proxy's independent connection to the resolved address. This represents the actual observation path rather than treating the client as the external TCP initiator.
- The proxy's first access row accounts for 375 client control bytes plus 3,680 tunnel bytes, matching core conn line 23's 4,055 originator bytes; 156 control-response bytes plus 31,877 tunnel bytes match its 32,033 responder bytes. The tunnel totals also match the upstream DMZ connection. These are meaningful semantic relationships, not merely copied UIDs.
- Connection states include unsuccessful SYNs, rejections, both reset directions, partial connections, and midstream observations, with appropriate histories and packet accounting. DMZ conn line 1, for example, is an unanswered one-packet SYN with `S0`, history `S`, and zero responder packets/bytes; the first two perimeter firewall rows record a corresponding build and 30-second SYN timeout.
- DNS has A, AAAA, PTR, SRV, TXT, MX, NS and SOA queries, plus NXDOMAIN, REFUSED and SERVFAIL outcomes. Core DNS lines 16 and 34 have successful empty AAAA answers for internal names, rather than inventing IPv6 addresses for every host.
- TLS includes TLS 1.2 and 1.3, resumed and full sessions, modern AEAD ciphers, and some CBC compatibility traffic. In the visible chains, certificate SANs match SNI, certificate validity covers the observed session, and repeated fingerprints retain consistent certificate identity across sensors.

## Detailed Analysis

### Scope and method

I parsed all supplied Zeek JSON records from `zeek-core`, `zeek-dmz` and `zeek-db`, focusing on 20,822 connection records, 3,965 DNS records, 4,220 HTTP records, and 2,751 SSL records. I also examined their certificate/file companions, SMB/DHCP/SMTP records, and samples of the supplied perimeter firewall, proxy and Snort records. Counts are sensor observations and may include the same traffic seen at multiple locations; they are not unique enterprise-wide connections. File references below use one-based JSON line numbers. Epoch timestamps are UTC.

For every DNS, HTTP, SSL, SMB mapping/file and SMTP row, I checked the UID against that sensor's connection log and compared the full source/destination tuple. All those references resolved and all tuples matched. No protocol timestamp preceded its connection start by more than one millisecond, or extended beyond its connection interval by more than 200 milliseconds. Those are explicit tolerances rather than claims of exact packet timestamp equality.

### Transport semantics and packet budgets

Core connection states are SF 9,489, S0 1,868, RSTO 154, RSTR 86, OTH 33, REJ 28, S2 18, S3 17 and S1 6. DMZ states are SF 5,766, S0 2,745, RSTO 81, RSTR 52, REJ 32, S2 12, S3 7, S1 7 and OTH 5. The database sensor has 363 SF observations among 416 connections. The higher failed-SYN fraction on the DMZ is plausible for an externally exposed network segment; it is not an unexplained uniform enterprise-wide failure rate.

Across all three sensors, I found no TCP SF record missing both-sided FIN history, no TCP SF record with fewer than three originator/two responder packets, no S0 record with responder traffic, and no S1 record carrying FIN/reset history. For both directions of every record, IP bytes cover recorded payload bytes plus minimum IPv4/TCP or IPv4/UDP header budgets. These checks cannot establish packet-level authenticity without PCAP, but rule out several common hard contradictions.

Long-lived administration is also differentiated from short application requests. Core conn line 41 records SSH from `10.10.1.31:50901` to `10.10.3.20:22`, duration `3499.117248`, with 37,874/172,655 payload bytes. Core conn line 756 records RDP from `10.10.1.35:65275` to `10.10.2.20:3389`, duration `445.208852`, with much more responder traffic, 1,624,700 versus 114,601 bytes. Neither is reduced to a tiny fixed-duration handshake.

### DNS and resolution ordering

The first outbound browsing example is useful because the network path is explicit. DMZ DNS line 1 starts at `1793624513.710807`, has RTT `0.037560`, and returns `151.101.1.140`/`151.101.193.140` for `www.redditstatic.com`. DMZ conn line 13 opens to the first returned address at `1793624513.759038`, approximately 10.7 milliseconds after the response, and SSL line 1 identifies the same hostname. This ordering is plausible.

All supplied DNS RTTs fit their matching connection duration, within 100 microseconds. Responses include authoritative internal answers, recursive external answers, negative responses, successful empty AAAA results, and reverse lookups. Core has 174 A/NXDOMAIN and 11 PTR/NXDOMAIN rows, among other negative outcomes. Those are ordinary operational features rather than a single successful-A template.

The repeated domain-controller lookups are the clearest mild texture concern. They occur across 42 same-client/same-name groups, not just one anomalous workstation. However, requesting again within TTL is not prohibited by DNS and cannot reveal which application cache was consulted. I therefore treat the 307 short-interval recurrences as a reason for caution, not a hard contradiction or a major score penalty.

### HTTP, TLS and proxy semantics

CONNECT dominates core HTTP: 1,667 successful tunnels, with 44 forbidden, 32 proxy-authentication-required, 12 service-unavailable, 10 gateway-timeout and 8 bad-gateway outcomes. A modern network using an explicit proxy can therefore have many HTTP analyzer rows while carrying predominantly encrypted application traffic. Counting these CONNECT rows as ordinary cleartext web browsing would mischaracterize the dataset.

The first core CONNECT (`http.json:1`, UID `C9PHy4Mfn7EDbODWoNN`) has zero HTTP entity bodies, while its conn row contains the larger tunnel traffic. The proxy access record distinguishes control-message bytes from tunnel bytes, and its sums reconcile as described above. The upstream flow uses a different source port and UID, as expected for an explicit proxy.

I checked every SSL row that exposed certificate-chain references against its sensor's X.509 records. The referenced leaf certificates were present; SNI matched SAN entries, validity intervals covered the sessions, and no fingerprint acquired conflicting certificate fields across sensors. TLS 1.3 examples appropriately lack a visible plaintext certificate chain rather than producing a universal TLS 1.2-shaped handshake.

HTTP entity references are less complete: seven listed FUIDs were absent locally. Their small number and distribution across both ordinary content and proxy errors is compatible with selective export or file-log loss. Without the collection policy, converting these into a major authenticity indictment would exceed the evidence.

### Traffic timing and environment

The core sensor's hourly connection counts for 13:00–18:59 UTC are 1,429, 3,088, 1,714, 1,677, 2,084 and 1,707. DMZ counts are 1,136, 2,626, 1,245, 1,109, 1,393 and 1,198. Activity is neither exactly flat nor scheduled into identical hourly totals. The six-hour daytime window cannot establish overnight infrastructure behavior, weekend behavior or a full diurnal cycle.

Core includes Kerberos, LDAP, SMB, SMTP and syslog alongside proxy traffic; the database sensor is dominated by MySQL (261 service-identified connections). That segregation is consistent with differing observation locations. I do not infer mandatory endpoint or protocol coverage from the names of the sensors or the presence of Mac-originated network traffic.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| weak_signal | Zeek DNS | 307 of 972 successive same-client/DC-name A-query pairs recur within a 300-second TTL | Mild possible per-activity resolution texture; independent caches and resolver changes remain credible. |
| weak_signal | Zeek HTTP/files | Seven HTTP FUIDs absent from that sensor's supplied files log | Small local linkage limitation; filtering/export loss prevents confident attribution to generation. |

No verified `hard_contradiction` was found. Complete matching elsewhere is not scored as a synthetic indicator.

## Realism Score by Category

- **Field format accuracy:** 9 — JSON records, transport fields, DNS answers, HTTP bodies and TLS/certificate identities are internally coherent in the checks performed.
- **Temporal patterns:** 8 — Variable rates and session lengths are plausible; repeated DNS within TTL is a mild reservation, and the window limits diurnal assessment.
- **Cross-source correlation:** 9 — Protocol/connection tuples and meaningful proxy byte relationships agree; seven local file references remain unresolved.
- **Behavioral realism:** 8 — Proxy errors, failed flows, infrastructure protocols, browsing and long-lived administration have differentiated characteristics.
- **Environmental consistency:** 9 — Protocol distributions fit core, DMZ and database observation paths without requiring unobserved collectors.

## Recommendations

- If this were synthetic, model host/application DNS caching explicitly for the repeated DC-name A requests, while retaining realistic cache bypass and independent resolver behavior. Use core DNS lines 956–957 and the 307 short-interval pairs as concrete review cases.
- If this were synthetic, preserve local HTTP-to-files linkage when both logs are intended to be complete, or make the file-log export/filtering policy explicit. Review the seven exact HTTP line references above; do not fill unrelated source families merely to increase coverage.
