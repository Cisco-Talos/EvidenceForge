# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 44

## Executive Summary

The network evidence is technically coherent across three Zeek sensors, with credible connection states, proxy behavior, DNS diversity, and TLS visibility. The strongest synthetic suggestion is unusually stable, target-specific RDP transport-to-logon timing across separate sessions; repeated DNS lookups within positive cache lifetimes add a weaker concern. Neither establishes an impossible relationship, and I found no hard source-native contradiction in the checks performed.

## Evidence For Synthetic

- [distribution_texture] RDP transport-to-successful-logon delays cluster tightly by target across otherwise separate sessions. Matching `zeek-core/conn.json` TCP/3389 tuples to target eCAR `USER_SESSION/LOGIN` records gives DC-02 delays of **7.504377, 7.512696, 7.522372, and 7.532331 seconds**; FILE-SRV-01 gives **6.550805, 6.553786, and 6.539774 seconds**. These sessions span different times and, on both targets, different principals. Such narrow, target-specific timing suggests a fixed timing recipe. Small sample sizes, stable authentication infrastructure, and differences between sensor and endpoint clocks remain credible alternatives, so this is not a causality violation.
- [weak_signal] Windows clients repeatedly resolve names before earlier positive TTLs expire. In `zeek-core/dns.json`, 84 successive same-client/same-name A-query pairs among 417 successful A-query records from six Windows workstation addresses fall within the preceding answer's minimum TTL. For example, WS-MCHEN-01 (`10.10.1.31`, confirmed by its endpoint FLOW records) queries `DC-01.meridianhcs.local` at **14:16:01.445830** and **14:16:33.360789 UTC**, receiving the same A answer and a 300-second TTL. Direct DNS queries, cache bypass, service-specific resolvers, and cache invalidation can explain this; the observation receives little weight alone.

## Evidence For Real

- Connection states include failed attempts, resets, partial sessions, and established traffic, with internally consistent histories. Core contains 9,917 SF, 1,629 S0, 166 RSTO, 102 RSTR, 40 REJ, and several partial states, rather than an all-success population.
- DNS includes A, AAAA, PTR, SRV, TXT, NS, MX, and SOA queries on core, with 213 NXDOMAIN, 12 SERVFAIL, and 6 REFUSED outcomes. Core DNS RTTs range from 0.000055 to 2.336072 seconds.
- TLS visibility respects the encryption boundary: none of the **2,286 TLSv13 rows** across the sensors exposes a certificate chain. TLSv12 includes both full and resumed handshakes; checked ECDSA cipher selections agree with ECDSA leaf keys.
- The explicit proxy has separate client-to-proxy CONNECT and proxy-to-origin TLS connections. Proxy control-message bytes are distinguished from tunnel bytes, and the first visible exchange has coherent byte totals across sources.
- Matched protocol tuples and lifetimes are consistent: every DNS, HTTP, and SSL UID resolves within its own sensor's connection file; none of those records precedes its connection or falls after its visible close. DNS response times also fit within the corresponding connection intervals.
- Successful endpoint Type 10 logons match substantial, established RDP transports rather than the short probes also present on port 3389. All 13 examined logons have matching SF connections and occur after transport start.

## Detailed Analysis

### Scope and method

I examined only the assigned data directory and briefing. The review parsed all three sensors' connection, DNS, HTTP, SSL, files, and X.509 JSON records, inspected supporting SMTP, DHCP, SMB, firewall, proxy, and IDS examples, and used endpoint eCAR records selectively for ownership and RDP timing. All times below are UTC on 2026-11-02. Sensor counts are observations, not unique network transactions; overlapping sensor views must not be summed as independent activity.

Core has **12,351 connections**, DMZ **10,267**, and DB **470**. Core spans approximately 13:00:01–18:59:55; the DB sensor's first connection is at 13:05:23 and last at 18:54:45. This is insufficient to judge overnight, weekend, or full-day cadence. Missing activity outside the visible window was not scored.

### Transport integrity and protocol distribution

Core contains 7,007 TCP, 4,925 UDP, and 419 ICMP records. DMZ has 8,759 TCP, 1,204 UDP, and 304 ICMP records, with a greater failed-attempt population: 2,258 S0 connections. DB is dominated by MySQL, including 245 connections with the `mysql` service label, which fits its visible traffic role.

Checks found no S0 connection with responder packets or responder payload, no TCP SF history missing either endpoint's FIN marker, and no content-gap history with zero `missed_bytes`. The inverse gap check also passed. No connection claimed more than 65,535 IP bytes per observed packet, and gap-free TCP payload accounting had sufficient IP/TCP overhead. No same-sensor, same-direction TCP five-tuple had overlapping visible connection intervals in the adjacent-interval check.

Long-lived sessions coexist with short transactions. For example, core SSH UID `CXkzSU6i2Ghqz62Q1h` connects `10.10.1.35:49676` to `10.10.3.10:22` for 3,384.336174 seconds, with bidirectional payload and SF closure. DB MySQL UID `C1zOBNOImeO5rlOpAPy` lasts 0.296972 seconds with 1,809 originator and 45,387 responder bytes. There is no expectation that every service share one duration model.

### Proxy and HTTP evidence

HTTP counts are 2,647 core, 2,936 DMZ, and 29 DB. Most are CONNECT requests, so the large HTTP row count does not imply that most application content is unencrypted web traffic. Core has 2,442 CONNECT rows and DMZ 2,517, alongside GET/POST traffic and varied response codes, including 407, 403, gateway failures, redirects, and cache-related responses. Transaction depths reach seven, providing evidence of HTTP connection reuse.

The initial client exchange is `10.10.1.41:61726 → 10.10.3.20:8080`, visible under different core and DMZ UIDs. The proxy row at 13:00:01 reports 386 client control bytes plus 1,340 tunnel bytes, matching the connection's 1,726 originator bytes. Its 133 response control bytes plus 23,862 tunnel bytes match 23,995 responder bytes. DMZ separately observes `10.10.3.20:43730 → 199.232.64.133:443` with SNI `registry.npmjs.org`; ASA records show a corresponding dynamic translation to `203.14.220.1:4259`.

These relationships support technical plausibility. Their completeness itself was not used to infer either authenticity or synthetic origin.

### DNS and TLS

DNS row counts are 3,262 core, 1,147 DMZ, and 40 DB. Every checked answer vector has a matching TTL-vector length. Query timestamps plus RTT remain within the matching connection lifetime. The first visible proxy-origin lookup has a response before the subsequent TLS exchange; I did not require a fresh DNS query for every connection, because cached and pre-window resolutions are legitimate.

The repeated Windows lookups described above merit investigation, particularly the 31.914959-second repeat against a 300-second TTL. Another same-client example resolves `FILE-SRV-01.meridianhcs.local` at 17:17:27.199000 and 17:39:34.200600, 1,327.001600 seconds apart, with a preceding TTL of 1,800 seconds. These are cache-behavior questions, not violations of the DNS wire protocol.

TLS counts are 423 core, 3,148 DMZ, and 29 DB. DMZ has 2,090 TLSv13 and 1,053 TLSv12 rows, plus five rows lacking a negotiated version; DB's 29 TLS rows are TLSv12. The DB mix is possible for a distinct application population and was not scored as an obsolete-network defect.

For visible certificate chains, each checked child issuer matches the next certificate's subject. Repeated fingerprints retain consistent certificate fields, associated files SHA-1 values match fingerprints, and repeated file hashes retain consistent total sizes. No observed certificate is outside its logged validity interval. These checks cannot verify signatures without certificate bytes, but reveal no internal identity contradiction.

### Remote access and timing texture

The 13 endpoint Type 10 logons correlate to successful RDP connections with realistic session-scale byte volumes and durations. For example, DC-02's source port 63966 uses UID `ChhjxtJEhlgHHuEFDA`, duration 1,212.717211 seconds, 115,002 originator bytes, and 1,385,440 responder bytes. Its successful login follows network start by 7.504377 seconds. Short, low-byte port-3389 connections from the monitoring address were not assumed to be authenticated desktop sessions.

The concern is the narrow variation in transport-to-authentication delays, not their ordering. DC-02's four values span only **27.954 milliseconds**; FILE-SRV-01's three span **14.012 milliseconds**. DC-01's three values are 6.913541, 6.872945, and 6.868348 seconds. Session durations and payload sizes vary substantially, while authentication lag remains clustered by target. This pattern raises a bounded timing-texture concern, but the data do not establish whether synchronized clocks, clock offsets, or a stable operational workflow caused it.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Zeek TCP/3389 and target eCAR Type 10 logons | 13 sessions; strongest repeated clusters on DC-02 and FILE-SRV-01 | Main synthetic suggestion: unusually narrow, target-specific transport-to-login delays; possible clock/workflow explanations limit weight. |
| weak_signal | Zeek core DNS and endpoint ownership | 84 within-TTL successive query pairs among 417 successful A-query records from six Windows workstations | Small upward adjustment: repeated cache-eligible lookups; resolver and cache policy are unknown. |

No hard contradiction, demonstrated contract gap, or demonstrated schema defect was established. The score reflects a technically convincing network dataset with a specific timing concern, not a confident attribution of its origin.

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed fields, transport accounting, TLS key types, file hashes, and certificate-chain identities are internally coherent.
- **Temporal patterns:** 7 — Connection/protocol lifetimes pass checks, but repeated RDP authentication delays show unusually narrow target-specific clusters.
- **Cross-source correlation:** 9 — Proxy, NAT, protocol UID, and remote-session evidence align without a demonstrated contradiction.
- **Behavioral realism:** 8 — Credible failures, connection reuse, protocol diversity, and varied session scales; DNS caching behavior remains uncertain.
- **Environmental consistency:** 8 — DB, DMZ, proxy, monitoring, and workstation roles fit observed traffic; the six-hour window limits broader judgment.

## Recommendations

- If this were synthetic, investigate the RDP transport-to-login timing rule. Preserve valid transport-before-authentication ordering while allowing measured variation from authentication method, credential negotiation, target load, and session reuse; model clock offsets separately from actual protocol latency.
- If this were synthetic, distinguish clients using an OS DNS cache from applications issuing direct DNS requests. Honor positive cache lifetimes where appropriate, while retaining explicit cache bypass, expiry, invalidation, and service-specific resolver behavior.
- Preserve the existing TLSv13 certificate visibility boundary, certificate/file identity consistency, and proxy control-versus-tunnel byte accounting. No concrete evidence supports adding arbitrary sources or increasing record volume merely to make the collection look busier.
