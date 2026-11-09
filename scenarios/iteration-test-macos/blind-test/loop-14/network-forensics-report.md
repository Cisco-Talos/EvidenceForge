# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 62
**Synthetic-Confidence Score:** 46

## Executive Summary

The Zeek records show plausible enterprise traffic, source-specific protocol mixes, and coherent event ordering across connection, DNS, HTTP, and TLS logs. Two focused behaviors stand out: an internal host makes 237 encoded-looking TXT queries in about 15 minutes, and a web server performs a tightly bounded subnet scan; both have credible network explanations, so neither alone establishes synthetic origin. I found no impossible network ordering or clear source-native contradiction.

## Evidence For Synthetic

- [distribution_texture] `zeek-core/dns.json` records 237 TXT lookups from `10.10.2.30` between 2026-11-02 17:44:40 and 17:59:30 UTC under `ns1.westbridge-services.cloud`. All queried names are unique; their first labels are lowercase hexadecimal strings of even lengths from 14 to 28 characters, and most returned TXT values also look encoded. This is a sharply constructed tunnel-like stream and is the strongest synthetic-looking pattern. It is also consistent with deliberate DNS tunneling, so I treat it as a weak authenticity indicator rather than a defect.
- [weak_signal] In `zeek-dmz/http.json`, a large share of HTTP transactions are `CONNECT` requests to `10.10.3.20:8080`, and the same sensor records outbound TLS. This fits an explicit proxy path, but the concentration of one proxy-style pattern gives less evidence of diverse direct client traffic. Because the network sensor may intentionally sit on that path, this is only a weak signal and does not affect the verdict by itself.

## Evidence For Real

- `zeek-core/conn.json`, `zeek-dmz/conn.json`, and `zeek-db/conn.json` have distinct, plausible traffic profiles: the core view has substantial DNS/Kerberos/LDAP and proxy traffic; the DMZ view has external TLS, proxy and web traffic; and the DB view is dominated by MySQL connections. The visible sensor scopes explain the different volumes and mixes.
- DNS has a varied query-type mix (A, AAAA, PTR, SRV, TXT, NS, MX, SOA) and response outcomes, including NOERROR, NXDOMAIN, SERVFAIL, and REFUSED. Query RTTs vary rather than collapsing to one fixed value.
- HTTP includes CONNECT, GET, and POST requests; successful responses; redirects; authentication/proxy denials; and occasional gateway errors. TLS includes TLS 1.2 and 1.3 with several cipher suites, and both established and failed handshakes.
- The 2026-11-02 14:40 UTC scan from `10.10.3.10` is operationally plausible. `WEB-EXT-01.meridianhcs.local/ecar.json` shows `nmap -sn 10.10.2.0/24` created at 14:40:26.657 UTC before the ICMP sweep in `zeek-dmz/conn.json` at 14:40:29–32. A second `nmap -Pn -sT -p 22,80,443,445,3306 10.10.2.0/24` process starts at 14:40:35.885 UTC before the corresponding TCP sweep at 14:40:38–45. Zeek reports a mix of S0, REJ, SF, and reset outcomes rather than one uniform result.
- DNS, HTTP, and SSL records in each Zeek sensor view reference connection UIDs present in that view. Their timestamps are at or after the connection start; HTTP and SSL records do not visibly extend beyond the associated connection lifetime. This supports internally coherent sensor records. The matching itself is not synthetic evidence.

## Detailed Analysis

### Scope and volume

The three Zeek connection files cover approximately six hours on 2026-11-02 UTC. `zeek-core/conn.json` contains 11,972 records, `zeek-dmz/conn.json` 9,220, and `zeek-db/conn.json` 420. The different source counts and traffic profiles are plausible for core, DMZ, and database observation points; the smaller DB view is concentrated on its database host and related services rather than appearing as a randomly truncated copy of the other sensors.

### Connections and protocols

The core connection view is mainly TCP and UDP, with 9,711 SF and 1,893 S0 records plus a smaller mix of resets, rejections, and partial states. DNS, Kerberos, LDAP, HTTP on port 8080, SMB, TLS, SSH, SMTP, and Syslog appear. In the DMZ view, TLS, HTTP, and DNS are prominent, alongside inbound and outbound service traffic. The database view has 249 connections to port 3306, predominantly identified as MySQL, which is consistent with a narrow DB sensor scope.

At 14:40 UTC, `10.10.3.10` contacted 256 distinct `10.10.2.x` destinations with ICMP and TCP probes to ports 22, 80, 443, 445, and 3306. Most probes are S0, while some are accepted or rejected. The fixed target and port set is expected from the visible nmap commands, and the Zeek start times follow the corresponding process starts. The scan is conspicuous activity, but its compactness and cross-source clarity do not count as synthetic evidence on their own.

### DNS

The core resolver traffic has a broad query-type mix and includes ordinary internal name lookups as well as public-domain queries. Query response times vary. The main outlier is `10.10.2.30`'s 237 TXT queries to the same domain over 15 minutes. Query labels and returned strings look encoded, TTL values are short, and there are a few NXDOMAIN, REFUSED, and SERVFAIL results among successful answers. This is strongly tunnel-like and warrants investigation as network behavior. Since tunneling software can create exactly this pattern, I cannot distinguish a plausible modeled or real incident from synthetic construction from the DNS data alone.

### HTTP and TLS

`zeek-core/http.json` contains 2,138 records, mostly CONNECT requests to the explicit proxy at `10.10.3.20:8080`, with a smaller set of GET/POST records and varied HTTP outcomes. The DMZ view contains 2,376 HTTP records, including proxy egress and traffic to the visible web service. Its 2,662 SSL records include TLS 1.2 and TLS 1.3; the more common suites are modern AEAD suites, with a smaller number of CBC suites. Certificate and SSL references are present, and the observed handshake outcomes include a small failed subset.

### Timing and correlation

For the examined Zeek files, DNS, HTTP, and SSL UIDs resolve to connection records in the same sensor view. DNS timestamps are at or after connection start; HTTP and SSL observations are not visibly before their connections or materially beyond their recorded lifetimes. The scan's process creation and flow timing also agree at the visible level. I did not find a visible dependent network event that predates its initiating scan process, or a field-value contradiction that would force a synthetic verdict. Complete UID matching is treated as coherence evidence only, not as a synthetic indicator.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the synthetic-confidence score |
|---|---|---|---|
| `distribution_texture` | Zeek DNS (`zeek-core/dns.json`) | 237 unique TXT lookups from `10.10.2.30` to one domain in 15 minutes; encoded-looking hex labels and response strings | This concentrated, highly encoded stream is a concrete tunnel-like texture. It is compatible with plausible malicious DNS behavior, so it raises suspicion without proving synthesis. |
| `weak_signal` | Zeek HTTP (`zeek-core/http.json`, `zeek-dmz/http.json`) | CONNECT-heavy traffic through `10.10.3.20:8080` | A narrow proxy path limits visible protocol diversity, but the traffic is consistent with an explicit proxy and sensor placement. It has little weight. |

## Realism Score by Category

- **Field format accuracy:** 9 — Zeek connection, DNS, HTTP, and SSL records have coherent source-native fields and matching UID references.
- **Temporal patterns:** 8 — Normal connection lifetimes and observable scan-to-flow ordering; one concentrated TXT-query burst is unusual but plausibly intentional.
- **Cross-source correlation:** 9 — EDR flow observations and Zeek records agree on the scan's addresses, ports, and timing; complete matching is not treated as a synthetic clue.
- **Behavioral realism:** 7 — Proxy traffic and scan behavior are plausible; the encoded TXT stream is a strong and unusual tunnel pattern.
- **Environmental consistency:** 8 — The three sensor views have different volumes and protocol mixes that fit their apparent network positions.

## Recommendations

- If this were synthetic, make the DNS-tunnel profile reflect a specific modeled protocol or vary the visible encoding and response behavior. The current 237-query sequence has exclusively unique, even-length hexadecimal first labels under one domain and consistently short TTLs, making the tunnel pattern unusually explicit.
- If the intended collection includes direct client egress, include representative direct flows or clarify the proxy observation path. If all web egress is intentionally proxied, the existing CONNECT-heavy mix is consistent with that scope.
