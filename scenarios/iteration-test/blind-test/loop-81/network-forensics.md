# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 72
**Synthetic-Confidence Score:** 64

## Executive Summary

Zeek, proxy, and Snort records have credible source-native shapes, plausible protocol mixes, and strong UID/tuple consistency; I found no hard network-layer contradiction. I assess the dataset as synthetic with moderate confidence because two high-cardinality DNS patterns have unusually regular, generated-looking texture: a sustained TXT-query sequence and repeated random-label `.top` lookups. Those patterns could also reflect real malicious activity, so they do not support a high synthetic-confidence score alone.

## Evidence For Synthetic

- [distribution_texture] In `zeek-core/dns.json`, `10.10.2.30` issued 209 distinct TXT queries below `ns1.westbridge-services.cloud` between 2026-11-02 17:44:32 and 18:45:08 UTC. 194 of the 208 inter-query gaps were under 10 seconds (median 2.01 seconds); 185 records returned TXT values in a repeated `TXT <length> <token>` shape. Query labels and returned tokens are mostly unique, hash-like strings. This is consistent with DNS tunneling, but the tightly repeated shape and cadence also give the stream a strong generated texture.
- [distribution_texture] In `zeek-dmz/dns.json`, `10.10.3.10` made 93 unique A queries for random-looking `.top` labels during the visible window; 82 returned NXDOMAIN and 11 returned `45.33.32.30`. For the dense runs, gaps cluster around 30 seconds (median 29.9 seconds; p10 20.2, p90 39.6). This is plausible DGA behavior, but the repeated label pattern and stable cadence are a second concentrated distribution signal.
- [weak_signal] The successful `.top` answers all point to the same address, while no connection from `10.10.3.10` to that address appears within two minutes of those 11 queries. Resolution without a follow-on connection is possible (for example, a sinkhole or a blocked client attempt), so I treat this as supporting context rather than a missing-companion contradiction.

## Evidence For Real

- Zeek records use consistent JSON field shapes and plausible protocol semantics. In each sensor directory, all DNS, HTTP, SSL, and SMTP records checked had a matching `conn.json` UID and matching endpoint tuple. This degree of correlation is not itself evidence for or against authenticity.
- `zeek-core/conn.json` covers about six hours (13:00–18:59 UTC) with a mixed state distribution: 9,937 `SF`, 1,710 `S0`, plus `OTH`, resets, rejects, and a small number of partial states. It includes expected enterprise protocols such as DNS, Kerberos, LDAP, SMB, HTTPS, SMTP, SSH, and RDP. Connection durations range from sub-second transactions to longer SSH/RDP sessions.
- DNS has a credible mix rather than only suspicious queries. `zeek-core/dns.json` contains A, AAAA, PTR, SRV, TXT, MX, NS, and SOA queries; 2,908 responses are `NOERROR`, 205 are `NXDOMAIN`, and a smaller number are `SERVFAIL` or `REFUSED`. For example, UID `Czn7EtgANXswTnWoFo` at 13:00:02.107 UTC is a 25 ms UDP SRV lookup for `_ldap._tcp.meridianhcs.local`, answered by the two domain controllers with 300-second TTLs.
- Proxy and Zeek HTTP views agree on observed requests. At 13:01:43 UTC, `zeek-core/http.json` records a `CONNECT cache.dataforge.net:443` from `10.10.2.21:38105` to proxy `10.10.3.20:8080`, status 200 and `curl/7.88.1`; the corresponding first line in `PROXY-01.meridianhcs.local/proxy_access.log` carries the same client, destination, status, and user agent.
- TLS observations include TLS 1.2 and 1.3 with plausible cipher suites and SNI. For example, `zeek-core/ssl.json` records an established TLS 1.2 connection to `LOG-MON-01.meridianhcs.local` at 13:08:50.985 UTC using `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`; the DMZ sensor records TLS 1.3 handshakes to the published service.
- The suspicious activity is network-coherent. A Snort DNS alert at 13:26:45.676 UTC for `10.10.3.10:34530 -> 10.10.2.10:53` matches Zeek’s NXDOMAIN lookup for `storage-vftvanw8.cloud` on the same tuple and transaction. External scan traffic also produces both failed SYN-only connections and completed TLS flows, rather than every attempt having the same outcome.

## Detailed Analysis

### Connection states and traffic mix

The three connection datasets are `zeek-core/conn.json` (12,416 rows), `zeek-dmz/conn.json` (9,954), and `zeek-db/conn.json` (467), each spanning most of 13:00–19:00 UTC on 2026-11-02. Core traffic is dominated by TCP and UDP, with 411 ICMP records. The core state mix is mostly completed sessions (`SF`) but includes `S0`, resets, rejects, and partial states. The DMZ view similarly contains both completed inbound sessions and a substantial body of unanswered probes (`S0`).

Service placement is broadly plausible from the observed tuples: the DB sensor is dominated by MySQL to `10.10.4.10:3306` (281 connection records), while core traffic includes DNS, Kerberos, LDAP, SMB, and proxy-bound HTTP on port 8080. One example DB flow is `10.10.3.10:52368 -> 10.10.4.10:3306` at 13:02:23.248 UTC, `SF`, 4.79 seconds, with traffic in both directions. I did not treat the overlapping observations between sensor directories as a synthetic indicator; separate taps can observe the same tuple at slightly different times.

### DNS, HTTP, and TLS

Normal enterprise resolution and external browsing coexist with the suspicious DNS streams. DNS response codes and query types have reasonable variety, including suffix-search-like failures (`wpad`, `isatap`, and an appended local suffix) alongside successful internal SRV/A lookups and public service names. The DGA-like `.top` behavior is concrete, but malicious domains and sinkhole answers are possible in real telemetry; the domain names themselves are not used as evidence based on real-world reputation.

The `.cloud` TXT sequence from `10.10.2.30` is a stronger texture concern: nearly all inter-query gaps are short, each record uses a novel long subdomain, and responses repeatedly carry a length-prefixed token. That is consistent with tunneled data, but the unusually uniform record family and frequent cadence look constructed. Separately, the `.top` queries from `10.10.3.10` recur in dense runs at roughly 20–40-second intervals and mostly fail, with a subset resolving to one address. I found an outbound `SF` connection from that host to `45.33.32.30:8443` at 14:20:20.749 UTC, but it predates the later `.top` answers by hours and does not establish a query-to-flow join.

HTTP CONNECT transactions use the proxy address and carry matching host, status, and client metadata in proxy and Zeek logs. TLS records show a mixture of TLS 1.2 and 1.3, modern AEAD ciphers, SNI values, and some resumptions. I found no protocol-version or TLS/connection tuple contradiction in the sampled records.

### Scanning and alerts

`zeek-dmz/conn.json` shows 421 connections from `185.70.41.45` to `10.10.3.10`, overwhelmingly port 443, over roughly 51 minutes. The records include `S0` probes and completed TLS sessions; the SSL companion records show TLS 1.3, SNI `ehr-portal.meridianhcs.com`, and both resumed and non-resumed handshakes. The perimeter Snort log labels repeated activity from this source as rapid HTTP/HTTPS connection attempts, which is consistent with the connection evidence.

Other external sources probe several exposed service ports on `10.10.3.10`; for example, `185.220.88.13` has 188 observed connections, mostly unanswered attempts to ports 445, 3389, 135, 5985, and 139. This is a plausible scan pattern, not an impossible TCP progression. The Snort DNS alert for the `.cloud` lookup also matches the Zeek source port, resolver, and query time to within a fraction of a second.

### Window limits

The visible network window is approximately 13:00–19:00 UTC. I judged lifecycle relationships inside that window; missing starts before 13:00 or closes after 19:00 alone are not synthetic evidence. The cross-source UID and tuple matches are useful integrity checks, but completeness alone is not a synthetic clue.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the score |
|---|---|---|---|
| `distribution_texture` | Zeek DNS (`zeek-core`) | 209 unique TXT requests from one source over about an hour | Short, clustered gaps and repeated length-prefixed random-looking TXT answers suggest a generated/tunneled stream. Real DNS tunneling remains a plausible alternative. |
| `distribution_texture` | Zeek DNS (`zeek-dmz`) | 93 randomized `.top` A queries from one source, with dense runs | Random labels, a stable 20–40-second cadence within runs, and repeated resolution to one address are a notable DGA-like pattern, but can reflect real malware. |
| `weak_signal` | Zeek DNS/connection (`zeek-dmz`) | 11 successful `.top` answers | No flow to the returned address follows within two minutes; this is possible and was not treated as a contract failure. |

## Realism Score by Category

- **Field format accuracy:** 9 — Zeek, Snort, and proxy fields are well-formed and source-appropriate in sampled records.
- **Temporal patterns:** 7 — General activity is irregular and spans the collection window; the two DNS patterns have noticeably stable timing texture.
- **Cross-source correlation:** 9 — Sampled Zeek protocol rows join to connection UIDs and tuples, and selected proxy/Snort observations align with Zeek.
- **Behavioral realism:** 7 — Service and scan behavior is plausible; the concentrated TXT and DGA-like traffic is unusual but can be malicious behavior.
- **Environmental consistency:** 8 — Internal service placement and traffic mix are plausible from network evidence; no required protocol companion was demonstrably absent.

## Recommendations

- If this were synthetic, vary the TXT-tunnel request spacing and query/answer encoding across intervals, and include more variation in run length and pauses. The concrete basis is the 209-query stream from `10.10.2.30`, where 194 of 208 gaps are under 10 seconds and 185 responses share a length-prefixed token shape.
- If this were synthetic, vary the DGA-like query run lengths and resolver outcomes for `10.10.3.10`; the visible `.top` series has tightly grouped 20–40-second gaps within runs and 11 successful answers all use the same address.
