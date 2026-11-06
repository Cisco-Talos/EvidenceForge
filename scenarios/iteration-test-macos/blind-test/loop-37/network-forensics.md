# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 34

## Executive Summary

The network evidence is mostly production-like: transport accounting, protocol timing, certificate identity, and explicit-proxy behavior withstand the checks described below. Repeated DNS resolutions within advertised TTLs and a predominance of short TLS connections are weak indications of simplified activity modeling, but both have plausible operational explanations; I found no demonstrated network-layer hard contradiction that establishes synthetic origin.

## Evidence For Synthetic

- [weak_signal] Repeated same-client domain-controller resolutions frequently occur inside the advertised TTL. In `zeek-core/dns.json`, lines 58 and 64 show `10.10.2.20` asking for `DC-01.meridianhcs.local` at `1793624919.337343` and `1793624958.097909`, only 38.761 seconds apart, with both answers carrying TTL 300. Across same-client A lookups for DC-01/DC-02, 308 of 962 consecutive pairs recur within the prior TTL, distributed over 42 client/name groups. This could reflect application-specific resolvers or cache bypass, and the example switches recursive servers; therefore it is not an impossible caching violation.
- [weak_signal] TLS transport lifetimes favor small, short transactions. Of 2,729 DMZ connections referenced by `ssl.json`, 2,186 last at most five seconds and 2,622 at most ten seconds; only 50 exceed 30 seconds, and the maximum is 178.827196 seconds (`zeek-dmz/conn.json`, line 5947). The core has a broader tail: 26 of 360 SSL-referenced connections exceed 30 seconds. A workload dominated by explicit proxy fetches can explain this, but the DMZ distribution could also result from a simplified request-per-connection model. This is a low-weight distribution observation, not a claim that every enterprise must have long-lived TLS sessions.

## Evidence For Real

- The three network views differ appropriately. `zeek-core/conn.json` has 12,279 rows and substantial DNS/Kerberos/LDAP traffic; `zeek-db/conn.json` has 464 rows, including 307 with service `mysql`; the DMZ has 9,287 rows with heavy SSL/proxy traffic and unsolicited attempts. This is a plausible segmented sensor layout.
- Connection states and histories have meaningful diversity rather than universally successful sessions. Core counts include 9,996 SF, 1,918 S0, 166 RSTO, 98 RSTR, 23 REJ, and smaller partial/other states. The DMZ includes 2,620 S0 and 29 REJ. Directional reset histories agree with their state: for example RSTO commonly uses `ShADaR`, RSTR `ShADadr`, and REJ `Sr`.
- DNS contains realistic record and error variety: the core includes 2,270 A, 266 AAAA, 247 TXT, 142 PTR, 100 SRV, 8 NS and 6 MX transactions, with 213 NXDOMAIN, 15 SERVFAIL and 4 REFUSED responses. `zeek-core/dns.json:1` has an AD SRV response naming both domain controllers with port 389 and appropriate private authoritative response flags.
- Proxy control messages and TLS transport occupy separate connections. `zeek-dmz/http.json:1` is a CONNECT request to `10.10.3.20:8080` for `www.bing.com:443`; `zeek-dmz/ssl.json:1` is a separate outbound TLS connection from that proxy to `13.107.21.200:443`, with matching SNI. `PROXY-01.meridianhcs.local/proxy_access.log:1` distinguishes CONNECT control-message bytes from tunnel bytes and duration.
- Certificate/file references are internally sound. `zeek-dmz/ssl.json:1` references leaf `F7V6NNfQcjtxQds8gx`; `zeek-dmz/files.json:1` records it as an SSL certificate transferred from the responder, and `zeek-dmz/x509.json:1` gives a matching Bing subject/SAN and fingerprint. No referenced certificate FUID was absent from its sensor's X.509 records.

## Detailed Analysis

### Scope and method

I parsed all JSON records under `zeek-core`, `zeek-dmz` and `zeek-db`, and inspected samples from the proxy, ASA and Snort logs. Totals were 22,030 connection rows, 3,993 DNS rows, 4,825 HTTP rows and 3,106 SSL rows. The observed connection-start window is approximately 13:00–19:00 UTC on 2 November 2026. Counts across overlapping sensors are observations, not counts of globally unique traffic.

I joined protocol records to connection records within each sensor by UID, checked transport intervals, inspected directional byte/packet accounting, tested TCP tuple overlap, and checked X.509 identity consistency across repeated fingerprints. I did not assume missing pre-window initiation or post-window termination was a defect, and did not require additional endpoint or network sources.

### Transport integrity and timing

Every DNS, HTTP and SSL UID had a corresponding connection in the same sensor. Their timestamps lay within the corresponding connection interval using a 1 ms allowance before the start and 100 ms after the end. No consecutive TCP records with the same directional four-tuple had overlapping visible intervals in the checks performed.

No flow had payload bytes exceeding its corresponding IP-byte total or positive payload with zero packets. No no-gap TCP direction had fewer IP bytes than payload plus the minimum 40 bytes per IPv4/TCP packet. No non-TCP record claimed TCP-style `missed_bytes`. Successful TCP histories contained both FIN directions; SYN-only TCP S0 records did not claim responder packets. These are useful positive checks because they test physical/source semantics rather than merely matching IDs.

The DMZ's opening row (`zeek-dmz/conn.json:1`, `1793624405.564569`) describes an external SYN attempt to `10.10.3.10:6379`, with S0, history `S`, one originator packet, and no responder packet. The corresponding early ASA sequence (`fw-perimeter/cisco_asa.log:1,3`) builds the inbound connection and reports SYN timeout after 30 seconds. That is coherent failed-handshake evidence.

Core hourly connection counts vary considerably: 1,696, 3,149, 1,825, 1,785, 2,021 and 1,803 for UTC hours 13 through 18. This does not resemble a flat hourly quota. The bounded daytime window does not support conclusions about overnight operations, weekly seasonality or weekend behavior.

### DNS behavior

No A/AAAA answer contained an address of the opposite family, and no nonzero-rcode transaction carried positive `answers` in these files. UDP query-byte totals were never below the minimum DNS header/question length implied by the visible query name. Core DNS RTTs range from 28 microseconds to 2.117978 seconds; the DMZ ranges from 233 microseconds to 2.118127 seconds, allowing both fast responses and slow/error paths.

The private domain-controller lookups have stable authoritative answers and TTLs, which is reasonable; frequent same-client rerequests before TTL expiry are the main weak concern. Because these logs do not identify the resolver library, application cache, or a cache-flush policy, I cannot elevate that concern to a contract violation.

### HTTP, proxy and TLS

CONNECT is the dominant HTTP method: 2,052 core and 2,077 DMZ rows. Thus a large HTTP row count is not evidence that modern browsing is predominantly unencrypted. Plaintext HTTP rows use ports 80/8080, with one core request on 8530; there is no HTTP/SSL UID overlap suggesting accidental interpretation of encrypted payload as plaintext.

Proxy statuses include successful tunnels, authentication responses, denied destinations, and 502/503/504 failures. `zeek-core/http.json:2` is a zero-body 304 response, while other rows have GET/POST responses and nonzero bodies. No individual HTTP request or response body exceeded its corresponding connection-direction payload count.

TLS mixes version 1.2 and 1.3, GCM and ChaCha20 suites, resumed and full handshakes. Internal database-visible TLS is version 1.2, while the DMZ favors version 1.3; that is plausible role-dependent diversity. TLS 1.3 rows generally omit certificate FUIDs, consistent with passive visibility limits after encryption begins; I do not treat that as missing evidence.

Across all three sensors there are 157 distinct certificate fingerprints. Repeated observations of a fingerprint have consistent certificate properties. No observed referenced leaf certificate fell outside its visible validity interval. This supports stable certificate identity rather than per-connection invention.

### Files and limitations

No individual extracted file exceeded its directional connection payload. One core HTTP connection (`CdlfIyJcRvLmiCEJO`, `conn.json:706`) has aggregate extracted `seen_bytes` of 709,465 versus responder payload 705,581 (`files.json:35–39,41–42`). I do **not** score this as a contradiction: HTTP decompression can make extracted content larger than wire payload, and this connection also reports capture gaps. The supplied HTTP metadata does not resolve compression conclusively.

I found no hard evidence sufficient to distinguish a carefully modeled synthetic dataset from sanitized production data. That is why the verdict remains inconclusive despite the relatively low synthetic-appearance score.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| weak_signal | Zeek DNS | 308/962 consecutive same-client DC-name A-query pairs recur before TTL expiry | Small increase; resolver/cache-bypass behavior is an adequate alternative explanation |
| weak_signal | Zeek SSL/conn | 2,622/2,729 DMZ SSL-referenced transports last at most ten seconds | Small increase; request-oriented proxy workloads can produce this distribution |

No demonstrated `hard_contradiction`, `contract_gap` or `schema_or_format` defect was found in the checks performed. Reference completeness was used to validate joins, not as a synthetic indicator.

## Realism Score by Category

- **Field format accuracy:** 9 — Source fields, hashes, protocol types and transport accounting are coherent in the inspected records.
- **Temporal patterns:** 8 — Nonflat hourly activity, diverse lifetimes and valid protocol intervals; short TLS predominance remains a weak concern.
- **Cross-source correlation:** 9 — Proxy, TLS, certificate and firewall examples agree without visible impossible relationships.
- **Behavioral realism:** 8 — Diverse failure states, DNS outcomes and service-specific traffic; resolver cache behavior warrants explanation.
- **Environmental consistency:** 9 — Core, DMZ and database views exhibit plausible service and role differences.

## Recommendations

- If this were synthetic, model application/resolver cache reuse explicitly, or retain enough resolver context to explain frequent same-client lookups inside positive TTLs. The DC-query examples above are the concrete target.
- If this were synthetic, check the short TLS lifetime distribution against the intended proxy/application workload. Add persistent connections only when those applications actually warrant them; the observed DMZ tail alone does not justify a mandatory quota.
