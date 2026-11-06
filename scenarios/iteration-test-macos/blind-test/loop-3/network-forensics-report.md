# Network Forensics Analyst — Authenticity Assessment
## Verdict
**Assessment:** Synthetic
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 72

## Executive Summary (2–3 sentences)
The Zeek data has strong protocol and lifecycle texture, including realistic DNS response diversity, TLS 1.2/1.3, failed TCP attempts, and matching protocol-record UIDs. The principal synthetic tell is the unusually systematic duplication of thousands of identical flow tuples across `zeek-core` and `zeek-dmz`, almost always with a tightly clustered ~0.114-second timestamp offset and often identical packet/byte counts; this could reflect mirrored observation points, but its scale and regularity look more like paired rendering than independent collection. No single network record proves impossible protocol behavior, so the verdict is confident but not absolute.

## Evidence For Synthetic
- **distribution_texture** — `zeek-core/conn.json` and `zeek-dmz/conn.json` contain 4,919 same-tuple flow pairs within two seconds. Of these, 4,907 have timestamps separated by 0.100–0.130 seconds; median absolute separation is 0.114259 seconds. For example, `10.10.2.27:62952 → 10.10.3.20:8080/TCP` appears in DMZ at `1793624490.508274` (UID `CCjSSB3on2pqptiqE`) and core at `1793624490.624542` (UID `CEcvq4xCo5bLViRXL`), with the same 2.837-second duration, 4,288/31,596 bytes, six/26 packets, and `SF` state. Repeated near-fixed offset and copied counters across 4,919 records are unlikely to arise from two independent sensor clocks and flow accounting.
- **distribution_texture** — The same cross-sensor pairing extends to `http.json`: the two records for that tuple both report `CONNECT downloads.cloud.com:443`, status 200, `curl/7.88.1`, and matching request/response fields, with timestamps `1793624490.628496` (DMZ UID `CCjSSB3on2pqptiqE`) and `1793624490.744763` (core UID `CEcvq4xCo5bLViRXL`). Shared UIDs correctly bind each sensor's own connection and HTTP row, but the close duplicate application records reinforce the paired-data texture.
- **weak_signal** — Both sensors contain unusually large concentrated volumes for this six-hour slice (12,364 core and 9,621 DMZ connection rows), including 2,212/2,428 connections to proxy port 8080 and 2,589 core connections to Kerberos port 88. These are compatible with enterprise monitoring and proxy/DC roles inferred from observed services, so volume alone is weak and not treated as a defect.

## Evidence For Real
- Zeek source-native structure is coherent: every sampled `dns`, `http`, and `ssl` record had a matching `conn` UID in its own sensor dataset (core: 3,099/3,099 DNS, 2,416/2,416 HTTP, 315/315 SSL; DMZ: 925/925, 2,664/2,664, 2,817/2,817). TCP/UDP `ip_proto` values matched protocol, and no connection showed positive payload bytes with zero packets.
- Connection states are varied rather than uniformly successful: core has 10,124 `SF`, 1,898 `S0`, 154 `RSTO`, 75 `RSTR`, and 46 `REJ`; DMZ has 6,639 `SF`, 2,738 `S0`, 107 `RSTO`, 57 `RSTR`, and 45 `REJ`. These are plausible mixes for internal and perimeter observation.
- DNS includes `A`, `AAAA`, `PTR`, `SRV`, `TXT`, `MX`, `SOA`, and `NS`, with `NOERROR`, `NXDOMAIN`, `SERVFAIL`, and `REFUSED`; for example, core DNS UID `CYUMOHrg76wR3AOCsKv` is an `A` lookup for `DC-02.meridianhcs.local` with answer `10.10.2.11`, TTL 300, and `NOERROR`.
- TLS records show both TLS 1.2 and 1.3 and multiple modern cipher suites. DMZ SSL UID `CsFwxvbt98uZlqPflkW` for `ehr-portal.meridianhcs.com` has a matching X.509 chain whose leaf subject/SAN match that name and whose issuer is Amazon RSA 2048 M01. Internal core SSL UID `CJqcQsN2u1JRN1jSVy` similarly links `LOG-MON-01.meridianhcs.local` to an internal enterprise-issued certificate.
- Port/service behavior generally fits observed roles: internal Kerberos/DNS/LDAP, file service on 445, proxy CONNECT traffic on 8080, and DMZ TLS on 443. Both accepted and failed external connection attempts occur. A long SSH session in core (`10.10.3.10:46631 → 10.10.2.30:22`, UID `CCkwaBuG9kRDp7utdI`) lasts 13,346 seconds and has bytes in both directions; its end falls within the observed capture interval.

## Detailed Analysis (specific records)
- The six-hour Zeek connection windows are `2026-11-02 13:00:12–18:59:28 UTC` for core and `13:00:35–18:59:01 UTC` for DMZ. A connection can span much of this interval; the longest paired SSH record begins at `1793632472.568673` in core and lasts `13346.29749` seconds. Its DMZ counterpart uses a separate sensor UID and starts `0.112230` seconds earlier, lasts `13346.297989` seconds, and reports the same endpoints and byte counts. This remains consistent with the wider paired-sensor pattern, not an impossible duration.
- For the proxy example, the core and DMZ connection records share tuple, state, service, payload counts, and packet counts while differing in UID and start time by 116 ms. Both `http.json` rows reference their corresponding local UID and show a `CONNECT` tunnel to `downloads.cloud.com:443`, status 200. This is a plausible path through a proxy, but the same tightly clustered sensor offset repeated thousands of times is the strongest concern.
- Internal DNS example: `zeek-core/dns.json`, UID `CYUMOHrg76wR3AOCsKv`, at `1793624433.502349`, has `10.10.2.26:46341 → 10.10.2.11:53`, query `DC-02.meridianhcs.local`, answer `10.10.2.11`, TTL 300, `NOERROR`, and 0.333 ms RTT. PTR UID `CIxBSVnomcLWhPCafun` follows at `1793624434.049169` and resolves `11.2.10.10.in-addr.arpa` to the same hostname. These are plausible record-level query/answer values.
- The two sensors' HTTP mix is predominantly `CONNECT` (2,134 core; 2,181 DMZ), with GET and POST also present. HTTP status codes include success, redirects, partial content, proxy denial, and upstream errors (including 403, 407, 301/302, 206, 502–504). This is credible proxy texture; the high CONNECT share is explained by explicit proxy use visible on port 8080.
- Internal port observations include SMB mappings and file actions to `10.10.2.21:445`, plus SSH on port 22. DMZ sees substantially more inbound `S0` at 22/3389/5985 and on 443, consistent with perimeter exposure and unsuccessful probes. Without a complete topology or full packet path, these are not contradictions.

## Synthetic Indicator Summary (category/source/scope/score effect)
| Category | Source / scope | Score effect |
|---|---|---:|
| distribution_texture | 4,919 matched conn tuples between core and DMZ; 4,907 within a 100–130 ms offset band, frequently with repeated counters | +24 |
| distribution_texture | Paired HTTP proxy CONNECT rows reproduce host, method, status, user agent, and request/response values across sensors | +8 |
| weak_signal | High service-volume concentration in the six-hour slice, explainable by observed proxy and directory-service roles | +2 |
| hard_contradiction | None identified | 0 |
| contract_gap | None identified in sampled Zeek conn/DNS/HTTP/SSL UID references | 0 |
| schema_or_format | None identified in reviewed Zeek fields | 0 |
| environment_or_collection_plausibility | Mirrored/synchronized sensors could explain some paired flows; regular offset and matching counters at this scale remain doubtful | +4 |

## Realism Score by Category (1–10): Field format accuracy; Temporal patterns; Cross-source correlation; Behavioral realism; Environmental consistency
**Field format accuracy: 9/10; Temporal patterns: 7/10; Cross-source correlation: 9/10; Behavioral realism: 8/10; Environmental consistency: 7/10.**

## Recommendations (concrete evidence only, framed as improvements if synthetic)
- If the two files represent independent Zeek sensors, preserve sensor-specific packet accounting and clock behavior rather than rendering 4,919 same-tuple pairs with 4,907 timestamps inside a 100–130 ms band and frequently equal byte/packet counts. If they are deliberate mirrors, make the shared observation path explicit in dataset documentation.
- Retain the strong native UID linkage and varied connection states; the reviewed records show no missing conn references or basic IP-protocol/packet-count contradictions.
