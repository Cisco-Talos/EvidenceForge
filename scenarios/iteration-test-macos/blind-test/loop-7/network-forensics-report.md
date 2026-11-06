# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive  
**Verdict Confidence:** 67  
**Synthetic-Confidence Score:** 37

## Executive Summary

The Zeek connection, DNS, HTTP, and TLS records show varied, plausible traffic and coherent source-native pivots across proxy, perimeter firewall, IDS, web access, and endpoint-flow records. One completed TLS session presents a chain containing an intermediate certificate that expired more than a year before observation; this is a concrete concern, but the capture alone cannot establish whether the client rejected it or whether a local trust configuration permitted it. Network evidence therefore supports neither a confident real nor synthetic verdict.

## Evidence For Synthetic

- [environment_or_collection_plausibility] In `zeek-dmz/ssl.json`, UID `CP8zMH3ENbU3kZshDg` records an established TLS 1.2 session to `www.reddit.com` at 2026-11-02 17:38:14 UTC (`established=true`, `ssl_history=CsxknGIi`). Its chain in `zeek-dmz/x509.json` includes `CN=R3, O=Let's Encrypt, C=US`, whose `certificate.not_valid_after` is 2025-09-15 16:00 UTC. The paired `zeek-dmz/conn.json` row is a completed `SF` connection lasting 3.73 seconds with substantial traffic in both directions. An expired intermediate in a completed session is suspicious for a normal web client, though TLS completion alone does not prove certificate validation succeeded.

## Evidence For Real

- Zeek application records consistently join to transport records by UID and five-tuple. Across `zeek-core`, `zeek-dmz`, and `zeek-db`, I found no tuple mismatches for the DNS, HTTP, or SSL records checked, and all file-record connection references resolved.
- Traffic has a plausible mixture of connection outcomes rather than only successful sessions: `zeek-core/conn.json` has 10,294 `SF`, 1,869 `S0`, 170 `RSTO`, 91 `RSTR`, and 35 `REJ` records; `zeek-dmz/conn.json` has 6,816 `SF`, 2,805 `S0`, 101 `RSTO`, 52 `RSTR`, and 25 `REJ`. The failed and partial attempts include packet histories consistent with their states.
- DNS records include internal A, PTR, and SRV lookups, successful answers, and failures. For example, `status-brnbiakv.tk` from `10.10.3.10:35707` receives `SERVFAIL` at 2026-11-02 13:16:12 UTC in `zeek-core/dns.json`; its matching connection is a one-query/one-response UDP DNS exchange. `snort-core/snort_alert.log` and `snort-perimeter/snort_alert.log` alert on that same source tuple and time window.
- A proxy transaction has a useful multi-source byte and protocol pivot. `PROXY-01.meridianhcs.local/proxy_access.log` records a successful `CONNECT downloads.cloud.com:443` from `10.10.2.27` at 13:01:30 UTC, with tunnel counts of 4,013 client bytes and 31,422 server bytes. `zeek-dmz/conn.json` records the proxy’s TLS connection to `23.45.127.51:443` with the same directional byte counts and a 2.77-second duration; `zeek-dmz/ssl.json` records SNI `downloads.cloud.com` and TLS 1.3. The corresponding client-to-proxy HTTP CONNECT is present in `zeek-core/http.json`.
- A failed inbound web connection is represented consistently at the network and firewall layers. `zeek-dmz/conn.json` records `185.220.233.25:41399` to `10.10.3.10:8080` as an `S0` SYN-only attempt at 13:00:35 UTC. `fw-perimeter/cisco_asa.log` records the inbound connection at 13:00:35 and tears it down 30 seconds later as `SYN Timeout`, with zero bytes.
- TLS observations are mostly conventional: both TLS 1.2 and TLS 1.3 appear, with common AES-GCM and ChaCha20-Poly1305 suites. Apart from the cited R3 intermediate, the observed certificate chains resolve to X.509 records and their validity intervals contain the observation time.

## Detailed Analysis

### Connection behavior and coverage

The three Zeek connection files cover different apparent segments and have a six-hour window on 2026-11-02, from about 13:00 to 19:00 UTC. `zeek-core/conn.json` contains 12,532 records, `zeek-dmz/conn.json` 9,830, and `zeek-db/conn.json` 449. The core mix includes DNS, Kerberos, LDAP, SMB, HTTP-to-proxy, TLS, syslog, SSH, SMTP, and database traffic. The DMZ view is dominated by TLS, HTTP, DNS, and inbound web traffic; the smaller database view is dominated by MySQL. This volume and family distribution is plausible for the apparent host roles and bounded business-hour window.

Transport states and histories are not uniform. Core and DMZ include complete handshakes, SYN-only attempts (`S0`), resets, rejects, and partial-session states. The `S0` records have zero responder packets; the sampled `SF` records have packets in both directions. Durations range from brief DNS exchanges to multi-hour SSH sessions. I found no negative durations or zero-initiator-packet connections.

### DNS, IDS, and firewall pivots

The `.tk` lookup from `10.10.3.10:35707` is a concrete shared pivot. The perimeter and core Snort files alert on the same UDP tuple within about 0.1 seconds of one another. Zeek sees the query as `status-brnbiakv.tk`, type A, transaction ID 24266, with a `SERVFAIL` response and an approximately 1 ms RTT. The core and DMZ sensors record the same exchange with their own UIDs and sensor timestamps 114 ms apart. That spread is small and plausible for separate observation points; it is not evidence of impossible ordering.

The firewall also contains paired build and teardown activity for the sampled external SYN attempt. The ASA record’s 30-second SYN timeout agrees with Zeek’s lack of a completed handshake. This is a concrete network-layer match, rather than an inference from alert text alone.

### HTTP, proxy, TLS, and endpoint-flow pivots

The `downloads.cloud.com` transaction is internally coherent across the proxy and Zeek. The client-facing HTTP CONNECT uses `10.10.2.27` to `10.10.3.20:8080`; the proxy-facing TLS connection originates from `10.10.3.20` and carries the matching SNI. The proxy’s tunnel byte counters equal the directional Zeek connection byte counters. This demonstrates that control-message bytes and tunneled bytes are represented separately and consistently in the proxy log.

For the cited `www.reddit.com` TLS connection, `PROXY-01.meridianhcs.local/ecar.json` has an outbound `FLOW/CONNECT` on the same tuple and source port at timestamp 1793641094231 ms, about 46 ms before the Zeek connection start. That close timing supports the tuple correlation. The endpoint-flow record does not resolve the certificate-validity concern because it reports transport connection details, not certificate verification outcome.

### TLS certificate validity

The leaf certificate for `www.reddit.com` is valid from 2026-10-03 through 2027-01-01, which covers the observation on November 2. The second chain item is the R3 intermediate, valid only through 2025-09-15. Zeek reports the TLS session as established and the TCP connection as a normal completed `SF` flow with 4,123 client bytes and 17,257 server bytes. A stale intermediate may reflect server configuration, an unusual or permissive client trust path, or synthetic certificate material. Since Zeek records handshake visibility rather than the client’s trust decision, this is a suspicious but not conclusive authenticity indicator.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the score |
|---|---|---|---|
| `environment_or_collection_plausibility` | Zeek SSL/X.509, corroborating endpoint FLOW | One completed `www.reddit.com` TLS session at 2026-11-02 17:38:14 UTC | The presented R3 intermediate was expired by the observation date, despite an established session. This is unusual for a normally validating client but not proof of a failed validation or synthetic generation. |

## Realism Score by Category

- **Field format accuracy:** 9 — Zeek JSON fields and connection/application tuples are structurally consistent; the stale intermediate is the only material certificate anomaly found.
- **Temporal patterns:** 8 — Traffic spans the window with varied durations and realistic bursty transactions; source timestamps in sampled cross-sensor pivots differ by tens to hundreds of milliseconds.
- **Cross-source correlation:** 9 — Sampled proxy, Zeek, Snort, firewall, web, and endpoint-flow pivots agree on tuples, timing, or byte counts.
- **Behavioral realism:** 8 — There is a broad, role-consistent protocol mix with failed, partial, and successful connections.
- **Environmental consistency:** 7 — Core, DMZ, proxy, web, and database traffic align with apparent placement, with one suspicious expired intermediate in a completed TLS session.

## Recommendations

- If this were synthetic, ensure successful TLS handshakes use a chain valid at observation time, or model the associated client-side rejection when an expired intermediate is presented. In particular, review the R3 intermediate attached to the 2026-11-02 `www.reddit.com` session in `zeek-dmz/ssl.json` and `zeek-dmz/x509.json`.
