# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive  
**Verdict Confidence:** 58  
**Synthetic-Confidence Score:** 25

## Executive Summary

The network evidence is internally coherent across Zeek connection, application, and file records, and mostly aligns with endpoint eCAR flow tuples and session chronology. I found no strong source-native contradiction or impossible protocol sequence; the small set of unmatched endpoint flows is not enough to infer an unrealistic collection profile. The evidence leans production-like, but the network slice alone does not settle whether the data is real or synthetic.

## Evidence For Synthetic

- [weak_signal] **A small cross-sensor tuple gap:** 233 of 25,842 complete eCAR FLOW tuples (0.9%) had no exact five-tuple in the available Zeek `conn.json` files. Examples include DC-02 DNS requests from `10.10.2.11` to itself on UDP/53 and some endpoint-observed flows. These are plausible host-local or sensor-scope gaps; without a visible collection contradiction, I assign this little weight.
- [weak_signal] **Some failed endpoint connection outcomes pair with Zeek resets:** for example, the inbound SSH flow to `MAIL-EDGE-01` at eCAR time `1793630440.940` has Zeek `REJ`, while the flow to `MAC-MROSS-02` at `1793624673.923` pairs with Zeek `RSTO`. A reset after a TCP attempt can reflect session or application failure, so these are not hard contradictions.

## Evidence For Real

- eCAR FLOWs align closely with Zeek tuples: 25,609 of 25,842 fully tupled rows (99.1%) have an exact match, and every matching pair is within five seconds. The median absolute timestamp difference is 0.354 seconds.
- Zeek application records are referentially sound in the checked families: DNS, HTTP, SSL, SMTP, SMB mapping, and SMB file rows all link to an existing connection UID. HTTP response file IDs also link to entries in the corresponding `files.json`.
- DNS behavior has a varied, credible mix. `zeek-core/dns.json` has A, AAAA, PTR, SRV, TXT, NS, MX, and SOA queries, plus NOERROR, NXDOMAIN, SERVFAIL, and REFUSED responses. Successful AAAA lookups with empty answer lists are consistent with NODATA responses.
- HTTP and TLS show ordinary service diversity: `zeek-core/http.json` includes CONNECT, GET, and POST, with 200, redirect, proxy-auth, and server-error statuses. The checked TLS records in `zeek-core/ssl.json` and `zeek-dmz/ssl.json` include TLS 1.2 and TLS 1.3, and established sessions have version values.
- Connection accounting is coherent in the checked Zeek files: no negative durations, payload totals greater than IP-byte totals, TCP S0 records with response traffic, or zero-origin-packet UDP records were found. TCP history strings were consistent with their broad connection-state classes.
- SSH traffic includes both routine successful sessions and failed attempts. At `1793624715.379`, `MAIL-EDGE-01.meridianhcs.local/ecar.json` records inbound TCP/22 from `10.10.1.31:54296`; a server-side SSH process appears at `1793624715.127`, the matching session login at `1793624724.451`, and a shell process at `1793624725.769`. This places transport before authenticated session use.
- SMB records reuse the same connection UID between `zeek-core/smb_mapping.json` and `zeek-core/smb_files.json`; the observed file actions include opens, reads, writes, and a rename rather than only a single repeated operation.

## Detailed Analysis

### Scope and time window

The data contains Zeek `conn.json` records from `zeek-core`, `zeek-dmz`, and `zeek-db`, protocol logs for DNS, HTTP, SSL, SMTP, SMB, files, and certificates, and per-host eCAR records. The Zeek connection window runs from **2026-11-02 13:00:00.884 UTC** (`zeek-core/conn.json`) through **2026-11-02 18:59:55.807 UTC** (`zeek-core/conn.json`), about six hours on a Monday. eCAR FLOW timestamps are epoch milliseconds; Zeek timestamps are epoch seconds.

The three sensors contain 11,972 (`zeek-core`), 9,220 (`zeek-dmz`), and 420 (`zeek-db`) connection rows. Their largest traffic families fit the observed segment roles: core has DNS, HTTP proxy traffic on 8080, Kerberos, LDAP, SMB, SSH and TLS; DMZ has outbound TLS/HTTP and inbound service traffic; the database sensor is dominated by MySQL on 3306. These source volumes do not by themselves imply under- or over-collection.

### Connection patterns and tuple correlation

Across the three Zeek sensors, `SF` is the most common state (16,332 rows combined), with `S0` next (4,627), followed by resets and smaller numbers of `REJ`, `S1`, `S2`, `S3`, and `OTH`. This is a plausible mix of completed flows, unanswered attempts, and interrupted sessions. The `S0` population includes ordinary UDP syslog traffic such as `zeek-core/conn.json` at `1793624433.942`: UDP from `10.10.1.99:36149` to `10.10.2.40:514`, service `syslog`, 1,592 origin bytes, zero responder bytes, history `D`. A no-reply result is expected for one-way UDP syslog and is not evidence of a failed TCP handshake.

For the eCAR/Zeek comparison, I normalized complete eCAR FLOW tuples as source IP, source port, destination IP, destination port, and protocol, then matched those against Zeek originator/responder tuples. **25,609 / 25,842** complete tuples matched exactly (99.1%). All exact matches were within five seconds; the median absolute timestamp difference was **0.354 seconds**. This is useful correlation evidence, but completeness itself is not a synthetic clue.

The 233 unmatched tuples deserve context rather than an automatic penalty. Some eCAR rows represent local endpoint observations, including DNS queries from DC-02's `10.10.2.11` address to the same address on port 53. This can be host-local resolver activity that a network sensor does not see as a routed flow. I found no visible evidence that the unmatched fraction masks a required protocol companion or contradicts the apparent sensor layout.

### DNS, HTTP, TLS, and file references

Across `zeek-core/dns.json`, `zeek-dmz/dns.json`, and `zeek-db/dns.json`, DNS records cover multiple query types and result codes. Core has 3,082 queries, including 229 NXDOMAIN, 11 SERVFAIL, and 5 REFUSED results; DMZ has 983 queries, including 141 NXDOMAIN and a small SERVFAIL/REFUSED tail. The answer and TTL array lengths match in every DNS record checked. For example, `zeek-core/dns.json` at `1793624400.884041` records an A query for `DC-02.meridianhcs.local` with answer `10.10.2.11`, matching the related connection to the DNS server at `10.10.2.11`.

The HTTP logs have a large share of CONNECT requests to the proxy service on port 8080, alongside GET and POST requests. `zeek-core/http.json` at `1793624432.011476` records a GET to `WEB-EXT-01` with HTTP 200, a 25,656-byte response, and response FUID `FLss7iMTnTukt80m9H8`; `zeek-core/files.json` contains that FUID tied to the HTTP connection UID. HTTP status codes include successful responses, redirects, proxy authentication failures, and gateway/server errors. I found no checked 4xx/5xx row with an obviously successful `OK` or `Created` message.

TLS records are predominantly established TLS 1.2 or TLS 1.3 sessions. `zeek-core/ssl.json` at `1793624463.925468` has SNI `LOG-MON-01.meridianhcs.local`, TLS 1.2, and certificate FUIDs; the associated certificate rows share the same fingerprint and identify the internal host. DMZ records include external SNI/certificate pairs, such as `na139.salesforce.com` in `zeek-dmz/ssl.json` at `1793624482.797050` and its X.509 entry. Three core, five DMZ, and one DB SSL entries have no version, but none is marked established; I did not treat this as a contradiction.

### Sessions, SSH, and lateral traffic

There are 425 eCAR FLOW rows with destination port 22. Among the 403 exact Zeek tuple matches, Zeek classifies 294 as `S0`, 95 as `SF` with service `ssh`, 8 as `REJ`, and the remainder mostly as reset states. This distribution includes both unanswered probes and successful SSH transports. Repeated probes to the externally facing `WEB-EXT-01` are noticeable, but their source/port variation and Zeek attempt states are consistent with background SSH scanning; the pattern alone does not establish a generator artifact.

Successful inbound SSH examples preserve the expected network-before-authentication order. On `MAIL-EDGE-01`, the eCAR FLOW for `10.10.1.31:54296 -> 10.10.2.25:22` occurs at `1793624715.379`; the USER_SESSION LOGIN carrying the same source IP and port is at `1793624724.451`, followed by a shell process at `1793624725.769`. An earlier server process event at `1793624715.127` is close to the flow observation and can represent connection handling before authentication completes. The order is plausible. Missing process or session initiators outside the six-hour visible window would not be an issue; I found no visible dependent event that clearly precedes its required initiating network event.

Internal SSH and SMB traffic appear in the same environment as LDAP/Kerberos, DNS, and service traffic. I did not infer that every internal connection should have an endpoint-side session record: the available endpoint event scope varies by host, and the matching network evidence is often sufficient to explain the visible path. No RDP-specific conclusion is necessary for this network assessment.

### Overall interpretation

The record set has a coherent six-hour business-day window, a believable mix of infrastructure and user/service traffic, and source-native Zeek field relationships. The major caveat is modest unmatched eCAR-to-Zeek tuple coverage plus a few failure/reset pairings. Neither currently rises to an impossible ordering, wrong field value, implausible volume, or required-companion failure. I therefore score the data as mostly production-like while retaining an inconclusive origin verdict.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the score |
|---|---|---|---|
| `weak_signal` | eCAR FLOW vs. Zeek conn | 233 of 25,842 complete eCAR tuples lack a matching tuple in the three visible Zeek sensors | Small unexplained remainder is worth review, but examples include host-local DNS and no collection contradiction is visible. Low impact. |
| `weak_signal` | eCAR FLOW vs. Zeek conn | A few flows marked outcome `failure` pair with Zeek `REJ`/`RSTO` | These can reflect rejected or reset sessions and do not contradict the flow's network outcome. Very low impact. |

No `hard_contradiction`, `contract_gap`, `distribution_texture`, or `schema_or_format` indicator was substantiated in the checked network records.

## Realism Score by Category

- **Field format accuracy:** 9 — Zeek UID, tuple, DNS, HTTP, TLS, and file references are internally consistent; no major source-native field errors found.
- **Temporal patterns:** 8 — Endpoint and Zeek connection times are close, and SSH transport precedes session login; the six-hour window is coherent.
- **Cross-source correlation:** 9 — Exact endpoint/network tuple matching is high, and Zeek application UIDs and file FUIDs resolve cleanly.
- **Behavioral realism:** 8 — DNS, proxy HTTP, TLS, SMTP, SMB, SSH, and failed connection behavior show useful variety; some SSH probing is conspicuous but plausible.
- **Environmental consistency:** 8 — The core, DMZ, and database traffic mixes broadly fit their visible roles; no unsupported coverage expectation was imposed.

## Recommendations

- If this were synthetic, preserve the observed distinction between successful UDP sends and unanswered UDP transactions; UDP syslog `S0`/history `D` records at port 514 are plausible and should not be forced into TCP-like response patterns.
- If this were synthetic, review the 233 endpoint FLOW tuples without Zeek matches by sensor visibility and host-local routing. Only add network companion rows where the visible routing/collection model requires the sensor to observe them.
- If this were synthetic, keep the demonstrated SSH timing relationship: connection observation first, then authenticated session login and shell activity. Do not add initiators before the visible collection window merely to make each session complete.
