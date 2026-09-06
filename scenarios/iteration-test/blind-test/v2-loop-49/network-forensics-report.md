# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 90
**Synthetic-Confidence Score:** 86

## Executive Summary

The dataset contains unusually strong network modeling—especially coherent proxy legs, sensor-specific packet loss, valid TLS chains, and realistic DHCP renewal behavior—but several source-visible defects are difficult to reconcile with native Zeek output. The decisive indicators are two TCP connections labeled `SF` despite histories and packet counts that contain neither a TCP handshake nor teardown, a dataset-wide artificial offset between one-packet UDP DNS connections and their corresponding DNS query timestamps, and repeated vocabulary/distribution patterns in public HTTP and SMB evidence.

## Evidence For Synthetic

- `[hard_contradiction]` In `zeek-core/conn.json`, UID `CGcRbtGJ9RHDmRjED` at `2024-03-18T12:54:37.469642Z` is TCP/53 with `conn_state="SF"`, but has `history="DdG"`, `orig_pkts=1`, and `resp_pkts=1`. A second record, UID `CGU0KB8BadJbROjPQO` at `2024-03-18T17:54:54.759093Z`, is also TCP/53 and `SF` with `history="Dd"`, one packet in each direction, and zero missed bytes. `SF` denotes an established, normally terminated TCP connection; these records expose only payload packets and no SYN/SYN-ACK or FIN in either direction. Midstream payload-only observation would not support `SF`, particularly for the second record with `missed_bytes=0`.
- `[schema_or_format]` All 3,881 reviewed UDP DNS transactions are one-to-one with their own `conn.json` UID, yet every `dns.json` query timestamp is later than its UDP connection start. The positive offset is systematic: core has 2,903/2,903 affected UDP DNS records (minimum 1.038 ms, median 2.717 ms, maximum 62.015 ms), DMZ has 944/944 (minimum 1.041 ms, median 2.567 ms), and DB has 34/34 (minimum 1.056 ms, median 2.927 ms). For a one-query UDP flow, the query datagram is also the packet that creates the Zeek connection, so native `conn.log` and `dns.log` timestamps normally share that packet timestamp; a universally injected millisecond-scale application offset looks generated rather than packet-derived.
- `[distribution_texture]` Public HTTP traffic to `10.10.3.10` consists of 51 requests from 46 external clients, with 44 clients producing exactly one request. Those isolated clients draw from only seven user-agent strings and a small repeated URI pool. Browser-labeled clients retrieve full HTML resources such as `/index.html` or `/login` but almost never produce same-client follow-on requests for CSS, JavaScript, images, or favicon resources, while those assets appear as unrelated one-off requests from other IPs.
- `[contract_gap]` The public web endpoint behaves inconsistently for identical methods and paths over the six-hour window without accompanying session texture that explains the variation. For example, twelve `GET /` requests split exactly into six `301` and six `404` responses; `/api/v1/status` produces `200`, `302`, and `304`; `/favicon.ico` produces `200` and `302`; and `/assets/app.js` alternates between a 75,107-byte `200` and a 285-byte `301`. Client-specific redirects or cache validators can explain individual cases, but the combination of one-shot clients, fixed user-agent pool, absent browser follow-ons, and path/status combinatorics is generator-like.
- `[environment_or_collection_plausibility]` The telemetry window is 18 March 2024, but `zeek-core/smb_files.json` contains 34 distinct names explicitly organized under future years: 14 under `2025`, 13 under `2026`, and 7 under `2027`. Some future planning documents are plausible, but the pattern extends to operational domain-policy paths such as `User\\2027\\startup-final.ps1`, `Policies\\2027\\groups-v2.pol`, `Machine\\2025\\groups.xml`, and `Preferences\\2026\\policy.ps1` on `SYSVOL`/`NETLOGON`. The breadth across ordinary documents and active policy artifacts suggests a date-vocabulary pool not anchored to the evidence time.

## Evidence For Real

- All protocol children tested have valid local parents: missing parent UID counts are zero for DNS, HTTP, TLS, and files across the core, DMZ, and DB viewpoints. No DNS, HTTP, TLS, or file child occurs after its parent connection interval.
- Overlapping sensors show realistic observation differences rather than byte-for-byte duplication. Core and DMZ share 3,993 near-time five-tuples with no connection-state disagreements, but 354 have packet/byte differences accompanied by plausible `missed_bytes` and `G/g` history markers. Their start-time differences remain bounded below 119 ms.
- Explicit-proxy behavior is particularly coherent. Of 1,367 DMZ `CONNECT` transactions, 1,252 successful `200` tunnels have a matching proxy-origin TLS session with the same hostname within the tested timing window, while none of the `403`, `407`, `502`, `503`, or `504` failures creates such an origin TLS leg. Seventeen successful tunnels without a visible origin leg are a believable collection gap.
- TLS evidence is internally consistent. The DMZ viewpoint contains 2,013 TLS sessions with a credible TLS 1.3/TLS 1.2 mix (1,336/677), modern cipher diversity, 683 resumptions, and 845 X.509 rows. All 436 leaf certificates that could be checked match their SNI through CN or SAN, all 404 observed chain links have issuer-to-subject continuity, and no observed certificate is expired or not yet valid.
- DNS has realistic breadth: A, AAAA, PTR, SRV, TXT, MX, NS, and SOA traffic; NOERROR, NXDOMAIN, SERVFAIL, and REFUSED outcomes; suffix-search noise such as `wpad`, `wpad.local`, `isatap`, and `oldserver.meridianhcs.local`; varied TTLs; valid address families; and no answer/TTL cardinality defects.
- DHCP renewals show strong lifecycle realism. Hosts with 3,600-second leases renew at roughly 1,800 seconds with jitter; 7,200-second leases renew near 3,600 seconds; and 14,400-second leases renew near 7,200 seconds. MAC, hostname, assigned address, and server remain stable per client.
- SMB transfer accounting is directionally coherent. Across 165 `FILE_READ`/`FILE_WRITE` operations, no declared file size exceeds the corresponding responder/origin byte count, and measured transfer rates range from roughly 297 B/s to 6.24 MB/s rather than collapsing to one fixed throughput.
- Connection texture is broad rather than uniformly successful. Core states include 8,719 `SF`, 1,914 `S0`, 146 `RSTO`, 89 `RSTR`, 30 `REJ`, 28 `OTH`, plus `S1`/`S2`/`S3`; DMZ similarly mixes 4,966 `SF` with 2,645 `S0` and multiple reset/rejection states. A sustained external TLS client at `185.70.41.45` also shows a plausible mix of 350 `SF`, 23 `S0`, 16 `RSTO`, and 10 `RSTR` outcomes rather than perfect success.

## Detailed Analysis

### Scope and source inventory

I examined only the generated evidence under the supplied data directory. The network corpus has three Zeek viewpoints: core (10,960 connections), DMZ (7,847), and DB (434), spanning approximately `2024-03-18T12:00:05Z` through `17:59:52Z`. Available network families include `conn`, `dns`, `http`, `ssl`, `x509`, `ocsp`, and `files` at all three viewpoints, with core-only DHCP, SMTP, SMB mapping/files, and small PE metadata sets.

The source mix is plausible for a segmented enterprise. Core is dominated by DNS, Kerberos, LDAP, explicit proxy, SMB, TLS, SSH, and database traffic. DMZ emphasizes 443, 8080, DNS, web, database, and unsolicited external scans. The DB sensor is tightly scoped around MySQL from `10.10.3.10` to `10.10.4.10`, plus limited management and proxy traffic.

### Connection-state and transport semantics

Most state/history combinations are credible. `S0` rows generally contain origin SYN-only history; rejected/reset connections use the expected reset direction; established flows contain handshake and closure symbols; and service-specific durations are varied. Examples include median core durations of roughly 2.16 seconds for port 8080, 2.75 seconds for SMB, 4.21 seconds for TLS/443, and 1,928 seconds for modeled SSH sessions.

The two TCP-DNS exceptions are decisive because their fields cannot jointly describe native packet observation. At `12:54:37.469642Z`, `CGcRbtGJ9RHDmRjED` has one origin payload packet, one response payload packet, one missed byte, and `history="DdG"`; at `17:54:54.759093Z`, `CGU0KB8BadJbROjPQO` has the same one-packet-per-direction shape, no loss, and `history="Dd"`. Both are labeled `SF`. Their linked DNS rows are SERVFAIL responses for `DC-02.meridianhcs.local` and `DC-01.meridianhcs.local`, respectively. The protocol outcome is possible, but the TCP lifecycle projection is not.

The wider state distribution is nevertheless convincing. External scanners generate long tails of unanswered probes over Telnet, SSH, SMB, RDP, SMTP, and web ports. Sensor overlap is also handled well: the same five-tuple gets sensor-local UID values and clock offsets, while missed-packet markers explain many byte differences. I found no cross-sensor state conflict among the 4,427 overlapping pairs tested.

### DNS behavior and timing

Core DNS includes 2,119 A, 239 AAAA, 143 PTR, 92 SRV, 303 TXT, and smaller NS/MX/SOA populations. There are 216 NXDOMAINs, with realistic local discovery failures and sparse public reverse-lookup failures. AAAA NODATA responses correctly omit answer and TTL arrays, successful A/AAAA answers use the correct address family, answer and TTL array lengths match, and error responses do not carry answers.

The DNS timing contract is the largest dataset-wide defect. Each DNS row uses a unique connection UID—there are no multi-transaction DNS UIDs in any viewpoint—and 3,881 of those parents are UDP. Despite that one-datagram request shape, not one DNS timestamp equals its parent connection timestamp. For example, core UID `Cl6dXZAWxQDQ8B6wk5` starts at `12:00:05.580965Z`, while its A query for `DC-01.meridianhcs.local` is timestamped `12:00:05.598407Z`, 17.442 ms later; the recorded DNS RTT is only 0.516 ms. The systematic positive offset across every sensor is unlike Zeek's packet-derived timestamping and materially raises synthetic confidence.

### HTTP, proxy, and public-facing traffic

The explicit proxy implementation is one of the strongest realistic elements. Client-to-proxy `CONNECT` requests preserve client identity and user agent; successful transactions produce proxy-origin DNS/TLS activity; denied or failed transactions terminate at the proxy; and the two viewpoints have small clock/packet-count differences. Status distribution includes `200`, `403`, `407`, `502`, `503`, and `504`, with body/FUID metadata on failure pages. Request and response body sizes remain within connection byte counts, and bodyless statuses such as `304` correctly report zero response body.

The public web baseline is much weaker. Forty-four of 46 external clients make exactly one request, yet most identify as full Chrome, Edge, or Firefox browsers. A real browser receiving a 25–49 KB HTML page normally creates a same-client burst of dependent asset requests unless JavaScript, cookies, or a collection boundary prevents it. Here the assets appear, but usually from unrelated one-shot IPs. The small reusable path and user-agent pools, combined with per-path response variation, make the traffic look assembled record-by-record rather than produced by sessions. The two multi-request clients (`223.221.86.118` and `87.96.194.148`) are more convincing because they show tightly grouped API or reconnaissance sequences.

### TLS, certificates, and OCSP

TLS is high quality overall. Core has 173 TLS 1.2 and 156 TLS 1.3 sessions; DMZ has 677 TLS 1.2 and 1,336 TLS 1.3; DB has 29 TLS 1.2. Cipher selection is compatible with the negotiated version, and the mix includes AES-GCM, ChaCha20-Poly1305, ECDSA, and a limited amount of AES-CBC on TLS 1.2. Session resumption is neither absent nor universal.

Certificate identity, validity, and chain relationships are coherent. SNI-to-leaf matching passed for every checkable chain. All linked X.509 IDs exist locally, except two OCSP serials in the DMZ view without a same-window local X.509 row—an explainable cache or bounded-window condition. Repeated internal certificates retain fingerprints across observations and sensors, while sensor-local FUIDs remain distinct. These details argue strongly for real or carefully modeled evidence.

### Infrastructure and SMB behavior

DHCP is notably realistic: stable identities renew at approximately T/2 with per-client jitter instead of exact global intervals. For example, `WS-DRAMIREZ-01` has a 3,600-second lease and eleven renewal gaps ranging from about 1,774.7 to 1,870.2 seconds. `LT-MRIVERA-02` has a 14,400-second lease and gaps of about 7,126.9 and 7,086.9 seconds.

SMB mapping, action, file-analysis, and connection rows correlate cleanly by UID/FUID and preserve directionally correct byte accounting. However, file naming has a conspicuous time-anchor defect. A March 2024 collection contains active reads/writes of 34 distinct files under 2025–2027 directories. Future budget or roadmap documents are plausible in isolation, but repeated future-dated SYSVOL/NETLOGON policy names are difficult to explain as organic production naming and suggest generation vocabulary based on a date other than the event timestamp.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `hard_contradiction` | Zeek TCP `conn` / DNS | 2 core flows | `SF` conflicts with payload-only `Dd`/`DdG` histories and one packet per direction; this is the strongest immediate authenticity failure. |
| `schema_or_format` | Zeek UDP `conn` + `dns` | 3,881 transactions across all 3 sensors | Every one-query UDP DNS row receives a synthetic-looking positive offset from the packet that creates its connection. |
| `distribution_texture` | DMZ HTTP | 44 of 46 public clients are one-shot | Browser identities, paths, and assets are sampled without realistic same-client browsing sessions. |
| `contract_gap` | DMZ HTTP | Repeated public endpoint baseline | Identical paths rotate among redirect, success, cache, and not-found outcomes without session evidence that plausibly owns the differences. |
| `environment_or_collection_plausibility` | Core SMB | 34 distinct future-year filenames | 2025–2027 naming is widespread in a March 2024 window, including operational domain-policy artifacts. |

## Realism Score by Category

- **Field format accuracy:** 7 — Most Zeek fields and protocol values are well formed, but the two impossible TCP `SF` histories and universal UDP DNS timestamp offset are serious native-semantic defects.
- **Temporal patterns:** 8 — Business-hour bursts, scanner timing, varied durations, sensor clock differences, and DHCP T/2 jitter are strong; DNS packet timing is systematically artificial.
- **Cross-source correlation:** 9 — UID/FUID linkage, proxy terminal behavior, TLS chains, SMB accounting, and overlapping-sensor states are consistently coherent without being byte-identical.
- **Behavioral realism:** 6 — Proxy, scanner, TLS, and SMB transport behavior are convincing, but public browser traffic lacks session-shaped follow-on activity and uses a visibly small combinatorial pool.
- **Environmental consistency:** 6 — Segmentation and service placement are plausible, but 34 future-year SMB names—including active policy artifacts—do not fit the March 2024 evidence clock well.

## Recommendations

- If this were synthetic, derive Zeek `conn_state`, `history`, packet counts, and closure semantics from one canonical TCP lifecycle. Never emit `SF` unless both establishment and normal termination are represented in the source-visible packet/history projection; payload-only midstream flows should use the appropriate partial-observation state.
- If this were synthetic, timestamp a one-query UDP `dns.log` request from the same source-visible packet timestamp that opens its `conn.log` flow. Preserve a later response timestamp only through `rtt`/duration semantics, and reserve query-after-connection offsets for TCP handshakes or genuine multi-transaction transports.
- If this were synthetic, model public web clients as short-lived sessions rather than independent requests. Persist IP, user agent, cookies/cache state, and redirect state long enough to generate HTML followed by same-client CSS/JavaScript/image requests; let `304`, authenticated redirects, and WAF decisions arise from that state.
- If this were synthetic, make web response behavior endpoint- and state-driven. Stable unauthenticated requests to the same path should not randomly alternate among `200`, `301`, `302`, `304`, and `404`; variations should have visible ownership such as scheme redirect, conditional headers, authentication state, deployment change, or WAF policy.
- If this were synthetic, anchor year-bearing SMB path vocabulary to the event timestamp. Allow future years only for semantically future-facing document families, and keep active SYSVOL/NETLOGON policy directories near or before the collection year unless an explicit migration/staging activity explains them.
