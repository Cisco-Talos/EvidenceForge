# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 42

## Executive Summary

The network evidence is substantially production-like: connection state, packet accounting, protocol companions, certificate identity and sensor-specific observations generally agree. A small cluster of file-versus-transport observation inconsistencies and infrastructure traffic choices raises suspicion, but I did not establish a decisive impossible protocol sequence or generator identity leak.

## Evidence For Synthetic

- [contract_gap] Eight HTTP file observations report missing bytes while their same-sensor, same-UID TCP connections report `missed_bytes=0` and no `g/G` history. For example, `zeek-core/files.json:318` reports 1,922 missing bytes for `CXHSTuNDBjAAR5BAj9`, whereas `zeek-core/conn.json:5996` reports a completed, zero-gap connection. `zeek-dmz/files.json:103` similarly reports 1,796 missing bytes for `Cf0g5oI0Y6rdASQfWf`, versus zero missed bytes in `zeek-dmz/conn.json:479`. These are observation-contract concerns; application truncation or specialized file-analysis policy could explain some examples, so they are not classified as hard contradictions.
- [contract_gap] Four connections have the sum of their HTTP extracted-file `seen_bytes` exceeding the responder's connection payload bytes. In `zeek-core/conn.json:10324`, `CEGjwnYXcxRvXcY3Ig` has `resp_bytes=403034`, but the three associated files (`files.json:587-589`) have 37,179 + 363,239 + 5,603 = 406,021 observed bytes. The 2,987-byte excess needs a source-native explanation, such as content decoding or a defined distinction in transport byte accounting. All four connections also have nonzero missed bytes, which limits the strength of this finding.
- [environment_or_collection_plausibility] Infrastructure-looking hosts make command-line-client CONNECT requests to a diverse tracking/analytics destination pool. `10.10.2.40`, also identified by TLS SNI as `LOG-MON-01.meridianhcs.local`, uses `Wget/1.21.3` for `tracking.fastreach.app`, `edge.hotjar.io`, `analytics.pagerduty.com` and `analytics.medflow.co` (`zeek-core/http.json:2,207,621,692`). The apparent file server `10.10.2.21` uses curl for tracking destinations (`http.json:6,743`). This is possible monitoring, testing or malicious activity, but a broad shared destination pool across server roles is less convincing than explicit application-specific behavior. Domain spelling or real-world resolution is not part of this indicator.

## Evidence For Real

- All examined DNS, HTTP and SSL UIDs resolve to a connection in their own sensor's logs, and all file connection references resolve. Protocol record timestamps fall within their associated flow interval; file start-plus-duration also stays within the flow interval.
- Packet counts and IP byte totals meet minimum IP/TCP/UDP header bounds throughout all 21,549 connection observations. Completed TCP connections do not have impossible one-packet handshakes. TCP histories include reset, retransmission and gap variants rather than one universally successful form.
- Sensor traffic differs plausibly by location. `zeek-db` predominantly observes MySQL; `zeek-core` has substantial DNS, Kerberos and LDAP; `zeek-dmz` concentrates TLS, proxy HTTP and unsuccessful probes.
- TLS 1.3 predominates in the DMZ while TLS 1.2 remains common internally. Every linked TLS 1.2 ECDHE_RSA leaf checked has an RSA key; certificates checked against handshake time are neither expired nor not-yet-valid. Certificate subjects, serials and fingerprints remain stable across repeated observations.
- HTTP connection reuse has meaningful transaction depths, realistic asset dependencies, zero-body 304 responses and stable sizes for hashed static assets. For instance, `/assets/css/main.min.07b8945e.css` has seven successful core observations, all 5,819 bytes; the vendor JavaScript asset has seven, all 141,609 bytes.
- DNS includes A, AAAA, PTR, SRV, TXT, SOA, NS and MX traffic, with NXDOMAIN, SERVFAIL and REFUSED responses. TTLs are not universally constant; repeated requests to `api.snapcraft.io` include TTL aging from 195 to 157 over approximately 38 seconds.

## Detailed Analysis

### Scope and method

I parsed the supplied JSON directly and joined source-local UIDs and file references. Counts below describe sensor observations, not deduplicated real-world flows: the same connection can legitimately be present at multiple sensors. Times are UTC on 2 November 2026. The visible network window is approximately 13:00–19:00, so I did not score absent nighttime behavior or out-of-window lifecycle companions.

| Sensor | Connections | DNS | HTTP | SSL | Files |
|---|---:|---:|---:|---:|---:|
| zeek-core | 12,055 | 3,053 | 2,152 | 348 | 707 |
| zeek-dmz | 9,041 | 953 | 2,344 | 2,578 | 1,492 |
| zeek-db | 453 | 45 | 21 | 9 | 17 |

### Connection and protocol behavior

Core connection states include 9,759 SF, 1,925 S0, 157 RSTO, 113 RSTR and 34 REJ, with smaller S1/S2/S3/OTH populations. DMZ has 6,152 SF and 2,679 S0 observations; this higher unsuccessful fraction is consistent with its visible probing and firewall timeouts, rather than automatically being an unrealistic failure rate. `fw-perimeter/cisco_asa.log:2-3` shows an inbound TCP build followed by a 30-second SYN timeout with zero bytes.

Service composition differs substantially: the core has 3,065 DNS, 2,507 Kerberos and 1,153 LDAP connection observations; the DB sensor has 305 MySQL connections out of 453. The large HTTP total is substantially explained by explicit proxy traffic to TCP/8080, so it should not be interpreted as thousands of obsolete cleartext website sessions.

SSH flows include plausible sustained sessions. `zeek-core/conn.json:2` starts at 13:00:10.169071 with `10.10.1.35:59357 → 10.10.2.30:22`, a 3,647.193059-second SF connection and asymmetric 45,031/145,350-byte payloads. Core SSH duration has a median around 2,074 seconds, while HTTP's median is about 2.13 seconds. Those service distinctions are credible. Endpoint command/session ownership was outside the primary scope of this network review.

### DNS and TLS

Core DNS has 2,218 A, 266 AAAA, 128 PTR, 96 SRV and 331 TXT records, alongside smaller types. NOERROR accounts for 2,843 records, NXDOMAIN 188, SERVFAIL 14 and REFUSED eight. Answer and TTL vector lengths match throughout. No query payload was smaller than the minimum implied by its visible query name and DNS question fields; common additional lengths are compatible with EDNS options.

The first core DNS row and `conn.json:3` share `C5WSchKgiPjhIGAlL`, the same tuple and 2.432-ms transaction duration. A refused `.bit` query is also represented in `snort-core/snort_alert.log:1`. Suspicious names themselves do not distinguish synthetic from real.

DMZ TLS contains 1,802 TLS 1.3 observations and 775 TLS 1.2 observations, plus one incomplete negotiation without a version. Core is approximately evenly split, 175 versus 173. Resumed sessions and unsuccessful negotiations are represented. TLS 1.3 records do not require visible certificate extraction because those handshake messages are encrypted. I found no evidence supporting a cipher/key-type contradiction or invalid certificate time.

### File observation and byte accounting

The strongest reservation is the relationship between TCP observation loss and file observation loss. The eight zero-transport-gap/file-gap pairs are core files lines 34, 318 and 576, and DMZ files lines 103, 524, 1169, 1224 and 1335. Their connection lines are respectively core 539, 5996 and 10182, and DMZ 479, 4380, 7353, 7596 and 8228.

For the 13:21:30 browser connection, the core sees a complete TCP stream (`conn.json:539`, `missed_bytes=0`) but its favicon file has `seen_bytes=880`, `total_bytes=890`, `missing_bytes=10` (`files.json:34`). A second sensor's view of the same tuple can help distinguish a real truncated response from an observation artifact. A zero-gap transport plus an application-local file shortfall is possible, but the collection needs a coherent explanation for what `missing_bytes` represents.

The aggregate observed-file-byte excess occurs in core connection lines 9519 and 10324, and DMZ lines 287 and 7462. Excesses are respectively 723, 2,987, 4,273 and 127 bytes. I did not treat these as impossible without knowing content-encoding and precise counter semantics; nevertheless, they merit checking because all affected files are depth-zero HTTP bodies. The supplied rows do not expose a decoding explanation.

### Limits of the verdict

No malformed JSON, orphan protocol UID, impossible visible protocol timestamp, oversized individual file relative to its parent flow, or invalid linked certificate lifetime was demonstrated. Those successful checks are positive realism evidence, and completeness itself was not scored negatively. The residual issues are localized and potentially explainable; they support a mixed assessment near the production-like side of the rubric, rather than an 80–100 synthetic score.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| contract_gap | Zeek HTTP files/conn | Eight source-local file-gap/zero-TCP-gap pairs | Main reservation; file and transport observation semantics need reconciliation. |
| contract_gap | Zeek HTTP files/conn | Four flows with aggregate file seen bytes above responder bytes | Moderate concern, reduced by possible decoding/counter semantics and visible transport loss. |
| environment_or_collection_plausibility | Proxy HTTP/infrastructure hosts | Tracking/analytics CONNECTs from several server-like hosts | Small weight; plausible legitimate or malicious explanations remain. |

## Realism Score by Category

- **Field format accuracy:** 9 — Well-formed, protocol-appropriate fields and coherent basic packet accounting.
- **Temporal patterns:** 9 — Protocol observations and file lifetimes stay within flows; service durations differ plausibly.
- **Cross-source correlation:** 8 — UID and certificate joins hold; localized file/transport observation discrepancies remain.
- **Behavioral realism:** 8 — Convincing infrastructure and proxy patterns, with some questionable server destination selection.
- **Environmental consistency:** 8 — Sensor roles are well differentiated; command-line tracking requests need contextual support.

## Recommendations

- If this were synthetic, derive file gaps and transport gaps from the same source-local observation model. Explicitly distinguish a server-shortened HTTP body from capture loss or analyzer-local skipping.
- If this were synthetic, validate aggregate depth-zero extracted bytes against connection payloads using declared content-decoding and byte-counter semantics. Include any transformation metadata needed to explain legitimate exceptions.
- If this were synthetic, tie infrastructure outbound destinations to concrete applications or monitoring behavior. Retain unusual requests when intended, but avoid distributing browser-style analytics destinations across unrelated server roles without supporting process/application context.
