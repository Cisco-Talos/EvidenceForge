# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 76
**Synthetic-Confidence Score:** 35

## Executive Summary

The network data is mostly production-like: transport states, protocol timing, proxy traffic, and certificate relationships withstand a substantial set of consistency checks. The main reservation is a sustained mobile user-agent identity on an endpoint otherwise identified as a Mac; that is explainable and does not establish fabrication. I found no demonstrated impossible same-identity ordering or source-native protocol contradiction sufficient to call this dataset synthetic.

## Evidence For Synthetic

- [weak_signal] One apparent Mac originates predominantly iPhone-labelled proxy traffic. In `zeek-dmz/http.json`, `10.10.1.41` produces 239 transactions: 141 have `Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148`, 73 have Safari `Version/26.0`, and 25 have desktop Chrome `155.0.0.0`. The iPhone identity spans many unrelated services, including Workday, Microsoft 365, Zoom, Stack Overflow, Adobe, and analytics destinations. For reproducible examples, line 138 at `2026-11-02T13:25:30.048961Z` requests `wd5.myworkday.com`; line 1931 at `17:36:46.995179Z` requests `zoom.us`. `MAC-MROSS-01.meridianhcs.local/ecar.json` line 1 assigns `10.10.1.41` to `MAC-MROSS-01`; lines 31–37 contain an actual Mac Chrome process/helper lifecycle. This could reflect mobile emulation, rewritten headers, a client application, or shared addressing, so I apply only a small score penalty. The network records do not bind those HTTP requests to that Chrome PID, and I do not claim that they do.

## Evidence For Real

- Transport behavior is varied rather than one uniformly successful flow model. For example, `zeek-core/conn.json` has 9,865 `SF`, 1,741 `S0`, 420 `OTH`, 171 `RSTO`, 106 `RSTR`, 45 `REJ`, and smaller `S1/S2/S3` populations. Histories include handshake/data/close sequences, retransmission markers, and content-gap markers. The high failed-attempt population is compatible with the many visible probes and is not itself a defect.
- Application observations fit their visible transport intervals. Across all three sensors, every DNS, HTTP, and TLS UID resolves to a same-sensor connection with the same four-tuple; none precedes the connection start by more than 1 ms or lies more than 10 ms after its reported end. No overlapping TCP lifetimes using an identical four-tuple were found within a sensor.
- Explicit proxying is represented coherently. `zeek-dmz/http.json` line 1 is a successful `CONNECT clients6.google.com:443` from `10.10.1.32:57530` to `10.10.3.20:8080`, not an invented cleartext HTTP request to the TLS origin. Its upstream TLS connection is separate, and the proxy access log distinguishes control-message bytes from tunnel bytes.
- Certificate evidence has meaningful internal consistency. All TLS chain references resolve to same-sensor X.509 records; adjacent chain issuer/subject names agree; checked RSA/ECDSA authentication cipher families agree with the leaf key type; repeated fingerprints do not acquire contradictory certificate metadata; and referenced certificates are valid at the observed handshakes.
- DNS contains plausible mixed query and failure behavior. The core sensor includes A, AAAA, PTR, SRV, TXT, NS, MX, and SOA records, with 210 NXDOMAIN, 19 SERVFAIL, and 3 REFUSED responses. Empty successful AAAA responses occur alongside IPv4 use, which is ordinary NODATA behavior rather than a missing-address contradiction.
- Session durations have a meaningful service-dependent tail. Core successful SSH connections have a median duration of about 2,238 seconds and a maximum of 13,299 seconds, whereas successful proxy-port connections have a median of about 2.20 seconds. Large SMB/HTTP transfers also have packet and byte magnitudes appropriate to their large payloads.

## Detailed Analysis

### Inputs, provenance, and method

I read the supplied neutral instructions and files under `/private/tmp/log-study-0kwedkcm/data` only, using system `python3` with `/private/tmp` as the explicit working directory. I did not read project code, scenario files, project memory, prior assessments, other reviewer reports, or parent-directory inventories. Inherited generic project operating instructions were not used as evidence of data origin.

I parsed all supplied Zeek JSON files from `zeek-core`, `zeek-dmz`, and `zeek-db`. Those contain 22,509 connection observations, 4,196 DNS observations, 4,713 HTTP observations, and 3,041 TLS observations. These are sensor observations, not deduplicated enterprise-wide flow counts: the same underlying connection can be visible at multiple sensors. I also inspected samples of the ASA, proxy and Snort logs and a narrowly selected Mac endpoint file to corroborate address ownership.

For a source-native DNS format check, I consulted only the [upstream Zeek DNS implementation](https://raw.githubusercontent.com/zeek/zeek/master/scripts/base/protocols/dns/main.zeek). That code confirms that TXT answers carry a `TXT <length> <text>` representation and that SRV/MX/SOA answers are summarized rather than complete wire resource records. Thus I did not misclassify those answer shapes as omissions. No task-project public page or search result was consulted.

The visible connection start times cover approximately `2026-11-02 13:00–19:00 UTC`. A six-hour daytime slice cannot establish overnight infrastructure behavior or a whole-day work rhythm. Initiators before this slice and terminations beyond it are neutral.

### Connection state, duration, and packet accounting

The three sensors see different service mixes. The core sensor emphasizes DNS, Kerberos, LDAP, SMB, and client/proxy traffic; the DB sensor has 329 `mysql` service observations among 498 connections; the DMZ sensor emphasizes proxy HTTP, TLS and failed probes. This segmentation is plausible and is not a collection-profile contradiction.

A representative successful database flow is `zeek-db/conn.json` line 1: `10.10.3.10:36028 -> 10.10.4.10:3306`, duration `1.674143`, `SF`, history `ShADadfF`, with 4,124 originator and 30,340 responder payload bytes. The reported IP-byte totals exceed payload totals and account for packet headers. Successful TCP records throughout these files include the SYN/SYN-ACK and both FIN directions in their histories; no `SF` flow failed that elementary check.

Large transfers do not retain tiny placeholder packet counts. `zeek-core/conn.json` line 742, UID `CTW9bVIa6s6T2VNv8n`, reports 150,874,005 responder bytes on SMB over 26.318717 seconds, with 110,937 responder packets and a substantial originator ACK population. `zeek-dmz/conn.json` line 1070 reports an approximately 109 MB HTTP response with 74,721 responder packets. These magnitudes are mutually plausible.

I tested both directions of every TCP row for an impossible minimum-header bound: observed IP bytes must be capable of containing reported payload plus at least 40 bytes per IPv4/TCP packet. Some rows initially fall below the naive bound, but every such shortfall is covered by reported `missed_bytes`; their histories contain corresponding gaps. Zeek sequence-space payload counts can include unobserved bytes, so these are not demonstrated accounting contradictions. For example, DB connection line 23 has 175 missed bytes and a responder-side gap; it should not be scored as an impossible packet length.

Long SSH activity is represented as long transport sessions, not just momentary handshakes. Core line 5217, UID `C953E83z8JImsTDXrBm`, connects `10.10.3.10:45219` to `10.10.2.30:22` for `13298.584111` seconds with bidirectional payload. This connection can extend beyond the latest connection-start timestamp in the supplied slice; I do not treat that as evidence of an invalid closing lifecycle.

### DNS semantics and timing

The first core DNS row, UID `C811ndvH4HplPDAtP9L`, queries `_ldap._tcp.meridianhcs.local` using SRV and receives both DC names. Its connection row has matching tuple and timestamp, a `0.001519` duration, and the DNS row has a `0.001519` RTT. That is plausible for a single UDP query/reply exchange.

The core has 2,282 A, 283 AAAA, 129 PTR, 102 SRV, 362 TXT, 9 NS, 7 MX, and 6 SOA observations. The TXT population is concentrated late in the window, particularly from `10.10.2.30`; I do not infer fabrication from a concentrated DNS workload, since a script, mail workflow, investigation, or other bounded activity can produce one. Likewise, privacy-sanitized destinations are not judged against public address resolution.

TXT representation was checked against Zeek's upstream behavior. For instance, `zeek-core/dns.json` line 2157 contains `TXT 38 v=spf1 include:_spf.atlassian.net ~all`; the advertised text length is correct. The multi-string DKIM answer at line 2190 is represented as `TXT 255 ... TXT 155 ...`, which matches Zeek's concatenated presentation of TXT chunks. I checked advertised text lengths throughout the TXT population and found no mismatch.

No obvious A-response/IPv6-address mismatch was found. Successful empty AAAA answers are allowed; querying AAAA does not oblige a subsequent IPv6 connection. Nor must each connection have a fresh immediately preceding DNS query, because caches, address literals, and existing connections exist.

### Proxy and HTTP path

The strongest proxy example is the first transaction. `zeek-dmz/conn.json` line 1 begins the downstream client connection at `1793624404.660528`; the same sensor's HTTP line 1 observes CONNECT at `1793624404.789161`. The separate upstream TLS observation at `ssl.json` line 1 is `10.10.3.20:34135 -> 142.250.190.110:443` at `1793624404.841113`, with SNI `clients6.google.com`. This ordering is sensible.

`PROXY-01.meridianhcs.local/proxy_access.log` line 1 explicitly reports `cs_bytes=520`, `wire_sc_bytes=213`, `tunnel_cs_bytes=4274`, and `tunnel_sc_bytes=34835`. The downstream connection carries `4794/35048` payload bytes, exactly the control-plus-tunnel sums for that observation. The upstream TLS transport carries the tunnel quantities. This is a substantive accounting relationship, not merely shared labels.

CONNECT dominates the HTTP logs: 2,005 of 2,223 core transactions and 2,038 of 2,479 DMZ transactions. This is consistent with an explicit proxy carrying modern HTTPS traffic and should not be mistaken for a plaintext-HTTP-dominated organization. Statuses include authentication/policy and upstream errors: 407, 403, 502, 503 and 504, as well as successful and cached responses.

The Mac/mobile user-agent mixture is the principal weak reservation. The apparent iPhone identity is sustained over many services rather than a single mobile test request. Nevertheless, a user-agent string is client-controlled and an IP is not a cryptographic device identity. The supplied evidence does not rule out emulation or shared addressing. This observation therefore reduces behavioral confidence without becoming a hard platform contradiction.

### TLS, certificates, and ancillary sources

DMZ TLS comprises 1,750 TLS 1.3, 954 TLS 1.2, and 5 rows without a negotiated version. Core has 151 TLS 1.3, 164 TLS 1.2, and one unversioned row. DB's 16 TLS rows are TLS 1.2. The DB's older CBC cipher population is compatible with an internal legacy service; a mixed enterprise need not negotiate the same cipher distribution everywhere.

The files avoid the common mistake of claiming a parsed plaintext certificate handshake for every TLS 1.3 session: the dominant TLS 1.3 history is `Cs`. In the example TLS 1.2 transaction, DMZ `ssl.json` line 1 uses ECDHE-ECDSA and references a leaf whose `certificate.key_type` is `ecdsa` in `x509.json` line 1. Its RSA certificate signature is not a contradiction: an RSA CA can sign an EC leaf key.

All referenced chain IDs resolved, issuer/subject adjacency agreed, and no fingerprint changed metadata within a sensor. OCSP rows could be associated with visible certificate serials in many cases; when an issuer certificate fingerprint was shared, I found no conflicting issuer-name/key hash pair in those associations. Missing associations were not used to invent a contradiction.

The ASA opening rows distinguish the proxy's client and upstream sides and include dynamic translation before the outbound origin connection. The Snort samples use plausible fast-alert structure. These were sampled rather than exhaustively validated against vendor message catalogues; I do not claim a full ASA or signature-ID audit.

### Findings excluded from scoring

The core SMB records include UID `Cr7mRCkac27kS4mWeXo` in `smb_mapping.json` line 89 and `smb_files.json` lines 153–154, but no same-sensor conn row for that UID. Those are activity observations at about 17:10 UTC, not proof that the corresponding conn record had to appear in this slice: a connection may be summarized after the window or excluded by collection. I treated this as an unresolvable reference under the supplied collection constraints, not a scored synthetic indicator.

I also did not score complete matching, sparse optional source families, suspicious activity's narrative completeness, domain/IP public-resolution differences, absence of QUIC/Bonjour, or lack of night/weekend coverage. None independently demonstrates a network realism defect here.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `weak_signal` | Zeek HTTP/proxy identity, corroborated by normalized endpoint address ownership | 141 of 239 transactions from `10.10.1.41` use an iPhone identity despite Mac-associated endpoint evidence, spanning numerous services | Small penalty for unexplained identity texture; header spoofing, emulation or shared addressing remain viable explanations |

There is no scored `hard_contradiction`, `contract_gap`, or demonstrated `schema_or_format` defect. A score of 35 reflects mostly realistic telemetry with a limited explainable reservation, not a 35% estimate that the dataset is synthetic.

## Realism Score by Category

- **Field format accuracy:** 9 — Zeek JSON, DNS TXT summaries, transport fields and certificate shapes are internally credible; not every ancillary vendor field was independently audited.
- **Temporal patterns:** 9 — Service-dependent duration tails and nonuniform hourly volumes are plausible; no impossible visible protocol/transport ordering was found.
- **Cross-source correlation:** 9 — UID/tuple/interval, proxy byte accounting and certificate-chain relationships agree; one SMB reference is unresolved within the slice but is not necessarily defective.
- **Behavioral realism:** 8 — Diverse success/failure and service populations are convincing; the sustained Mac/mobile header mixture leaves a bounded uncertainty.
- **Environmental consistency:** 8 — Sensor/service segmentation and explicit proxy use make sense; endpoint-to-mobile identity remains unexplained rather than disproved.

## Recommendations

- If this were synthetic, bind browser/mobile user-agent selection to an explicitly modeled client/application identity. The 141 iPhone-labelled requests from Mac-associated `10.10.1.41` should arise from a consistent mobile-emulation/application/shared-address relationship when that is the intended behavior; otherwise use the owning desktop application's header.
- Preserve the observed distinction between proxy control traffic and tunnel bytes, the service-dependent long session durations, and source-native DNS TXT formatting. These are successful realism features, and simplifying them would introduce defects absent from this sample.
