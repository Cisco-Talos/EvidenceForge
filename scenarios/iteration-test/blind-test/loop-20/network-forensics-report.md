# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 65
**Synthetic-Confidence Score:** 28

## Executive Summary

The network telemetry appears mostly production-like, with plausible transport-state diversity, differentiated protocol usage by observation point, realistic DNS failure/search behavior, and internally consistent HTTP and TLS evidence. One SMB mapping has no visible matching connection record, but I found no demonstrated impossible transport ordering, conflicting connection tuple, or certificate identity contradiction; the remaining uncertainty is substantial because a sophisticated synthetic dataset could reproduce the positive characteristics.

## Evidence For Synthetic

- [weak_signal] `zeek-core/smb_mapping.json:100`, at **2026-11-02 17:35:24.870101 UTC**, records UID `CJqVWaauzqBwjEIOtb`, `10.10.1.22:56998 → 10.10.2.20:445`, share `FILE-SRV-01/ClinicalExports`. Neither that UID nor its four-tuple appears in the supplied Zeek connection records. This is an unresolved reference, affecting **1 of 141** core SMB mapping rows. A connection extending outside the exported slice, selective retention, export filtering, or collection loss could explain it. I therefore treat it as a minor, explainable observation rather than a demonstrated lifecycle defect; it does not independently establish synthetic origin.
- [weak_signal] I found no additional network issue strong enough to score as a synthetic indicator. In particular, complete protocol joins elsewhere, the visible intrusion sequence, and limited collection duration were not treated as evidence of generation.

## Evidence For Real

- Transport outcomes are heterogeneous and role-dependent. `zeek-core/conn.json` contains **9,925 SF, 1,624 S0, 168 RSTO, 119 RSTR, 42 REJ**, and smaller partial-state populations; `zeek-dmz/conn.json` has a materially larger scan/nonresponse component (**2,539 S0 of 10,384 rows**). Database observations instead concentrate on successful and reset MySQL sessions.
- DNS has operational variety. Core queries include **2,418 A, 285 AAAA, 274 TXT, 156 PTR, 104 SRV**, and small NS/MX/SOA populations, with **244 NXDOMAIN, 11 SERVFAIL, and 2 REFUSED** responses. These are actual field-level differences, rather than a uniformly successful resolution stream.
- HTTP persistent connections carry multiple ordered transactions and consistent payload budgets. UID `CuUOP5MqF21A0spKqK` has a page and two image requests, ordered transaction depths 1–3, meaningful referrers, and aggregate response bodies below its TCP responder payload count.
- TLS differs between observation points: the DMZ records **2,114 TLS 1.3 and 1,075 TLS 1.2** negotiations with identifiable versions, while the database sensor's **17** SSL rows are TLS 1.2. Negotiated cipher families agree with those version populations, and session resumption is represented.
- Cross-sensor views retain shared connection identity through their tuples while allowing different UIDs, timestamps, and packet-loss observations. For example, the long SSH connection from `10.10.3.10:60743` to `10.10.2.30:22` is independently represented in core and DMZ with matching application byte totals and closely corresponding durations.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory. The network assessment covered all JSON records in the three Zeek sensor directories: **23,125 connection observations**, **4,442 DNS rows**, **5,479 HTTP rows**, **3,613 SSL rows**, and **1,356 X.509 rows**, plus the visible SMB, SMTP, DHCP, files, PE, and OCSP source inventory and selected proxy/firewall records. Counts across sensors are observation counts; duplicated visibility of a connection is not an additional unique connection.

The visible connection starts span approximately **13:00–19:00 UTC on 2026-11-02**. This is insufficient to assess overnight behavior, weekday/weekend differences, or daily periodicity. I did not infer those properties or penalize the dataset for their absence. Host roles below are inferred from source names and traffic, rather than from any external environment description.

I joined protocol rows to connection UIDs within each sensor, compared origin/responder tuples, checked whether protocol timestamps fell within the visible connection intervals, checked HTTP response-body totals against TCP responder payload, and screened packet/IP-byte bounds and overlapping TCP four-tuples. I also checked referenced certificate availability, validity at observed handshake time, repeated fingerprint metadata, and RSA-versus-ECDSA compatibility where relevant. These are consistency screens, not a substitute for packet captures or cryptographic validation.

### TCP states, service distribution, and lateral traffic

The three sensors are not copies of a single protocol distribution. Core includes **2,083 Kerberos-service, 1,199 LDAP-service, 455 SMB-service, 64 SSH-service, and 18 RDP-service** connection observations. DMZ is dominated by SSL, HTTP, DNS, and unsuccessful connections; the database sensor contains **234 port-3306 observations out of 364 total connections**, all originating from `10.10.3.10` toward `10.10.4.10` for that port. A web/application-to-database relationship is plausible from those observed roles.

MySQL outcomes at the database sensor are **184 SF, 31 RSTO, 10 RSTR, 5 S2, 3 S3, and 1 OTH**. Interarrival gaps range from approximately **0.534 to 1,039 seconds**, with a median of **36.631 seconds**, which does not resemble a fixed connection-per-minute schedule. Its median port-3306 connection duration is **2.672 seconds**, with a 95th percentile of **20.002 seconds**.

SSH durations have a different scale. `zeek-core/conn.json:5259` starts at **15:14:59.012189 UTC**, UID `CAgkxl305csliYaY8v`, and records a **13,320.733101-second** successful SSH session with **44,533 originator and 12,787 responder payload bytes**. The corresponding DMZ view starts about **113 ms earlier**, uses UID `Ce0EWXJ12qcDAdQ5IX`, and reports essentially the same duration and payloads. This is plausible long-lived interactive transport, not a port-22 row assigned a generic subsecond web duration.

Across all connection rows I found no TCP four-tuple reused in overlapping recorded intervals among the non-S0 flows checked. No completed TCP flow had fewer than three packets in either direction, no directional IP-byte total fell below its payload-byte total, and no directional IP-byte total exceeded the broad IPv4 maximum-per-packet bound used in the screen. These checks rule out several simple accounting defects without proving that every packet count is exact.

### DNS behavior and timing

`zeek-core/dns.json:1` and `conn.json:1` show a conventional single-exchange UDP resolution: UID `CIzRNyqwenV9EZ5bt2`, `10.10.1.31:57565 → 10.10.2.11:53`, query `DC-02.meridianhcs.local`, A answer `10.10.2.11`, TTL **300**, RTT **0.057582 seconds**, and one packet each way. Payload counts **52/57** and IP-byte counts **80/85** are compatible with UDP/IP overhead.

Failure traffic includes `isatap.meridianhcs.local` at **13:02:40.398372 UTC** and `wpad.local` at **13:03:02.136374 UTC** in core, both NXDOMAIN. Reverse lookups and SRV queries occur alongside ordinary A/AAAA traffic. External-answer TTLs vary, while internal names show common administrative values such as 300 and 1,800 seconds. Domain ownership and public resolution accuracy were not used as authenticity tests because names may have been sanitized.

Every DNS row joins to a same-sensor connection with the same tuple and a timestamp inside its interval. No UDP DNS originator payload was smaller than the basic question-size lower bound used in the screen.

I also checked nearby DNS-answer timing against TCP starts. There are **five** cases across core and DMZ in which a TCP connection begins while the nearest visible matching DNS exchange is still pending. This is not automatically impossible: a cached address, asynchronous refresh, or an independent application can supply the destination. For example, `10.10.1.42` starts SMB to `10.10.2.20` about **15 ms** before the response time implied by core DNS UID `CmPfiutZoZsrFYszbTx`. The records do not establish that this particular query was the connection's required first resolution, so I did **not** count these cases as synthetic indicators.

### HTTP, proxying, and payload accounting

CONNECT traffic explains much of the high HTTP count. Core's HTTP records include **2,317 successful CONNECTs**, compared with **143 GET/200** rows; this is not evidence that cleartext browsing exceeds encrypted browsing. Proxy failures include authentication challenges, policy denials, and gateway errors.

The initial proxy example is concrete: the access log records a **13:00:19 UTC** CONNECT for `ctldl.windowsupdate.com:443`; DMZ UID `CVLqENoLEv13zc7PMM` then shows `10.10.3.20:41424 → 52.114.132.73:443`, and its SSL row records the corresponding SNI with TLS 1.3. The firewall also records a dynamic translation for the proxy's source tuple. Those observations support an explicit-proxy path. I did not require proxy application bytes to equal encrypted transport bytes.

For ordinary HTTP, core UID `CuUOP5MqF21A0spKqK` opens at **13:00:46.704443 UTC**, lasts **4.461305 seconds**, and carries **326,465 responder payload bytes**. Requests at **13:00:46.744441**, **13:00:48.178211**, and **13:00:49.317438** retrieve `/blog`, a JPEG, and a WebP image, respectively. Their body lengths total **325,844 bytes**, leaving a plausible **621 bytes** for response headers. The image referrers identify the page. Across the HTTP groups screened, none had aggregate response bodies larger than responder TCP payload on a connection with zero recorded missed bytes.

### TLS and certificate consistency

TLS 1.3 uses AES-GCM and ChaCha20 suites, while TLS 1.2 uses ECDHE suites including a smaller CBC population. Core has **128 resumed** SSL observations and DMZ **1,136**; failed or incomplete negotiations are also present. TLS 1.3 rows with short `ssl_history` and no visible certificate were not penalized merely because certificate messages may be encrypted on the observation path.

All SSL certificate-chain FUIDs referenced certificates in the same sensor's X.509 records. I found no referenced certificate outside its recorded validity interval at the associated handshake, no RSA leaf paired with a visible ECDHE-ECDSA suite, and no repeated certificate fingerprint carrying conflicting certificate metadata. This is positive consistency evidence, not proof that the certificates are authentic or that a generator could not maintain those relationships.

### Timing and collection qualifications

Core hourly observation counts are **1,595, 3,142, 1,914, 1,707, 2,153, and 1,866** for hours 13–18 UTC. DMZ has a similar broad peak but different counts. Burstiness and the unequal hourly counts are compatible with operational activity; six hours cannot establish a business-hours baseline.

There are **1,233** connection observations with nonzero `missed_bytes`, distributed across all three sensors. Some corresponding sensor views differ in missed bytes and packet counts. This supports a collection model with imperfect network visibility, although these fields alone do not establish real origin. The single unmatched SMB mapping remains the only unresolved source-local reference from my checks; the logs do not establish that its connection record was required to fall inside this export.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| `weak_signal` | Core Zeek SMB mapping versus conn | One mapping, UID `CJqVWaauzqBwjEIOtb`, at 17:35:24.870101 UTC; 1/141 mapping rows | Minor, explainable artifact; not an established contradiction because slice boundaries, retention, or export policy may explain it |
| `weak_signal` | Overall network assessment | No additional demonstrated contradiction | No additional upward weight; complete joins and easily interpreted activity were excluded as indicators |

## Realism Score by Category

- **Field format accuracy:** 9 — Parseable Zeek JSON with compatible tuple, protocol, payload, and certificate fields; no demonstrated impossible field value in the checks performed.
- **Temporal patterns:** 8 — Variable connection arrivals and service-appropriate duration scales; the six-hour slice limits daily-pattern assessment.
- **Cross-source correlation:** 9 — DNS/HTTP/TLS tuples and intervals agree with their connection rows, and sampled proxy/firewall paths fit; one SMB mapping remains unresolved.
- **Behavioral realism:** 8 — Infrastructure, browsing, proxy failures, scans, administration, and application/database traffic have differentiated observable behavior.
- **Environmental consistency:** 8 — Sensor-specific service concentrations and explicit-proxy behavior are plausible; inferred roles and undocumented export policy limit certainty.

## Recommendations

- If this were synthetic, explicitly account for the connection underlying SMB mapping UID `CJqVWaauzqBwjEIOtb` when defining the export. Preserve the connection if it belongs inside the selected window; if slicing or selective collection explains its absence, describe that export rule. This is a recommendation to resolve the observed ambiguity, not a claim that every mapping requires a connection start inside the visible window.
