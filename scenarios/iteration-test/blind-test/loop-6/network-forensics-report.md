# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 44

## Executive Summary

The network evidence is substantially production-like: connection states, protocol accounting, TLS certificate visibility, proxy tunneling, and sensor-specific observations are internally coherent. A conspicuous late-window cohort of mail-policy TXT lookups across otherwise unrelated client addresses suggests constructed background texture, but this is a distribution anomaly with plausible operational explanations, not a demonstrated protocol impossibility. I cannot confidently distinguish sophisticated synthetic telemetry from a real, sanitized collection on the network evidence alone.

## Evidence For Synthetic

- [distribution_texture] In `zeek-core/dns.json`, all 34 non-tunnel, routine TXT transactions occur between **2026-11-02 17:41:44.208597 and 18:03:34.090233 UTC**, despite a roughly six-hour collection starting at 13:00. They span **21 client addresses**, including workstation, server, and database address ranges, and consist of SPF, DKIM, DMARC, and verification-style names. Examples are `10.10.1.42` querying `selector1._domainkey.meridianhcs.com` at 17:41:44.208597 (`CwcoJlr0F6An2KE9vm`), `10.10.4.10` querying `selector1._domainkey.atlassian.net` at 17:54:02.836098 (`ClmP3uF0iEeIEXSmV5`), and `10.10.2.21` querying `_verify.sendgrid.net` at 18:03:34.090233 (`CsG7wXdaapyWMm8zOF`). This concentration across a broad cohort is an appreciable background-distribution tell. A scheduled diagnostic or coordinated application action could explain it; it is not sufficient for a synthetic verdict.

## Evidence For Real

- TCP states and histories agree in the cases checked. Across all three sensors, no `S0` row has responder packets, no `REJ` row claims application bytes, and every TCP `SF` row contains both `F` and `f` in its history. All per-direction packet counts meet the minimum implied by the corresponding history characters.
- DNS has a credible mixture of successful answers, negative responses, empty successful AAAA answers, and multiple query types. Core DNS contains 2,380 A, 323 AAAA, 253 TXT, 132 PTR, 98 SRV, nine MX, six NS, and two SOA transactions, with 224 NXDOMAIN, nine SERVFAIL, and six REFUSED responses.
- TLS distinguishes what a passive observer can see: **none of the 2,187 TLS 1.3 records across core and DMZ claims a certificate chain**. TLS 1.2 chains, when present, resolve to supplied certificate and file records, with matching issuer/subject relationships and compatible leaf key algorithms.
- Proxy control traffic and tunneled payload are explicitly distinguished. The first proxy access record, for `api.carepoint.com:443`, separates control-message bytes from tunnel bytes; the upstream Zeek connection carries exactly the reported 1,957 client and 63,367 server tunnel bytes.
- There are meaningful sensor-local differences rather than identical observation copies: 5,462 approximately contemporaneous cross-sensor flow pairs have consistent connection states but sometimes different packet counts, missed-byte counts, and histories. Such differences are compatible with observation position and capture loss.
- Service and duration variation is plausible. Database-sensor traffic is dominated by MySQL; core has Kerberos, LDAP, SMB, SSH, and RDP; DMZ has substantial TLS and HTTP proxy traffic. Successful core SSH flows span approximately 1.39 seconds to 3.70 hours, and successful RDP flows span approximately 124 to 3,486 seconds.

## Detailed Analysis

### Scope and method

I examined only the assigned data directory and briefing. I parsed all JSON records in the three Zeek sensor directories and inspected representative proxy, firewall, IDS, and normalized endpoint records. The quantitative network review includes **22,358 connection rows, 4,336 DNS rows, 4,992 HTTP rows, 3,439 TLS rows, 1,313 X.509 rows, and 2,556 file rows**. These are recorded observation counts, not deduplicated activity counts: the same traffic can cross multiple sensors.

The connection window runs from **2026-11-02 13:00:02.649837 to 18:59:49.834286 UTC**. It does not support conclusions about overnight traffic, whole-day schedules, or sessions beginning before the slice.

### Flow semantics and packet accounting

Core has 9,672 `SF`, 1,643 `S0`, 443 `OTH`, 154 `RSTO`, 106 `RSTR`, 28 `REJ`, and smaller populations of partial-close states. DMZ has 6,720 `SF` and 2,495 `S0`, with resets, rejections, partial sessions, and midstream observations also present. Database has 371 `SF`, 37 `RSTO`, 23 `RSTR`, 19 `OTH`, and smaller failure populations.

The large unanswered-flow population is not uniformly sprinkled across every source. For example, 1,237 core `S0` records originate at `10.10.3.10`, while DMZ also shows substantial unanswered traffic from several external addresses. This concentration is compatible with scanning or repeated reachability attempts; its presence alone is not an authenticity defect.

I checked application-byte counts against IP-byte totals, minimum IP/TCP headers, zero-packet directions, UDP maximum payload bounds, and per-history minimum packet counts. These checks found no impossible values. No HTTP request or response body exceeds the associated connection's corresponding payload bytes, and no HTTP 304 record claims a response body. No successful CONNECT record claims an HTTP response body.

An illustrative RDP flow is core UID `C2szt9QxyeYoN9plhX`, from `10.10.1.31:52673` to `10.10.2.27:3389`, starting at epoch `1793627420.93305`: it has a 438.450580-second successful interval, 300,464 originator bytes, and 1,585,383 responder bytes. It is materially different from tiny short-lived probes.

### Protocol timing and cross-sensor observations

For all supplied DNS, HTTP, and TLS rows, the UID resolves to a connection in the same sensor directory. No protocol timestamp precedes its associated connection start, and none lies more than one millisecond after that connection's reported end. This is positive consistency evidence; completeness itself was not treated as a synthetic clue.

Matching cross-sensor flows by five-tuple and a start-time difference below one second yielded 5,462 pairs. Their states agree, while 288 pairs differ in originator packet counts, 318 in responder packet counts, 525 in history, and 533 in missed bytes. Small payload differences occur in a few cases. This review did not establish an impossible relationship among those observation differences; independent clocks, capture paths, and loss prevent treating a small timestamp difference alone as causality proof.

### DNS behavior and the localized TXT cohort

Most visible DNS behavior fits an enterprise environment: AD service discovery, internal forward and reverse resolution, public service names, A/AAAA pairing, and negative responses. The first core row, UID `Cy7bKJVXGBLSw4N5M0b`, is an authoritative SRV response for `_ldap._tcp.meridianhcs.local` with both domain-controller names and a 0.001111-second RTT. Core UID `CYRRbYEV4Pu293vVLx` is a successful AAAA lookup for `FILE-SRV-01.meridianhcs.local` with no answer array, a plausible NODATA response rather than a forced IPv6 address.

The main anomaly is the late routine TXT cohort. Separating the high-entropy `westbridge-services.cloud` query population and the later `metrics.westbridge-services.net` TXT lookup leaves 34 routine transactions, all within 21 minutes 49.881636 seconds. That separation is based on visible query names and response content; I am not penalizing the suspicious query sequence for being compact or narratable.

The 34 routine records include a database client checking SPF/DKIM-related domains and a broad spread of other clients doing similar lookups at the same late stage. Their absence in the preceding approximately 4 hours 42 minutes, followed by broad participation, looks more like a coordinated cohort than ordinary independently arriving mail-related DNS activity. A fleet diagnostic, security tool, or scheduled verification could produce this, so I assign moderate distribution weight and no hard-contradiction weight.

### TLS, certificates, and proxy paths

DMZ has 1,956 TLS 1.3 and 1,001 TLS 1.2 records with negotiated versions, while core has 231 and 215 respectively. Database TLS is entirely TLS 1.2 in its 26 records. The database population includes 15 AES-CBC cipher selections, suggesting an older enterprise TLS client/server profile; that is possible and was not independently scored as synthetic.

I verified visible TLS 1.2 cipher authentication against leaf key type, certificate-chain issuer/subject links, certificate validity at observation time, and certificate bytes against responder payload capacity. No incompatibility was found. Repeated certificate fingerprints retain consistent identity and key fields. TLS 1.3 certificate absence is specifically appropriate to passive encrypted-handshake visibility.

The opening proxy transaction is a useful concrete correlation. In DMZ, client-side connection `CYojqFDPCJdzCFXCYk` starts at 13:00:03.052060, with its CONNECT request logged at 13:00:03.093553. Upstream connection `C8cJFHtsgeUYKITdHMu` starts at 13:00:03.124809 from `10.10.3.20:60315` to `23.72.175.240:443`; its TLS observation at 13:00:03.722511 names `api.carepoint.com`. Proxy access telemetry identifies control bytes separately and its tunnel byte counts match that upstream transport. A request timestamp is not a timestamp of completed proxy authorization, so this sequence does not establish a CONNECT-before-connect defect.

### Limits of the conclusion

This review found no demonstrable impossible network ordering, incompatible TLS authentication, malformed byte accounting, or generator identity leak. It also cannot authenticate the underlying packets, infer a required collector absent from the supplied logs, or prove that a coordinated DNS cohort was fabricated. The network data alone supports an inconclusive assessment: substantial protocol realism is tempered by one notable distribution anomaly.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Zeek DNS, particularly core; independently visible portions at DB and DMZ | 34 routine TXT transactions across 21 client addresses, exclusively 17:41:44–18:03:34 UTC within a six-hour slice | Moderate concern: abrupt cohort-wide background behavior with no preceding examples. A scheduled operational explanation remains plausible, preventing a confident synthetic verdict. |

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed fields, byte/packet bounds, HTTP body semantics, and TLS key/chain relationships held up under targeted checks.
- **Temporal patterns:** 8 — Flow and protocol lifetimes are coherent and varied; the late routine TXT cohort is conspicuous.
- **Cross-source correlation:** 9 — UID links, proxy payload accounting, and cross-sensor states agree without a demonstrated contradiction.
- **Behavioral realism:** 8 — Credible service-specific durations, concentrated scanning, and mixed DNS/TLS behavior; routine mail-policy lookups form an unusual broad client cohort.
- **Environmental consistency:** 8 — Database, core, and DMZ protocol mixes are plausible; widespread client-side mail-policy queries warrant an operational explanation.

## Recommendations

- If this were synthetic, tie routine SPF/DKIM/DMARC and verification queries to the actual application or diagnostic behavior that produces them. The specific issue to improve is the isolated 17:41–18:03 cohort across 21 addresses; use role-appropriate scheduling and preceding/following activity when modeling independent routine lookups, or preserve evidence of the coordinated job if that cohort is intentional.
- If this were synthetic, retain the observed protocol safeguards: packet/history compatibility, passive TLS 1.3 certificate visibility limits, TLS 1.2 chain/key compatibility, and explicit separation of CONNECT control bytes from tunneled payload. No additional missing-source requirement follows from this review.
