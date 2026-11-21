# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 83
**Synthetic-Confidence Score:** 47

## Executive Summary

The network evidence is largely convincing: proxy resolution and transport timing, TCP histories, TLS certificate identities, and application/file accounting withstand several direct consistency checks. A systematic separation between TCP termination state and application-log availability is the main concern: TLS metadata accompanies every SSL-classified `SF` and `S1` observation, but none of the SSL-classified reset, half-closed, or `OTH` observations, even when substantial bidirectional payload and no capture gaps are recorded. This could reflect a collection filter, so it supports a mixed assessment rather than a hard synthetic verdict.

## Evidence For Synthetic

- [distribution_texture] **TLS metadata availability partitions exactly by TCP state across three sensors.** In `zeek-core`, all 363 SSL-classified `SF` connections and all four `S1` connections have corresponding `ssl.json` UIDs, while all 55 SSL-classified `RSTO`, `RSTR`, `S2`, `S3`, and `OTH` observations lack them. The corresponding counts are 3,139 plus nine present versus 117 absent in `zeek-dmz`, and 29 present versus five absent in `zeek-db`. These are sensor observations, not necessarily distinct connections. Of the 177 absent companions, 172 have `missed_bytes=0`; the concern is the exact state-conditioned source distribution, not incompleteness itself.
- [distribution_texture] **HTTP shows a related termination-state split.** All 17 non-`SF` HTTP-classified connections in `zeek-dmz/conn.json` lack a corresponding `http.json` UID. Ten have both response payload and `missed_bytes=0`. For example, line 799, UID `Ch1S08xlgvWR1B5qMx`, records an `RSTO` flow with 2,914 originator bytes and 13,729 responder bytes, but no HTTP transaction row. A reset does not itself preclude an observable HTTP transaction. This reinforces the preceding concern but is not scored as an independent hard contradiction.

## Evidence For Real

- **A concrete proxy path respects resolution and transport ordering.** At the start of `zeek-dmz`, the client CONNECT to `registry.npmjs.org:443` is followed by proxy DNS resolution and then a separate proxy-originated TLS transport. DNS UID `C1tPdBuY9TFYDJoDbq` starts at `1793624401.502196` with `rtt=0.079624`, so the visible response completes at `1793624401.581820`. Upstream TCP UID `CBh5vygnjTwRRPDQtJ` starts at `1793624401.598658`, approximately 16.8 ms later, and its TLS SNI is `registry.npmjs.org`.
- **Proxy byte scopes make sense.** The first proxy access row separates 386 client control-message bytes and 133 server control-message bytes from tunnel payload of 1,340 and 23,862 bytes. The upstream Zeek connection has exactly the tunnel payload counts, while the client-facing connection has 1,726 and 23,995 bytes. This is coherent accounting for separate transport legs rather than an encrypted response body being mislabeled as a CONNECT response body.
- **TLS visibility varies appropriately with protocol version.** All 2,286 TLS 1.3 observations across core and DMZ lack visible certificate-chain references. TLS 1.2 observations include full handshakes, abbreviated/resumed handshakes, and incomplete handshakes. Certificate fingerprints, serials, validity periods, and file sizes remain stable when the same certificate recurs.
- **Connection-state and history diversity is substantial.** The core sensor includes 1,387 TCP `S0` records with history `S` and zero payload, 40 TCP `REJ` records with `Sr` or `Srr` and zero payload, reset flows, half-closed flows, and many ordinary `SF` connections. The data is not uniformly successful traffic.
- **DNS includes plausible operational variety.** Core DNS has A, AAAA, PTR, SRV, TXT, NS, MX, and SOA queries, with 213 NXDOMAINs, 12 SERVFAILs, and six REFUSED responses among 3,262 records. Internal AAAA queries sometimes return NOERROR without answers, which is compatible with an IPv4-oriented environment rather than a malformed answer.
- **Service and duration distributions reflect different roles.** The database sensor is dominated by MySQL; the DMZ sensor emphasizes TLS, HTTP/proxy, and scans; core includes Kerberos, LDAP, SMB, DHCP, and syslog. Long interactive SSH sessions coexist with short connections and failed attempts.

## Detailed Analysis

### Scope and method

I examined only the supplied data and this role's instructions. I parsed the Zeek JSON records and inspected the perimeter firewall, proxy, web-access, and Snort samples. I did not inspect scenarios, ground truth, repositories, other reviewers' output, or external provenance.

The Zeek connection files contain 12,351 core, 10,267 DMZ, and 470 database observations: 23,088 total sensor observations. Core starts at `1793624401.497159` and ends at `1793645995.524529`, covering approximately 13:00–19:00 UTC on November 2, 2026. The other sensor files lie within approximately the same six-hour interval. Connections observed on multiple sensors were not treated as independent real-world sessions when interpreting evidence strength.

I checked protocol UIDs against each sensor's own connection file, application timestamps against connection intervals, overlapping TCP tuples, TLS/certificate relationships, file hashes and byte budgets, DNS response durations, and state-conditioned application-log availability. The assessment does not depend on an assumed sensor product version or on absent platform-specific endpoint telemetry.

### TCP state, transport lifecycle, and packet accounting

Core contains 7,007 TCP, 4,925 UDP, and 419 ICMP observations. DMZ contains 8,759 TCP, 1,204 UDP, and 304 ICMP observations. Database contains 391 TCP, 50 UDP, and 29 ICMP observations.

TCP state diversity is plausible. Core has 5,234 TCP `SF`, 1,387 `S0`, 166 `RSTO`, 102 `RSTR`, and 40 `REJ` observations, as well as `S1`, `S2`, and `S3`. The state/history combinations examined make semantic sense: unanswered SYN attempts carry `S`, rejected attempts have responder resets, and the half-closed states use the corresponding FIN direction. I found no overlapping TCP connection intervals for the same directional four-tuple within a sensor when requiring an overlap greater than 100 ms.

No TCP observation failed a basic aggregate IP-byte lower-bound check of payload plus 20 bytes per recorded packet, and none exceeded 65,535 IP bytes per packet on average. These are coarse consistency checks, not reconstruction of packet sizes or TCP sequence space.

For each sensor, all examined DNS, HTTP, TLS, SMTP, and SMB file/mapping rows with matching connection UIDs fall within the visible connection interval, allowing 10 ms at the end for numeric/timestamp tolerance. Two core SMB mapping UIDs have no core connection row; I did not score that as a defect because a sliced or selectively exported collection can retain application evidence for a connection whose record is outside the supplied set.

Interactive flow durations are not collapsed into one short range. Core SSH UID `CXkzSU6i2Ghqz62Q1h`, `10.10.1.35:49676 -> 10.10.3.10:22`, starts at 13:16:55.034758 UTC and lasts 3,384.336174 seconds. Core SSH durations range from subsecond exchanges to approximately 13,322 seconds. Conversely, database MySQL `SF` durations range from approximately 0.064 to 29.139 seconds. These differences are compatible with interactive administration and short database work.

### The application-log distribution concern

Restricting the test to `conn.json` rows whose `service` is explicitly `ssl` avoids conflating ordinary port-443 scans with positively classified TLS traffic:

| Sensor | `SF` with SSL row / total | `S1` with SSL row / total | Other states with SSL row / total |
|---|---:|---:|---:|
| Core | 363 / 363 | 4 / 4 | 0 / 55 |
| DMZ | 3,139 / 3,139 | 9 / 9 | 0 / 117 |
| Database | 29 / 29 | 0 / 0 | 0 / 5 |

STARTTLS observations can also have SSL rows while their connection service is SMTP; those were excluded from this table.

This is more specific than a complaint that some protocol records are missing. Three sensors exhibit an exact division by final TCP state, and the protocol export visibly supports incomplete handshakes in `S1`, so the supplied SSL logs are not simply restricted to completed handshakes.

Two examples make an explanation based solely on packet loss or a connection ending near the slice boundary less persuasive:

- `zeek-db/conn.json:169`, UID `CtTmhQbKXdbYqsQsp0`, starts at **14:54:19.908659 UTC**, `10.10.4.10:36330 -> 10.10.2.40:443`, lasts 1.625690 seconds, and records `RSTO`, history `ShADadTR`, 2,436 originator bytes, 20,416 responder bytes, and zero missed bytes. No database SSL row carries its UID.
- `zeek-core/conn.json:4414`, UID `CyCfqQR7ouC5IoVJr`, starts at **14:45:55.670904 UTC**, `10.10.2.30:54418 -> 10.10.2.21:443`, lasts 3.819332 seconds, and records `S2`, history `ShADadF`, 4,076 originator bytes, 12,706 responder bytes, and zero missed bytes. No core SSL row carries its UID.

These are not proof that either connection completed a TLS handshake. They show why normal TCP teardown differences alone do not adequately explain the dataset-wide application export split. A deliberate exporter or query filter could still produce it; that unresolved alternative substantially limits the verdict.

HTTP supplies corroboration: the 17 non-`SF` HTTP-classified DMZ connections all lack transaction rows, whereas 2,870 of 2,882 `SF` HTTP-classified connections have them. The ten no-gap, response-bearing examples make this an observation-pattern concern, but individual partial requests or malformed responses remain possible.

### DNS chronology, caching, and query diversity

Core DNS contains 2,390 A, 248 AAAA, 174 PTR, 102 SRV, 333 TXT, seven NS, five MX, and three SOA rows. The DMZ sensor has 1,147 DNS records, primarily proxy-originated A lookups, and database has 40. Differences across sensors are consistent with their visible host populations and paths; I did not require every platform or protocol on every sensor.

DNS RTT never exceeds its matching connection duration by more than the 1 ms tolerance used in the check. For repeated successful external A answers to the same resolver, I tested 18 adjacent, unexpired-cache pairs per core/DMZ view; none had an unexplained TTL increase of more than two seconds. Those overlapping views are not independent evidence, but the result argues against indiscriminate per-query TTL randomization.

One DNS/TCP overlap is ambiguous rather than impossible. DMZ DNS line 243, UID `CWcOfq3pDUJHVELiNu`, queries `www.clearstream.com` at 14:38:54.383292 UTC with `rtt=1.891788`, implying response completion at 14:38:56.275080. TCP line 2124, UID `CuNJlUEsTuBBnmTjBd`, starts toward the answer address `104.18.153.128` at 14:38:56.039534, approximately 236 ms before that response. A cached address, simultaneous resolver work, or an already-known destination can explain this. I did not treat every visible lookup as the compulsory initiating lookup for the following connection and did not score this overlap as a synthetic defect.

### TLS, certificates, files, and proxy semantics

DMZ TLS has 2,090 TLS 1.3 and 1,053 TLS 1.2 rows, plus five rows without a negotiated version. Core has 196 TLS 1.3 and 226 TLS 1.2, plus one without a version; database has 29 TLS 1.2 rows. Modern AEAD suites predominate, with a smaller TLS 1.2 CBC component. This is compatible with a mixed modern and legacy service estate without requiring assumptions about actual public-domain ownership.

No checked ECDHE-ECDSA handshake references an RSA leaf certificate. Referenced certificate chains resolve locally and have consistent issuer-to-subject relationships and CA constraints. Repeated fingerprints do not acquire conflicting certificate attributes, all observed certificate validity periods include the observation, and hash field widths are correct. Each SSL certificate-file group's visible byte total fits within its connection's responder payload. Examined SMB file sizes likewise fit within the corresponding directional connection payload.

TLS 1.3 rows do not invent cleartext certificate chains. TLS 1.2 full and resumed handshakes use different SSL histories, while incomplete `C` and `Cs` histories are present. The source does not blindly attach certificates to every TLS observation.

The initial proxy sequence also demonstrates distinct transport ownership: client `10.10.1.41:61726` connects to `10.10.3.20:8080`, while the proxy independently opens `10.10.3.20:43730 -> 199.232.64.133:443`. The SNI agrees with the CONNECT target and the proxy DNS answer. I consider these concrete protocol and accounting relationships evidence for realism, without treating complete source matching itself as evidence of either origin.

### Volume, topology, and remaining limits

Core hourly connection-observation counts are 1,563, 3,207, 1,874, 1,865, 2,106, and 1,736 for UTC hours 13 through 18. DMZ has a similar 14:00-hour increase. These counts are variable rather than exactly repeated; a six-hour daytime slice cannot establish a full diurnal or weekend model.

The database sensor has 245 MySQL-classified connections; core has substantial Kerberos and LDAP; the DMZ path has many proxy CONNECT and upstream TLS connections. HTTP volume is largely explicable through explicit proxy traffic, rather than evidence that a modern estate inexplicably uses mostly plaintext websites. Perimeter firewall logs include separate NAT translations and build/teardown messages, and Snort samples include DNS, STUN, package-management, scan, and other policy alerts. I did not attempt to validate every IDS rule revision against an external rule corpus.

I found no demonstrated impossible network ordering, malformed hash identity, or conflicting certificate identity. The unresolved state-conditioned application export pattern is meaningful, but one collection mechanism could explain much of it; the synthetic-confidence score therefore remains within the mixed/inconclusive band.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| distribution_texture | Zeek connection and SSL logs | Three sensors: 3,531 SSL-classified `SF` and 13 `S1` observations have companions; 177 observations in other states do not, including 172 without recorded capture gaps | Main reason for moving from mostly production-like toward the middle of the rubric; exact conditioning by termination state warrants explanation, but filtering remains plausible |
| distribution_texture | Zeek DMZ connection and HTTP logs | All 17 non-`SF` HTTP-classified connections lack transactions; ten have response payload with zero missed bytes | Corroborates the same concern; not counted as a second independent proof or as a hard contradiction |

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed network records, hash widths, state histories, and certificate structures are coherent; I found no demonstrated native-field impossibility.
- **Temporal patterns:** 9 — Protocol rows fit their connection intervals, TCP tuples do not visibly overlap, durations vary by service, and the detailed proxy resolution sequence is plausible.
- **Cross-source correlation:** 8 — Proxy byte accounting, transport identities, and certificate/file references align; application-log availability has a systematic relationship to TCP teardown state that remains unexplained.
- **Behavioral realism:** 8 — Mixed successful, rejected, unanswered, administrative, browsing, and infrastructure traffic is convincing, with a notable application-observation distribution artifact.
- **Environmental consistency:** 9 — Visible service concentrations and network paths fit the apparent core, DMZ, database, and explicit-proxy roles; the limited window does not establish broader coverage expectations.

## Recommendations

- If this were synthetic, determine application evidence from the actual visible protocol exchange rather than from successful TCP teardown. Retain HTTP transactions or TLS handshake observations for reset and half-closed connections when their modeled packets support them; preserve genuinely incomplete or unparsable exchanges as such.
- If this were synthetic, check the relationship between generic connection-noise generation and protocol-family generation. The same service-classified reset/half-close flows should have a coherent chance of producing partial protocol observations instead of being separated into a connection-only population solely by state.
- If the observed split instead comes from an intentional export filter, document that filter with the collection profile. That would resolve the strongest ambiguity without manufacturing extra protocol rows.
