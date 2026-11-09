# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 86
**Synthetic-Confidence Score:** 65

## Executive Summary

The network records have substantial protocol and correlation realism, but a large subset of HTTP transactions exposes a precise timing lattice that is difficult to reconcile with ordinary packet-derived timestamps. My verdict rests on this measured, source-local distribution artifact rather than on suspicious activity, source completeness, sanitized destinations, or the neatness of any intrusion narrative. I did not demonstrate a hard protocol contradiction, which limits the score and confidence.

## Evidence For Synthetic

- [distribution_texture] First-request HTTP timing has conspicuously quantized offsets despite six-decimal timestamps. For each `trans_depth=1` HTTP row I joined `uid` to that sensor's `conn.json` and calculated `1000 * (http.ts - conn.ts)`. In `zeek-core`, 124 of 182 first GETs (68.1%) are within 0.5 microseconds of an exact integer millisecond, spanning 13–85 ms; in `zeek-dmz`, 224 of 346 (64.7%) are exact integer milliseconds, spanning 12–85 ms. This is widespread: the quantized GETs involve 19 core client addresses and 71 DMZ client addresses. Examples: `zeek-core/http.json:1` and `conn.json:12` have UID `CEFI3WIyk23ZZVTKrC`, times `1793624436.072399` and `1793624436.046399`, exactly 26 ms apart; `http.json:2` and `conn.json:35`, UID `CTrZ7SAGKzrM9mvSI`, are exactly 85 ms apart (`1793624545.955642` versus `1793624545.870642`). `zeek-dmz/http.json:18` and `conn.json:67` have external client `98.0.18.69`, with timestamps `1793624768.999753` and `1793624768.953753`, exactly 46 ms apart. The identical final three fractional digits repeatedly survive between independently meaningful connection-open and request timestamps.
- [distribution_texture] The timing lattice is operation-selective, which makes a general timestamp-resolution explanation weak. Only 1 of 1,927 first CONNECT requests in core and 2 of 1,973 in DMZ meet the same integer-millisecond test, versus the majority of first GETs. First POSTs also show the effect (7/14 core; 13/29 DMZ). In contrast, no core SSL row (0/345) has an integer-millisecond nonzero offset from its connection timestamp. This supports a family-specific timing construction rather than a uniformly coarse sensor clock. This bullet corroborates the preceding issue and is not counted as an independent defect.

## Evidence For Real

- Connections and protocol companions are coherent. Across the three sensors, all 4,069 DNS, 4,749 HTTP and 3,013 SSL rows resolve to their own sensor's `conn.json` UID and agree on the four endpoint fields. No protocol timestamp precedes its connection or exceeds a recorded connection close by more than 1 ms. This is positive correctness evidence; completeness itself is neutral for authenticity under the study rules.
- TCP states have meaningful variety and match visible close/reset histories in the checks performed. Core includes 4,782 TCP `SF`, 1,438 `S0`, 157 `RSTO`, 107 `RSTR`, 45 `REJ`, and smaller partial/other states. Every tested `SF` has both `F` and `f`; reset states have the corresponding reset direction. Port scanning and incomplete handshakes coexist with normal traffic.
- DNS contains realistic record and error diversity: core has A, AAAA, PTR, SRV, TXT, MX, SOA and NS, with NXDOMAIN, SERVFAIL and REFUSED responses. `zeek-core/dns.json:14` contains an ordinary `isatap.meridianhcs.local` NXDOMAIN. `dns.json:6` contains `_ldap._tcp.dc._msdcs.meridianhcs.local` SRV targets for both visible DCs, with service port 389.
- TLS behavior is not indiscriminately successful or fully visible. DMZ has 1,883 TLS 1.3 and 767 TLS 1.2 records, plus three failed handshakes; resumed and non-resumed sessions occur. `zeek-dmz/ssl.json:2` shows a resumed TLS 1.3 connection with no exposed certificate chain, while `ssl.json:1` has a TLS 1.2 chain whose file IDs resolve to certificate evidence. `ssl.json:54` is an unsuccessful handshake (`established=false`, history `C`) rather than an invented negotiated version/cipher.
- Certificates retain stable identities: within each sensor, repeated fingerprints do not change subject, serial, issuer, validity, key parameters or SANs, and corresponding repeated certificate files have stable byte lengths. The internal LOG-MON certificate identity is also consistent between the initial core and DB examples.
- HTTP includes persistent connections with multiple transaction depths, referential assets, 304 responses without bodies, and file-analysis gaps. For example, `zeek-core/http.json:1189–1191` includes an HTML page, a bodyless 304 WebP request, and a JPEG response on one UID. These are useful details beyond isolated page GETs.

## Detailed Analysis

### Scope and method

I examined only the supplied data tree. The principal analysis used every row in `zeek-core`, `zeek-dmz` and `zeek-db` conn, DNS, HTTP, SSL, files and X.509 JSON, with smaller examinations of DHCP, SMTP, OCSP, proxy, firewall and IDS examples. I did not infer origin from filesystem dates or external domain resolution.

The visible connection window is approximately 2026-11-02 13:00–19:00 UTC. There are 12,170 core connections, 9,278 DMZ connections and 446 DB connections. These are sensor observations and may include the same underlying traffic on more than one sensor; I do not add them as unique enterprise flows.

### HTTP timing: the decisive artifact

The comparison is between two fields within the same sensor and same UID, so clock skew between sensors cannot explain it. Matching decimal suffixes mean that a timestamp such as `.870642` becomes `.955642` by adding exactly `.085000`, repeatedly across unrelated clients and requests. The very high prevalence among GETs is materially different from the CONNECT comparison population from those same files.

A real application can have timers, scheduled polling, or millisecond granularity in application logs. Here the fields are presented as Zeek network observations: connection start and HTTP request time. Both include microsecond-looking fractions, but the delta repeatedly lies on a narrow millisecond lattice. The effect includes external clients and internal clients, so a single periodic monitoring application is not a sufficient explanation. For example, core monitoring `/api/v1/status`, a browser `/products` request, and an external DMZ `/index.html` request all exhibit it. Different absolute sensor offsets preserve the same 26 ms and 85 ms deltas for the paired core/DMZ observations; I treat these duplicated views as corroboration, not independent samples.

A collection/export transformation that deliberately added family-specific latency could produce this. No such transformation is visible in the data, and the CONNECT/GET split makes ordinary global rounding unpersuasive. That remaining alternative prevents a near-certain verdict.

Reproduction: parse each sensor's JSON lines; map `conn.uid` to `conn.ts`; select HTTP `trans_depth == 1`; calculate delta in milliseconds; count rows for which `abs(delta - round(delta)) < 0.0005`. This threshold accommodates floating-point representation of six-decimal Unix timestamps and is only half a microsecond, not half a millisecond. DNS often has exactly zero offset because its query can initiate the UDP flow; that expected zero-offset case was not used as a synthetic signal.

### Transport, accounting and lifecycle

I checked all sensor-local TCP four-tuples for overlapping positive-duration records and found none. I also checked packet accounting: no logged payload count exceeds its corresponding IP-byte count, and the IP-byte-minus-payload difference is sufficient for the minimum per-packet IPv4/TCP or IPv4/UDP header burden in the examined records. Histories containing `G` or `g` have nonzero `missed_bytes` in these data.

Long interactive traffic differs from brief application requests. For example, `zeek-core/conn.json:568` records a successful SSH session lasting 2,427.716355 seconds, and `conn.json:1742` a successful RDP session lasting 2,585.452316 seconds with about 1.86 MB responder payload. `zeek-db/conn.json:182` has a successful SSH session lasting 1,125.598546 seconds. Low payload on a long interactive connection is compatible with idle periods and is not a contradiction.

The detailed checks did not establish impossible protocol-before-transport ordering or post-close file activity. I did not require pre-window opening or post-window closing evidence.

### DNS, TLS and collection path

The mix is compatible with a segmented enterprise using a proxy: core has 2,001 destination-port-8080 records, 2,572 port-88 and 1,155 port-389 records; DMZ has 3,274 port-443 and 2,221 port-8080 observations; DB is dominated by port 3306 (308/446 observations). Raw HTTP/HTTPS ratios therefore cannot be interpreted without distinguishing CONNECT control requests from decrypted content. Most HTTP rows are CONNECT (1,927 core and 1,973 DMZ), not plaintext page retrievals.

`PROXY-01.meridianhcs.local/proxy_access.log:1` explicitly separates CONNECT control bytes from tunnel bytes and tunnel duration. That is more coherent than treating a successful CONNECT's zero response body as an empty subsequent tunnel. `zeek-dmz/dns.json:1` resolves `onedrive.live.com` for `10.10.3.20`; `ssl.json:2` then shows that origin connecting to one returned address with matching SNI about 140 ms later. This is a concrete coherent name-to-connection example, not a requirement that every connection have a fresh DNS query.

I found no changing-certificate-fingerprint contradiction. TLS 1.3 rows without certificate files are compatible with encrypted handshake content. An expired certificate, an unusual issuer, or an unresolvable sanitized name would not by itself demonstrate synthetic origin.

### Ambiguous observations excluded from the score

Seven HTTP UIDs have summed response-body lengths slightly larger than their `conn.resp_bytes` (four core, three DMZ). For instance, core UID `Cc3le6k40YHgqEDMDKC` has 288,183 summed HTTP body bytes versus 286,616 connection responder bytes, and `conn.json:2177` also reports 3,066 missed bytes. File records show partial-content accounting, and the supplied fields do not expose enough about content encoding and transport accounting conventions to resolve this confidently. I did not call this a hard contradiction or add it to the synthetic score.

A six-hour business-day sample cannot establish overnight/weekend realism. Sensor coverage alone does not establish missing endpoint or protocol evidence. The logs support a larger environment than just the endpoint directories, so I did not label additional source addresses as invented hosts.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Zeek HTTP and conn timestamps | 124/182 core and 224/346 DMZ first GETs; 19 and 71 client addresses respectively | Strong, narrowly bounded whole-millisecond latency lattice inconsistent with the surrounding microsecond texture. Main reason for a likely-synthetic score. |
| distribution_texture | HTTP method comparison and SSL comparison | GET/POST affected; CONNECT almost entirely unaffected; core SSL unaffected | Strengthens attribution to behavior-family timing construction. Corroborates the same defect rather than adding an independent penalty. |

No demonstrated hard contradiction, generator identity leak or obligatory missing source family was scored.

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed source-native-looking fields, coherent types and protocol-specific structures; no demonstrated format contradiction.
- **Temporal patterns:** 5 — Lifecycle ordering is good, but HTTP first-request latency has a strong method-specific quantization artifact.
- **Cross-source correlation:** 9 — Sensor-local UID, tuple, file and certificate relationships are coherent in the checks performed.
- **Behavioral realism:** 8 — Proxy tunnels, DNS failures, TLS resumption/failures, interactive sessions and browser asset behavior are plausible.
- **Environmental consistency:** 8 — Segmentation, DC traffic, DB dominance and proxy paths fit together; the short window limits broader assessment.

## Recommendations

- If this were synthetic, derive HTTP request timestamps from a transport/application timing model that preserves submillisecond variation, instead of adding an integer-millisecond latency to a microsecond connection start for most GET/POST traffic. Check the resulting delta distribution separately by method, client role and sensor; fix the narrow 12–85 ms lattice without disturbing same-UID ordering.
- If this were synthetic, retain the existing protocol-state, UID, certificate-identity, file-lifecycle and tunnel-accounting consistency while adjusting timing. These aspects currently support realism; randomizing them independently would damage the coherent network evidence.
