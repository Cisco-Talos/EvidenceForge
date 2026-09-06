# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Real  
**Verdict Confidence:** 74  
**Synthetic-Confidence Score:** 30

## Executive Summary

The network telemetry is highly production-like: connection states, protocol timing, DNS behavior, proxy routing, TLS handshakes, certificates, and multi-sensor observations form a coherent six-hour capture. A few source-native details—especially missing duration on every rejected TCP connection—look generated or normalized, but they are limited enough that I judge the dataset more likely real than synthetic.

## Evidence For Synthetic

- `[schema_or_format]` Every observed `REJ` connection—20 in `zeek-core/conn.json` and 29 in `zeek-dmz/conn.json`—has `history:"Sr"` and one packet in each direction but omits `duration`. For example, at `2024-03-18T13:51:37.014989Z`, core UID `CTHVe6avXIZC3VxhUP` records a SYN and responder reset between `10.10.3.10:41194` and `10.10.2.26:443`, yet has no measurable SYN-to-RST interval. Occasional zero-resolution intervals are possible, but uniform omission across all rejected connections is a notable source-native artifact.
- `[weak_signal]` Cross-sensor clock relationships are unusually stable. Across 4,070 matched core/DMZ tuples, DMZ timestamps generally precede core by approximately 114 ms while durations differ by only fractions of a millisecond. A fixed NTP offset can explain this, but the regularity could also reflect programmed per-sensor offsets.
- `[weak_signal]` In `zeek-dmz/http.json`, 19 of 69 HTTP 301 responses inherit resource-oriented MIME types—12 `text/css` and seven `application/javascript`—rather than the more typical `text/html` redirect entity. The first record, at `2024-03-18T12:03:06.249661Z`, returns 301 for `/assets/main.css` with 277 response bytes and `text/css`. This is possible server behavior, but systematic URI-extension-derived typing would be a generator tell.

## Evidence For Real

- Connection-state distributions are varied and plausible. Core contains 8,638 `SF`, 1,952 `S0`, 118 `RSTO`, 86 `RSTR`, 24 `S3`, 21 `OTH`, 20 `REJ`, 14 `S2`, and four `S1` connections. DMZ and database sensors show different, role-appropriate mixtures.
- The dataset contains no negative durations, payload counts exceeding IP-byte counts, impossible zero-packet/nonzero-byte combinations, overlapping reuse of an active TCP five-tuple, or application records outside their associated connection interval.
- Every DNS, HTTP, and TLS record has a matching same-sensor `conn.json` UID and tuple. No tuple mismatch or visible application-before-connection ordering was found among 3,885 DNS, 3,408 HTTP, and 2,429 TLS records.
- DNS behavior has substantial natural texture: A, AAAA, PTR, SRV, MX, SOA, NS, and TXT queries; `NOERROR`, `NXDOMAIN`, `SERVFAIL`, and `REFUSED` responses; Windows-style `wpad`, `isatap`, suffix-appended, stale-host, and reverse-lookup failures; and RTTs ranging from sub-millisecond internal responses to more than two seconds.
- DNS authority flags are context-sensitive. External recursive answers are predominantly `AA=false`, while internal forward and reverse zones are generally authoritative. This avoids a common synthetic DNS defect.
- TLS versions and cipher suites are mutually compatible. TLS 1.3 uses AES-GCM or ChaCha20 suites, while TLS 1.2 uses ECDHE RSA/ECDSA suites. The mix includes 1,564 TLS 1.3 and 865 TLS 1.2 sessions.
- All 1,037 referenced X.509 records exist; observed chains have compatible issuer/subject relationships, certificate validity covers the connection timestamp, and no certificate SAN contradicts its SNI.
- TLS 1.3 frequently lacks visible certificate-chain records, while non-resumed TLS 1.2 sessions usually contain them. That distinction is consistent with encrypted TLS 1.3 handshake visibility rather than indiscriminate record generation.
- The explicit-proxy topology is coherent. Core HTTP logs contain 1,395 `CONNECT` requests to `10.10.3.20:8080`, while the DMZ sensor sees the proxy’s origin-facing TLS connections. CONNECT response bodies are empty and normal HTTP 304 responses uniformly have zero body length.
- Multi-sensor observations are similar without being blindly duplicated. A long SSH connection beginning at approximately `2024-03-18T13:40:16Z` appears in core and DMZ with sensor-local UIDs, a clock offset, nearly identical duration, and matching packet/byte accounting.
- The `10.10.3.10` scan at `2024-03-18T13:51:36Z` has realistic scanner texture: 1,270 attempts covering 254 addresses across ports 22, 80, 443, 445, and 3306 in randomized order over roughly ten seconds, producing mostly `S0` with some `REJ` and successful connections.
- DHCP renewals are host-stable and approximately follow half-lease timing with jitter. MAC, hostname, and assigned address remain consistent across renewals rather than being independently regenerated.

## Detailed Analysis

### Collection profile

The Zeek data spans `2024-03-18T12:00:03.920960Z` through `17:59:53.110163Z`, corresponding to a six-hour daytime slice. The three sensors contain 19,215 connection records: 10,877 core, 7,918 DMZ, and 420 database-segment observations.

Hourly core connection counts are 1,418, 2,998, 1,447, 1,506, 1,992, and 1,516. The 13:00 UTC peak is principally explained by the observed scan rather than a smooth volume curve. HTTP and DNS continue throughout the window with independently varying hourly counts.

### Connection and transport behavior

Core traffic contains substantial DNS, Kerberos, LDAP, HTTP proxy, SMB, TLS, syslog, SSH, DHCP, SMTP, and RDP activity. The database sensor is appropriately dominated by MySQL—264 identified MySQL connections among 420 total records—while still seeing DNS, monitoring/syslog, HTTPS, SSH, Kerberos, LDAP, and limited SMB.

Duration distributions are service-sensitive. Median core duration is about 53 ms because DNS, Kerberos, and LDAP are prominent; DMZ median duration is approximately 1.54 seconds; database median duration is approximately 1.79 seconds. Long interactive SSH sessions extend for tens of minutes or hours, including UID `CsziPPxUaYDVKYOxo`, which runs for 15,424.919 seconds and closes inside the capture at approximately `17:57:21Z`.

Packet accounting is internally valid. TCP average header overhead varies by direction and flow rather than remaining at one mechanically fixed value. UDP and ICMP accounting consistently reflects their expected 28-byte IPv4-plus-protocol overhead for the single-packet transactions represented.

The main transport weakness is the treatment of `REJ`: two packets and `Sr` history demonstrate a request and reset, but all such records omit duration.

### DNS behavior

Core DNS includes 2,097 A, 252 AAAA, 129 PTR, 93 SRV, 314 TXT, ten MX, nine SOA, and six NS queries. Its responses comprise 2,679 `NOERROR`, 210 `NXDOMAIN`, 18 `SERVFAIL`, and three `REFUSED`.

The first core transaction illustrates good timing. Connection UID `CsVG5T6KlU0VHmsVhP` starts at `12:00:11.049086Z`; the DNS query is logged at `12:00:11.051080Z` with an 8.739 ms RTT; and the 10.995 ms UDP connection interval contains the complete request and response.

NXDOMAIN texture includes `wpad`, `isatap`, unqualified names, suffix-appended external names, stale internal systems, random suspicious domains, and failed PTR lookups. TTLs range from one second to 86,400 seconds, including decrement-like cached values rather than only a small fixed pool.

The TXT burst beginning near `16:44:34Z` from `10.10.2.30`, including long randomized labels under `ns1.westbridge-services.cloud`, is behaviorally consistent with DNS tunneling. It is scored as observed network activity, not as an authenticity defect.

### HTTP and proxy behavior

The core sensor records 1,573 HTTP transactions, including 1,395 CONNECT requests. DMZ records 1,819, including 1,433 CONNECT requests and direct inbound web traffic. Database records only 16 HTTP events, consistent with restricted server egress through the proxy.

HTTP lifecycle semantics are sound:

- All 19 multi-request UIDs have sequential `trans_depth` values.
- HTTP timestamps remain inside their connection intervals.
- CONNECT 200 responses carry no response body.
- All 25 observed 304 responses have zero body length and no extracted response file.
- Error responses have plausible HTML or JSON bodies.
- Response file identifiers are present when Zeek reports extracted content.

The questionable detail is the extension-oriented MIME type on some redirects, although most redirect responses are correctly classified as `text/html`.

### TLS and certificate behavior

TLS usage is modern but heterogeneous:

- Core: 173 TLS 1.2 and 158 TLS 1.3 sessions.
- DMZ: 661 TLS 1.2 and 1,406 TLS 1.3 sessions.
- Database: 31 TLS 1.2 sessions.

At `12:00:04.152480Z`, inbound UID `C3VTc67u0ApBp6OqlI` negotiates TLS 1.2 with `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` for `ehr-portal.meridianhcs.com`. Its connection began at `12:00:03.920960Z`; both certificate file identifiers exist; their X.509 records appear afterward in handshake order; and the leaf SAN matches the SNI.

No incompatible TLS version/cipher pair, out-of-validity certificate, broken presented chain, missing certificate reference, or SNI/SAN contradiction was found. All 31 Zeek SMTP sessions marked `tls=true` also have matching SSL records under the same UID.

### Multi-sensor correlation

Sensor-local UIDs differ across sensors, as expected for independent Zeek instances. Matching five-tuples show stable but nonzero clock offsets:

- Core versus DMZ: 4,070 matched connections, median offset approximately −114 ms.
- Core versus database: 137 matches, median offset approximately +65 ms.
- DMZ versus database: 282 matches, median offset approximately +179 ms.

Connection states agree across every matched pair. Packet and byte differences occur on a minority of matches, consistent with capture-point or packet-loss effects. The DMZ sensor also observes two scan connections absent from core, preventing the data from looking like a literal duplicated feed.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---:|---|
| `schema_or_format` | Zeek `conn.json` | All 49 `REJ` records | Strongest concern: every visible SYN/RST exchange lacks a measurable duration. |
| `weak_signal` | Zeek multi-sensor timing | Thousands of matched flows | Stable 65–179 ms sensor offsets could be real clock skew but appear unusually controlled. |
| `weak_signal` | Zeek HTTP | 19 DMZ redirects | Resource-derived MIME types on redirect entities may indicate templated response construction. |

## Realism Score by Category

- **Field format accuracy:** 8 — Zeek fields and protocol semantics are strong overall, with rejected-connection duration handling the principal weakness.
- **Temporal patterns:** 9 — Bursty scans, varied interarrival times, realistic DNS RTTs, long sessions, and jittered DHCP renewals are convincing.
- **Cross-source correlation:** 9 — UID, tuple, timing, SMTP/STARTTLS, file, and certificate contracts are coherent without visible impossible ordering.
- **Behavioral realism:** 9 — Proxy browsing, service-specific durations, DNS suffix failures, scanning, lateral traffic, and mixed TLS behavior fit a live enterprise.
- **Environmental consistency:** 8 — Segment-specific service distributions and sensor visibility are plausible, although the fixed clock offsets merit scrutiny.

## Recommendations

If this were synthetic, the following changes would improve it:

- Give `REJ` connections a source-native, positive SYN-to-RST duration derived from the modeled network RTT. Do not omit duration uniformly whenever the state is `REJ`.
- Derive redirect MIME types from the actual redirect response entity and headers rather than the requested URI extension; most 301/302 bodies should reflect the server’s redirect template.
- Model sensor clock offset as a slowly drifting clock process, with small capture-point latency and timestamp noise, if the collection profile is intended to represent independently synchronized physical sensors.
