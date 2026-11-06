# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 92
**Synthetic-Confidence Score:** 84

## Executive Summary

The network data has substantial protocol detail and coherent DNS, HTTP, TLS, and sensor relationships. However, a repeated Zeek-native accounting contradiction affects hundreds of completed TCP connections: the same connection's sequence-space payload totals change between sensors by exactly the number of bytes each sensor missed. That pattern strongly suggests a synthetic observation-loss transformation rather than independent Zeek observations of real traffic.

## Evidence For Synthetic

- [hard_contradiction] **Capture loss incorrectly changes TCP sequence-space payload totals.** In `zeek-core/conn.json:65`, connection `10.10.2.40:40543 -> 10.10.3.20:8080` has `orig_bytes=5129`, `resp_bytes=10826`, `missed_bytes=100`, `conn_state="SF"`, and `history="ShADadfFg"` at `2026-11-02T13:04:49.135236Z`. The corresponding DMZ observation, `zeek-dmz/conn.json:36`, has `orig_bytes=5129`, `resp_bytes=10926`, `missed_bytes=0`, `conn_state="SF"`, and `history="ShADadfF"` at `13:04:49.021865Z`. Both see the handshake and FIN termination. Zeek's TCP `orig_bytes`/`resp_bytes` describe payload inferred from sequence space; an interior capture gap is reported separately in `missed_bytes` and should not subtract 100 bytes from the inferred endpoint sequence extent.
- [hard_contradiction] **The same error spans service families and sensor pairs.** `zeek-db/conn.json:12` and `zeek-dmz/conn.json:136` observe the completed MySQL connection `10.10.3.10:58104 -> 10.10.4.10:3306` at approximately `13:09:29Z`. DB reports `(orig_bytes, resp_bytes, missed_bytes)=(2962,38280,122)`; DMZ reports `(2992,38372,0)`. The payload deficit is exactly `30+92=122`. Across near-simultaneous matching tuples, **522 core–DMZ and 58 DB–DMZ completed TCP pairs** have unequal payload totals, and every one satisfies the same loss-subtraction identity. These are repeated manifestations of one underlying defect, not 580 independent defect types.

## Evidence For Real

- Transport and application references are internally coherent within each sensor. All inspected DNS, HTTP, and TLS UIDs resolve to a connection with the same endpoint tuple; application timestamps fall within those connection intervals, allowing 1 ms for timestamp precision.
- TCP state and history have plausible variety. Core has 9,996 `SF`, 1,918 `S0`, 166 `RSTO`, 98 `RSTR`, 23 `REJ`, and smaller partial/other-state populations. DMZ has 2,620 `S0` connections, consistent with its visible external probes rather than uniformly successful traffic. `zeek-dmz/conn.json:1` is an unanswered external SYN to `10.10.3.10:6379`, with zero response packets and `history="S"`.
- TLS visibility follows important encryption boundaries. Across the three sensors, certificate-chain FUIDs occur on non-resumed TLS 1.2 sessions; no TLS 1.3 row exposes a certificate chain. Linked leaf certificates exist, ECDSA-authenticated suites use compatible leaf key types, and no checked certificate fingerprint changes certificate content.
- DNS includes A, AAAA, PTR, SRV, TXT, MX, and NS activity, plus NXDOMAIN, SERVFAIL, and REFUSED outcomes. `zeek-core/dns.json:1` contains a plausible AD LDAP SRV response with two DC targets and matching TTL entries.
- HTTP is not restricted to isolated successful requests. `zeek-core/http.json:78–84` has seven transactions on one UID, incrementing `trans_depth`, page assets, and appropriate referrers. `zeek-core/http.json:2` and `zeek-dmz/http.json:2` report a bodyless `304 Not Modified` response.
- Explicit-proxy byte accounting is credible in a representative complete transaction. `PROXY-01.meridianhcs.local/proxy_access.log:1` reports CONNECT control bytes of 314/148 and tunnel bytes of 1728/32246. Their sums equal the client–proxy TCP payloads, 2042/32394, in `zeek-dmz/conn.json:4`; the separate upstream leg in `zeek-dmz/conn.json:6` has 1728/32246 payload bytes.

## Detailed Analysis

### Scope and method

I examined only the supplied data. Network scope comprises three Zeek collections, proxy access records, and the supplied network context visible through those records. The Zeek connection files contain 12,279 core, 464 DB, and 9,287 DMZ rows. The connection-start window is approximately 2026-11-02 13:00–19:00 UTC.

I parsed the JSON records, grouped protocol records by sensor-local UID, checked tuple equality and timing bounds, screened transport payload/IP-byte lower bounds, examined same-tuple TCP interval overlap, and joined overlapping sensor observations by protocol plus four-tuple with start times within one second. Separate sensors legitimately assign different UIDs. I did not treat matching coverage, sanitized domain names, or out-of-window lifecycle events as evidence of synthesis.

### Primary finding: sequence totals versus observed capture bytes

For TCP, a sensor can miss a packet yet still infer the endpoint's sequence extent from subsequent sequence numbers, acknowledgements, and FINs. Captured packet counts and IP-byte counters may consequently differ between sensors. The `missed_bytes` field can differ too. Those facts do not justify reducing a completely observed TCP session's sequence-derived `orig_bytes` or `resp_bytes` by the missing payload amount.

The example at core line 65/DMZ line 36 is particularly clear: both histories begin with `Sh`, contain bidirectional data, and end with both FIN directions. The lossy core history adds `g`; the payload total falls by exactly 100. Duration remains effectively identical, 4.174150 versus 4.174256 seconds. The four-tuple and timing identify the same connection despite sensor clock offsets.

The MySQL example supplies a second service and sensor pair. DB's history is `ShADadfFGg`, DMZ's is `ShADadfF`, and their durations are 4.148530 and 4.148597 seconds. Both origin and responder totals are reduced at the lossy observer, with their combined reduction exactly equal to `missed_bytes`.

The reproducible aggregate rule is:

`(orig_bytes_A + resp_bytes_A) - (orig_bytes_B + resp_bytes_B) = missed_bytes_B - missed_bytes_A`

It holds for all 522 differing completed core–DMZ pairs and all 58 differing completed DB–DMZ pairs found by the tuple/time join. There are 4,765 total near-simultaneous core–DMZ tuple matches and 331 DB–DMZ matches. This is more persuasive than an isolated bad row or an unfamiliar schema extension. It indicates that observed loss is being applied to a field whose native TCP meaning is different.

I have not scored ordinary cross-sensor HTTP body-length differences as separate contradictions. For example, core `http.json:37` has 631 response-body bytes while DMZ `http.json:40` has 630; the corresponding DMZ connection reports a one-byte gap. Application analyzers can observe fewer actual body bytes when capture is incomplete. The problematic claim is the accompanying change to sequence-derived connection totals.

### DNS and protocol ordering

The first DMZ proxy transaction is temporally sensible: `http.json:1` records CONNECT at `1793624461.684356`, `dns.json:1` records a `www.bing.com` lookup at `1793624461.689653` with `rtt=0.040298`, the upstream connection starts at `1793624461.738194`, and `ssl.json:1` occurs at `1793624461.783240`. Thus the DNS response precedes the upstream connection.

Core's slower-looking observation of the same transaction is consistent with a sensor clock offset. I did not mistake this for backwards network causality. I also did not require a fresh DNS lookup for every connection, since cached results are normal.

### TLS and certificates

TLS records contain both TLS 1.2 and TLS 1.3, resumed and non-resumed sessions, modern AEAD suites, some TLS 1.2 CBC use, and a small number of incomplete handshakes. This is compatible with mixed clients and services. The DB-facing sample is predominantly TLS 1.2 rather than sharing the DMZ's TLS 1.3-heavy distribution.

`zeek-dmz/ssl.json:1` links two certificate FUIDs for its TLS 1.2 Bing session. `zeek-dmz/x509.json:1` supplies a matching leaf and `files.json:1` carries the same certificate FUID and SHA-1/fingerprint identity. Certificate validity intervals contain their observation times in the records checked. These features materially support realism, even though they do not overcome the TCP accounting defect.

### Distribution and collection limits

HTTP is dominated by CONNECT on port 8080, so the raw HTTP-row count must not be read as evidence of a cleartext-web-dominated environment. Core emphasizes DNS/Kerberos/LDAP, DB emphasizes MySQL, and DMZ includes proxy egress plus unsolicited inbound probes. Hourly connection counts vary; core has 1,696 starts in hour 13 and 3,149 in hour 14, while DB has only 55 in hour 15 and 93 in hour 18.

This six-hour daytime window cannot establish overnight behavior or weekly business cadence. I found no defensible distribution-only reason to penalize those unobserved periods, no overlapping same-four-tuple TCP intervals within a sensor, and no general packet-accounting lower-bound failure in the recorded fields. The verdict rests on the demonstrated source-native accounting issue.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `hard_contradiction` | Zeek TCP `conn.json`, core/DMZ/DB | 580 completed cross-sensor pairs have payload totals reduced by exactly the relative `missed_bytes`; examples core:65/DMZ:36 and DB:12/DMZ:136 | Strong, repeated confusion between sequence-derived connection totals and observed capture bytes; sufficient to place the dataset in the 81–100 band despite otherwise good realism |

## Realism Score by Category

- **Field format accuracy:** 7 — JSON fields, references, certificates, and most protocol fields are convincing, but the native meaning of TCP byte totals is violated repeatedly.
- **Temporal patterns:** 9 — Protocol rows remain inside flow intervals; visible proxy DNS/TCP/TLS ordering is sensible, with plausible sensor clock offsets.
- **Cross-source correlation:** 6 — Identity and tuple matching work well; independent sensor observations contradict the expected meaning of completed TCP payload totals.
- **Behavioral realism:** 9 — Plausible scan failures, proxy errors, DNS diversity, HTTP reuse, mixed TLS versions, and service-specific activity.
- **Environmental consistency:** 9 — Core, DMZ, and DB traffic mixes align with their apparent observation paths; no missing-product assumptions were required.

## Recommendations

- If this were synthetic, preserve TCP sequence-derived `orig_bytes` and `resp_bytes` for the same fully observed connection across sensors. Apply capture loss to observed packet/IP-byte counters and analyzer visibility while recording sequence gaps separately in `missed_bytes`.
- If incomplete initial or terminal observation is intended to change inferred sequence extents, make the connection history and lifecycle support that condition rather than retaining a complete handshake and bidirectional FIN close for the affected records.
- Add a cross-sensor invariant check using the demonstrated core:65/DMZ:36 and DB:12/DMZ:136 relationships: capture gaps may alter observed application-body bytes and packet counters, but must not mechanically subtract their size from completed TCP sequence totals.
