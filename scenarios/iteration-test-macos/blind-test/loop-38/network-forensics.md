# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 77
**Synthetic-Confidence Score:** 62

## Executive Summary

The network telemetry is broadly coherent and substantially production-like: connection states, sensor-specific loss, proxy topology, DNS variety, TLS certificate relationships, and service-dependent durations withstand several consistency checks. My synthetic verdict rests on a narrowly scoped but concrete DNS-over-TCP contradiction: a decoded successful IPv4 answer is attributed to a connection containing too few response bytes to carry even the smallest such response. This is a localized defect, not evidence that the wider dataset has uniformly poor realism.

## Evidence For Synthetic

- [hard_contradiction] At **2026-11-02 17:44:30 UTC**, `zeek-core/dns.json:2174` reports UID `CRkx67bXuEAx6OIOJY`, TCP `10.10.2.11:57540 → 10.10.2.10:53`, transaction `16109`, `rcode_name=NOERROR`, `TC=false`, and `answers=["10.10.2.10"]`. The exact UID/tuple in `zeek-core/conn.json:9826` reports **`resp_bytes=25`**, `missed_bytes=0`, and history `ShADadf` without a content-gap marker. A DNS message containing even one IPv4 answer needs at least 27 DNS bytes under an unrealistically minimal root-owner/omitted-question construction, plus the two-byte TCP message length. A conventional reply echoing this question needs 59 TCP payload bytes. Thus the contradiction survives uncertainty about the sanitized domain's original length. This looks like transport accounting and decoded application evidence diverged for a partial-close connection.

## Evidence For Real

- The three sensors have believable different traffic mixes. `zeek-core/conn.json` contains 12,279 rows, including 2,576 Kerberos, 1,101 LDAP, 450 SMB, 56 SSH, and 16 RDP service classifications. `zeek-db/conn.json` contains 464 rows, dominated by 307 MySQL-classified flows. `zeek-dmz/conn.json` contains 9,287 rows with much heavier TLS/proxy traffic and unsuccessful probes.
- State/history relationships are largely credible. For example, `zeek-dmz/conn.json:1` is an unsolicited Redis-port attempt with `S0`, history `S`, one originator packet, zero responder packets, and no invented application exchange. Across the collection, rejected TCP attempts use `Sr`/`Srr`, reset connections contain the corresponding reset direction, and partial closes have appropriate `F`/`f` histories.
- DNS includes positive responses, NXDOMAIN, SERVFAIL, REFUSED, IPv4, IPv6, reverse, and service discovery. Core totals are 2,270 A, 266 AAAA, 247 TXT, 142 PTR, 100 SRV, eight NS, and six MX records; the 3,039 core DNS transactions include 213 NXDOMAINs. `zeek-core/dns.json:45` provides a plausible internal reverse lookup of `10.2.10.10.in-addr.arpa` to `DC-01.meridianhcs.local` with an authoritative 3,600-second TTL.
- Sensor-specific packet loss is represented coherently in examples. `zeek-core/conn.json:65` has UID `COV3GL6we7MSGZbDS`, `missed_bytes=100`, `resp_bytes=10826`, and history ending in lowercase `g`; the matching tuple in `zeek-dmz/conn.json:36` has `resp_bytes=10926`, no missed bytes, and no gap suffix. This is a plausible distinction between observation points, rather than a requirement that all sensors see identical payloads.
- TLS chains and identities are internally consistent. In `zeek-dmz/ssl.json:1`, `www.bing.com` uses a TLS 1.2 RSA-authenticated suite and references certificate FUID `F7V6NNfQcjtxQds8gx`; `zeek-dmz/x509.json:1` identifies the corresponding RSA leaf, matching hostname/SAN and SHA-1 fingerprint. The linked `files.json:1` digest agrees.
- HTTP browsing contains multiple transactions on a persistent connection, distinct content types, referrers, and varied response sizes. For example, `zeek-core/http.json:78–84` records an HTML document followed by JavaScript, SVG, favicon, CSS, additional JavaScript, and WebP assets under one UID with increasing transaction depths.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory, concentrating on all JSON records in `zeek-core`, `zeek-dmz`, and `zeek-db`. These contain **22,030 connection observations**, **3,993 DNS rows**, **4,825 HTTP rows**, and **3,106 SSL rows**. These totals are sensor observations, not counts of unique end-to-end activity; some traffic appears at multiple sensors. The connection-start window runs approximately **13:00–18:59 UTC on 2026-11-02**.

For every DNS, HTTP, and SSL row, I checked the local sensor's connection UID. There were no orphaned UIDs, no application timestamps before their connection start, and no application timestamps after the recorded connection interval within a one-millisecond tolerance. I also checked TCP tuple overlap, byte-versus-IP-byte lower bounds, file payload bounds, certificate consistency, and several protocol-specific relationships. Completeness itself did not count toward the synthetic verdict.

### Connection states, timing, and roles

Core state totals are 9,996 SF, 1,918 S0, 166 RSTO, 98 RSTR, 23 REJ, and smaller partial/midstream categories. DMZ has 6,451 SF and 2,620 S0, fitting a more exposed observation point; the database sensor has 386 SF and six S0. UDP and ICMP rows contribute to state totals, so interpreting all S0 rows as unsuccessful TCP handshakes would be misleading.

Service-dependent durations are convincingly separated. At the core, SSH has a median duration of approximately **1,686 seconds**, RDP **1,311 seconds**, Kerberos **0.020 seconds**, LDAP **2.218 seconds**, and HTTP **1.854 seconds**. Database MySQL flows have median **2.506 seconds** and range approximately **0.028–29.844 seconds**. These are plausible mixtures of interactive sessions, short authentication traffic, and application queries.

Traffic is not perfectly flat: core hourly connection counts are 1,696, 3,149, 1,825, 1,785, 2,021, and 1,803 for UTC hours 13 through 18. The DMZ similarly peaks at hour 14. The bounded daytime window cannot establish overnight activity or a full working-week rhythm, and I did not score their absence.

### DNS and the decisive payload inconsistency

Ordinary DNS wire-length checks passed for the overwhelming majority of rows. The exception is the TCP answer identified above. Its connection starts at `1793641470.655130`; the DNS row timestamp is `1793641470.656542`; and the duration is `0.005077` seconds. Thus this is an entirely visible exchange, not a missing pre-window initiator or a post-window response.

The contradiction does not depend merely on assuming that every DNS response repeats the question. A minimal IPv4 answer needs a 12-byte DNS header and at least a 15-byte resource record: one byte for the smallest possible owner name, ten bytes for TYPE/CLASS/TTL/RDLENGTH, and four bytes for the IPv4 address. DNS over TCP also requires a two-byte length prefix. That yields **29 bytes**, already exceeding the logged **25-byte entire responder payload**. The actual named response normally requires substantially more. There is no reported loss to reconcile this with the decoded answer.

This single row should not be generalized into a claim that all DNS behavior is implausible. Other visible TCP DNS exchanges have realistic success/failure variation, and the wider A/AAAA/PTR/SRV population is convincing.

### HTTP and TLS

Most observed HTTP transactions are CONNECT requests to a proxy, not cleartext browsing to Internet websites. Core has 2,052 CONNECT, 223 GET, and 19 POST rows; DMZ has 2,077 CONNECT, 407 GET, and 28 POST rows. Consequently the raw count of HTTP rows does not demonstrate an implausibly high cleartext-web ratio. `zeek-core/http.json:1` represents a client connecting to `10.10.3.20:8080`, while `zeek-dmz/ssl.json:1` observes that proxy's external TLS connection to Bing.

DMZ TLS contains 1,948 TLS 1.3 and 781 TLS 1.2 rows, with modern AES-GCM/ChaCha20 suites and a smaller CBC tail. The database sensor's 17 SSL rows are all TLS 1.2, a plausible application-specific difference. Across the linked certificate evidence, I found no conflicting certificate properties for a reused fingerprint or serial, no issuer/subject mismatch between represented adjacent chain elements, no certificate outside its validity period, and no ECDSA/RSA leaf-key mismatch for the applicable TLS 1.2 authentication suite.

Some HTTP body counters differ across observation points where packet loss is also recorded. I did not treat those differences as hard contradictions: source loss and analyzer accounting need to be distinguished from application-truth errors. In particular, the seven core HTTP responses at lines 78–84 total 709,681 body bytes versus 705,581 connection response bytes, but that connection (`conn.json:706`) also records 5,360 missed bytes. That ambiguity is materially different from the zero-loss DNS case.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| hard_contradiction | Core Zeek DNS and connection accounting | One TCP UID: DNS line 2174 / connection line 9826 | Decoded A response cannot fit in the entire reported response payload, even with a domain-independent absolute lower bound. Principal reason for exceeding the mixed/inconclusive band. |

The narrow scope of the finding and the many successful checks keep the score near the bottom of the likely-synthetic range. There is no supported dataset-wide generator fingerprint in this review.

## Realism Score by Category

- **Field format accuracy:** 9 — Consistent JSON types, recognizable Zeek tuples/states, and coherent linked certificate/file fields.
- **Temporal patterns:** 9 — Service-dependent durations, nonflat traffic, credible state histories, and no observed application-outside-connection ordering failures.
- **Cross-source correlation:** 7 — UID and certificate integrity are strong, but one decoded DNS response contradicts its own transport payload accounting.
- **Behavioral realism:** 9 — Proxy use, internal authentication, database service traffic, interactive durations, failed probes, and DNS variety are plausible.
- **Environmental consistency:** 9 — Sensor traffic mixes support distinct core, DMZ, and database observation paths without requiring unobserved collectors.

## Recommendations

- If this were synthetic, derive TCP DNS response payload accounting from the same response content that populates `answers`, including DNS-over-TCP framing. Preserve that accounting when applying partial-close states; the concrete repair target is UID `CRkx67bXuEAx6OIOJY`.
- If this were synthetic, add a protocol-aware consistency check that rejects a successfully decoded DNS answer when its connection's available response bytes cannot carry the response and no capture loss explains the discrepancy. Include unusual TCP termination states in that check.
