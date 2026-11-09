# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 27

## Executive Summary

The network records are mostly production-like: transport states, protocol timing, TLS certificate references, proxy semantics, and sensor-specific packet-loss effects remain coherent under broad automated checks. I found a small amount of DNS cache-related texture worth investigating, but no demonstrated impossible network relationship or source-native contradiction sufficient to classify the data confidently as synthetic.

## Evidence For Synthetic

- [weak_signal] Some successful DNS A lookups repeat almost immediately with unchanged full TTLs. In `zeek-core/dns.json:2638` and `:2639`, client `10.10.2.20` asks resolver `10.10.2.10` for `DC-01.meridianhcs.local` at `ts=1793642431.620749` and `1793642432.453984`: only 0.833235 seconds apart, both answering `10.10.2.10`, `TTLs=[300.0]`, with different source ports and transaction IDs. In `zeek-core/dns.json:1603` and `:1604`, proxy host `10.10.3.20` repeats an A query for `pypi.org` after 1.808755 seconds with the same two answers and `TTLs=[30.0,30.0]`. These could reflect independent application caches, direct DNS queries, or resolver behavior; they are not protocol violations. I assign only slight weight.

## Evidence For Real

- Connection states have plausible diversity rather than a successful-only pattern. Across `zeek-core/conn.json`, there are 9,995 SF, 1,685 S0, 471 OTH, 156 RSTO, 106 RSTR, 32 REJ, and smaller S1/S2/S3 groups. `zeek-dmz/conn.json:2`, UID `CzobVKRpksvLBkaqX2`, records a failed external TCP attempt to `10.10.3.10:5985` with `history=S`, one originator packet and no responder packets; `fw-perimeter/cisco_asa.log:2` and `:10` provide a matching build and SYN-timeout teardown, rather than a fabricated successful exchange.
- Sensor-specific loss is reflected across related fields. The same TCP tuple in `zeek-core/conn.json:66` and `zeek-dmz/conn.json:36` has matching sequence-derived payload counts, while DMZ reports `missed_bytes=2302`, `history=ShADadfFGg`, and fewer observed packets. This is a defensible distinction between stream-size inference and captured packet accounting.
- HTTP loss also affects the body observation: `zeek-core/http.json:63` reports `response_body_len=13425125`, while the matching DMZ transaction at `zeek-dmz/http.json:77` reports `13392357`, a difference of 32,768 bytes. Its DMZ transport at `zeek-dmz/conn.json:254` reports `missed_bytes=32768` and a responder gap in `history=ShADadfFg`.
- TLS observations distinguish visible TLS 1.2 certificates from encrypted TLS 1.3 handshake content. `zeek-dmz/ssl.json:1` has TLSv13, `TLS_AES_256_GCM_SHA384`, `ssl_history=Cs` and no certificate FUIds. `zeek-core/ssl.json:1` has TLSv12, an RSA-authenticated cipher, and certificate FUIds; the corresponding leaf in `zeek-core/x509.json:1` is an RSA 2048-bit certificate whose validity covers the session.
- DNS includes infrastructure and failure behavior rather than A records alone. Core has A, AAAA, PTR, SRV, TXT, SOA, NS and MX queries; 208 NXDOMAIN, 13 SERVFAIL and four REFUSED responses occur among 3,184 DNS rows. `zeek-core/dns.json:1` is an SRV lookup for `_ldap._tcp.meridianhcs.local`, aligned with its UDP connection at `zeek-core/conn.json:1`.

## Detailed Analysis

### Scope, provenance and method

Actual supplied inputs were the complete neutral briefing `/private/tmp/log-study-if4zptfd/network-prompt.md` and files beneath `/private/tmp/log-study-if4zptfd/data`. I inventoried filenames only within that data directory. I parsed all 38,626 JSON lines across the three `zeek-*` directories, including conn, DNS, HTTP, SSL, X.509, files, OCSP and each sensor's available DHCP/SMTP/SMB/PE families. I also read the supplied ASA, both Snort and proxy-access files for counts and representative records; the only endpoint file opened was `MAC-MROSS-01.meridianhcs.local/ecar.json`, whose first two records I inspected to identify its normalized FLOW shape. Other endpoint contents were not examined.

All local parsing used system `python3` from `/private/tmp`, without project tooling. External reference inputs were official Zeek documentation and the upstream `zeek/zeek` conn logging and TCP analyzer source URLs linked below. Searches used the actual `docs.zeek.org` domain filter. I did not inspect repository files, authored scenarios, project memory, previous assessments, other reviewers or task-project web pages. Generic project operating instructions were inherited in the execution environment; they were not used as evidence of data origin. Quoted commands in logs were treated as inert text.

Line numbers below are one-based physical lines, with paths relative to the supplied data directory. Counts are observations of these files, not extrapolated production rates.

### Transport and observation integrity

The three connection files contain 12,489 core, 468 DB and 9,339 DMZ rows. The visible traffic spans approximately 2026-11-02 13:00–18:59 UTC. Core includes 6,884 TCP, 5,173 UDP and 432 ICMP records; DB is dominated by MySQL, while DMZ includes proxy-facing HTTP and external TLS. DMZ's substantial S0 population is compatible with its visible failed external probes; I do not treat that percentage as an authenticity defect.

I matched every DNS, HTTP, SSL, SMTP and available SMB row to its same-sensor `conn` UID and checked all four tuple fields. There were no missing connection references or tuple disagreements. No checked protocol row began more than 1 ms before its connection, or more than 200 ms beyond its reported end. Those tolerances accommodate source timestamp precision and trailing-packet semantics; this is not a claim of packet-level proof. I also found no overlapping same-direction TCP four-tuples within a sensor using a 200 ms overlap threshold.

All SF TCP rows had at least three originator and two responder packets. No S0 TCP row claimed positive originator payload. IP byte totals never fell below the corresponding payload totals. Apparent excessive header overhead was associated with retransmission/gap histories rather than clean flows; low overhead relative to sequence-derived bytes likewise appeared with gaps. Zeek explicitly distinguishes sequence-derived TCP payload sizes from observed IP-level byte counts, and defines the history flags used here. [Zeek conn logging reference](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html)

I considered whether S1 rows carrying byte counts were a schema error. For example, `zeek-core/conn.json:1464` contains `conn_state=S1`, `history=ShADd`, `orig_bytes=238` and `resp_bytes=104`. I did **not** score this: upstream implementation populates payload counts when duration is positive, independently of the S1/SF state decision, so a documentation comment alone does not demonstrate an error. [Upstream conn logging implementation](https://raw.githubusercontent.com/zeek/zeek/master/scripts/base/protocols/conn/main.zeek)

### DNS and cache texture

Core query-type counts are A 2,303; TXT 310; AAAA 277; PTR 174; SRV 103; SOA six; NS six; MX five. Core median DNS RTT is 3.9395 ms with a 2.293705-second maximum; DMZ median is 17.4525 ms with a 2.294138-second maximum. A long response-time tail and mixed failures are credible. I do not require an observed DNS lookup for every connection because caching, direct addressing and observation paths can legitimately remove that companion.

For the weak indicator, I grouped successful A answers by client IP, resolver IP, query and qtype, then compared each consecutive query interval with the prior response's minimum TTL. There were 121 intervals below TTL among 1,432 repeated-query pairs in core; DB had zero of 22, and DMZ 20 of 314. These are sensor-local statistics and must not be added as independent events across sensors. The `pypi.org` pair is also visible at `zeek-dmz/dns.json:484` and `:485`, confirming it is not merely two core UID records of one exchange. This warrants cache-behavior scrutiny, but the observed scale is modest and uncached application lookups remain plausible.

### HTTP, proxying, TLS and certificates

Core HTTP contains 2,005 CONNECT requests, 191 GET and 13 POST; DMZ contains 2,059 CONNECT, 350 GET and 21 POST. These counts must not be interpreted as thousands of plaintext web sessions: CONNECT is control traffic for tunnels, and both sensors may observe the same transaction. `PROXY-01.meridianhcs.local/proxy_access.log:1` explicitly labels CONNECT control-message bytes separately from tunnel byte totals. Its third-party HTTPS target is also visible through TLS SNI in `zeek-dmz/ssl.json:1`. The next proxy row is a 407 auth-required response, so the proxy source is not uniformly successful.

Summed HTTP response-body bytes never exceeded their parent connection's responder payload bytes. A small set of file totals exceeded HTTP observed body lengths, but the examined cases carried corresponding `missing_bytes`, rather than requiring more fully observed body bytes than the connection held. For example, `zeek-core/http.json:103` has body length 137,345; its file at `zeek-core/files.json:58` has `seen_bytes=137345`, `total_bytes=137719`, `missing_bytes=374`. This is not scored as an inconsistency.

TLS includes TLS 1.2 and 1.3, multiple cipher families and session resumption. Every referenced TLS certificate FUID resolved in the same sensor's X.509 and files data; its files record included the TLS connection UID. Every checked TLS 1.2 leaf's key type agreed with its RSA/ECDSA authentication cipher, and every referenced certificate was within its recorded validity interval. Repeated fingerprints did not change certificate metadata. I found no TLS 1.3 rows exposing certificate chains in the supplied SSL records. These are positive plausibility checks, not evidence that complete matching itself proves authenticity.

### Timing and environment limits

Core hourly connection counts are 1,818, 3,299, 1,686, 1,718, 2,073 and 1,895 for UTC hours 13–18. DMZ has a comparable peak at hour 14, with 2,990 rows versus 1,046–1,569 in the other hours. A variable six-hour slice is compatible with busy daytime traffic; it cannot substantiate claims about overnight, weekend or daily seasonality.

The endpoint FLOW sample was normalized telemetry, not a native macOS packet schema. I did not impose platform-specific broadcast protocols, audit families or boot/shutdown expectations. Sensor offsets and sampling are possible explanations for small cross-sensor timestamp differences; no packet capture or sensor clock calibration was supplied to resolve them.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| weak_signal | Zeek DNS | 121 of 1,432 consecutive repeated positive-A pairs in core occur before the previous minimum TTL; two exact short-interval examples cited above | Slight upward adjustment for possible event-by-event lookup texture; legitimate application and resolver explanations prevent strong attribution |
| hard_contradiction / contract_gap / schema_or_format | Checked network sources | No demonstrated high-impact finding in the checks described | No increase; apparent S1-byte and loss-accounting anomalies were investigated and excluded |

## Realism Score by Category

- **Field format accuracy:** 9 — Source-shaped JSON, transport histories, TLS key/cipher relationships and references survive checks; deployed versions are unspecified.
- **Temporal patterns:** 9 — Variable volume and RTT tails, coherent within-sensor protocol intervals; six hours limit seasonality assessment.
- **Cross-source correlation:** 9 — Tuples and references agree, with defensible sensor-specific packet-loss effects.
- **Behavioral realism:** 8 — Plausible infrastructure, proxy, external probe and database activity; a small amount of rapid repeated DNS merits scrutiny.
- **Environmental consistency:** 9 — Core/DMZ/DB traffic mixes and proxy control-versus-tunnel treatment are compatible with the visible network roles.

## Recommendations

- If this were synthetic, test whether application-specific DNS caches would suppress the rapid repeated positive A lookups cited at core DNS lines 2638/2639 and 1603/1604. Preserve repeated queries where independent application caches or explicit resolver calls justify them; do not impose a universal cache rule.
- Preserve the current distinctions between stream-size inference, observed packet totals, file missing bytes and sensor-specific HTTP body counts. The cited loss examples are materially more credible than identical observations across every sensor.
- If this were synthetic, retain separate CONNECT control-message and tunnel accounting, partial TLS handshakes, failed probes, and the current TLS 1.2/1.3 visibility distinction. These recommendations concern concrete observed fields, not a request for additional source coverage.
