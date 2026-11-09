# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 84
**Synthetic-Confidence Score:** 72

## Executive Summary

The network evidence is substantially coherent: protocol references, connection intervals, TLS certificate facts, proxying, and infrastructure roles agree in the checks performed. A repeated TCP packet-accounting artifact across unrelated services and sensors is the main reason for a synthetic verdict: clean histories have byte counters incompatible with ordinary complete IPv4/TCP header arithmetic, usually at an exact 1,500-bytes-per-packet ceiling.

## Evidence For Synthetic

- [hard_contradiction] `zeek-core/conn.json:7`, UID `CHobQaXTd62NpmDvAm`, `ts=1793624460.195223`, reports `resp_bytes=5361807`, `resp_ip_bytes=5514000`, and `resp_pkts=3676`, with `history="ShADadfF"`, `conn_state="SF"`, and `missed_bytes=0`. The IP-minus-stream-byte residual is 152,193. For a complete non-retransmitted IPv4/TCP stream, summed IP/TCP header lengths are multiples of four; this residual is not. IP bytes also equal exactly `3676 × 1500`, despite the displayed establishment/closure history.
- [distribution_texture] Excluding histories containing any retransmission (`T/t`) or gap (`G/g`) marker, 56 directional counters in `zeek-core/conn.json` and nine in `zeek-dmz/conn.json` have non-word-aligned IP-minus-stream-byte residuals. Sixty-one of these 65 have IP bytes exactly equal to `packet_count × 1500`. Affected service counts are SMB 47, HTTP 11, RDP three, TLS three, and SSH one. This repeated ceiling suggests counters being bounded or adjusted independently.
- [hard_contradiction] Separate examples are `zeek-core/conn.json:187` (`orig_ip_bytes=1680000`, `orig_bytes=1628245`, `orig_pkts=1120`; residual 51,755) and `zeek-dmz/conn.json:7850` (`resp_ip_bytes=324000`, `resp_bytes=310775`, `resp_pkts=216`; residual 13,225). Both have `history="ShADadfF"` and zero missed bytes. The accounting caveat below limits absolute certainty for individual records.

## Evidence For Real

- Every DNS, HTTP, TLS, and files connection reference checked resolves within its sensor. Protocol timestamps fit associated connection intervals using a modest tolerance; HTTP bodies and file sizes do not exceed corresponding directional connection-byte totals.
- Service concentrations fit segmentation: the database sensor has 319 MySQL-identified connections out of 515, core has substantial DNS/Kerberos/LDAP/SMB activity, and DMZ has web/proxy traffic and unsuccessful probes.
- DNS includes A, AAAA, PTR, SRV, TXT, MX, SOA, NS, successful empty answers, NXDOMAIN, SERVFAIL, and REFUSED. Authoritative internal answers and recursive external answers are differentiated. Identical client/resolver/query/answer keys did not show arbitrary multi-valued authoritative TTL churn.
- TLS version, cipher, resumption, and certificate exposure are differentiated. `zeek-dmz/ssl.json:1` is TLS 1.3 without certificate references; line 4 is a full TLS 1.2 handshake with references. ECDSA-authenticated cipher selections agree with ECDSA leaf key types in the checked certificate-linked records; repeated certificate fingerprints retain identical certificate metadata.
- `zeek-core/http.json:1` describes a client CONNECT to `10.10.3.20:8080`; `zeek-dmz/ssl.json:1` describes the proxy's separate TLS connection to that named destination. CONNECT is correctly distinguished from cleartext origin-server HTTP.
- TCP states include successful, unanswered, rejected, reset, partial, and other connections. Gap histories have nonzero missed-byte counters. No same-sensor TCP connection intervals overlap for an identical directional four-tuple.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory. Quantitative checks covered all 20,363 `conn.json` rows across `zeek-core`, `zeek-dmz`, and `zeek-db`, with DNS, HTTP, SSL, files, and X.509 companions. Citations use one-based physical JSON line numbers. Filesystem times, potentially sanitized domains, complete correlation, and missing optional sources were not treated as authenticity indicators.

The visible window is approximately 2026-11-02 13:00–19:00 UTC. I did not require overnight traffic or initiating/closing records outside that window. Aggregate sensor counts include repeated observations of some physical activity.

### Connection behavior and timing

Core contains 9,182 SF, 1,893 S0, 155 RSTO, 93 RSTR, and 38 REJ connections, plus partial/other categories. DMZ contains 5,595 SF and 2,563 S0 connections. Database traffic is predominantly successful (433 SF), with resets and small partial categories. S0-heavy DMZ activity is compatible with probing and is not inherently unrealistic.

Core hourly counts for UTC hours 13–18 are 1,485, 3,095, 1,644, 1,717, 1,802, and 1,692. DMZ also has an elevated 14:00 hour, while database counts range from 78 to 98. I did not use this six-hour distribution to infer missing nighttime behavior.

Same-sensor TCP four-tuples do not have overlapping reported intervals. DNS RTT values do not exceed corresponding connection durations. These passing checks weaken a verdict based on generic lifecycle disorder.

### Packet-accounting artifact and its limits

For each direction of TCP records without `T/t/G/g` history markers, I calculated:

`residual = directional_ip_bytes - directional_stream_bytes`

For an ordinary complete stream, the residual is aggregate IP/TCP header bytes. IPv4 and TCP header lengths are each multiples of four. Sixty-five directional residuals fail that check. For `zeek-core/conn.json:7`, it is `5514000 - 5361807 = 152193`. For core line 187 it is `1680000 - 1628245 = 51755`. For DMZ line 7850, UID `CqxWtDpxhzj9GtT36H`, it is `324000 - 310775 = 13225`. That last connection is `10.10.3.20:39113 → 172.217.216.76:443`, at `ts=1793644389.905534`, duration 6.369008 seconds, SF with zero missed bytes.

Sixty-one failures coincide with exactly `ip_bytes = 1500 × pkts`. The remaining four IP-byte totals are also multiples of 1,500, although they do not match the final packet counts times 1,500. For example, `zeek-core/conn.json:1183` has `resp_ip_bytes=6100500`, `resp_pkts=4342`, and `resp_bytes=5904173`, yielding a residual of 196,327. The repeated ceiling across unrelated services makes a shared counter-adjustment artifact more likely than unrelated application behavior.

This calculation has a material caveat: Zeek stream-byte counters are sequence-derived, whereas IP-byte counters count observed packets. Capture loss, retransmission, partial streams, and unusual sequence behavior can invalidate naive subtraction. The filter excludes explicitly marked gaps/retransmissions, and the cited rows display full SF histories and zero missed bytes. Nevertheless, packet capture would be needed to establish every individual case absolutely. The strongest evidence is the repeated exact ceiling accompanying the arithmetic failures, not subtraction alone. I therefore stop short of an absolutely certain verdict.

### DNS, HTTP, and TLS

Core's 2,925 DNS rows include 2,179 A, 254 AAAA, 220 TXT, 161 PTR, and 101 SRV queries, with 208 NXDOMAIN and 12 SERVFAIL responses. DMZ has 912 DNS rows including 134 NXDOMAIN responses; database has 62 DNS rows. This is credible diversity rather than a successful-A-only pattern.

`zeek-core/dns.json:102` queries `_ldap._tcp.meridianhcs.local` from `10.10.2.26` to `10.10.2.11`, returning two domain controllers with `AA=true`; line 103 performs Kerberos service discovery. Database's first connection is application-to-database MySQL traffic. Core's first connection and `dhcp.json:1` describe a matching DHCP REQUEST/ACK renewal. These visible roles fit a segmented enterprise environment.

Most apparent HTTP activity is proxy CONNECT traffic: 1,618 of 1,818 core HTTP rows and 1,667 of 2,007 DMZ HTTP rows. Counting CONNECT as ordinary unencrypted browsing would mischaracterize the HTTPS ratio. Both TLS 1.2 and 1.3 occur with AES-GCM, TLS 1.3 ChaCha20, a smaller CBC component, and resumption.

I found no ECDSA-cipher/RSA-leaf mismatch among certificate-linked full handshakes, nor fingerprints changing certificate facts. Repeated file hashes retain consistent total sizes; MD5/SHA1 mappings do not contradict SHA256 mappings in the available file records. These are substantial positive checks. TLS 1.3 certificate omission and comprehensive source alignment were not penalized.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the score |
|---|---|---|---|
| hard_contradiction | Zeek TCP byte/packet counters | 65 directional counters, 56 core and nine DMZ | Clean displayed histories do not reconcile through ordinary complete IPv4/TCP header arithmetic; strongest synthetic evidence, subject to sequence-accounting caveat. |
| distribution_texture | Zeek TCP accounting | 61 of those 65 counters equal exactly 1,500 times packet count | Recurring ceiling links separate failures across services. Supporting evidence for the same defect, not an independent defect family. |

## Realism Score by Category

- **Field format accuracy:** 6 — Credible schemas and protocol fields, but repeated larger-flow byte/packet inconsistencies.
- **Temporal patterns:** 8 — Plausible variation, mixed connection outcomes, and passing interval/four-tuple checks.
- **Cross-source correlation:** 9 — References, file hashes, payload bounds, proxy paths, and certificate facts align in the tested relationships.
- **Behavioral realism:** 8 — Diverse directory, file, application, browsing, infrastructure, and probe traffic.
- **Environmental consistency:** 8 — Service concentrations and proxy/DNS roles fit the visible topology; the bounded window limits broader conclusions.

## Recommendations

- If this were synthetic, derive TCP payload bytes, packet counts, header contributions, and IP-byte totals from a compatible transport-accounting model. Avoid independently clamping IP bytes to `1500 × packet_count` while retaining incompatible stream bytes.
- If this were synthetic, validate full, gap-free TCP records against payload segmentation, header lengths, control packets, and retransmission semantics. Include large SMB transfers and the identified HTTP/TLS/SSH/RDP examples.
- If this were synthetic, preserve the existing distinctions among proxy CONNECT, upstream TLS, TLS 1.3 certificate visibility, certificate identity, DNS outcomes, and sensor-specific connection identities; these already contribute strongly to realism.
