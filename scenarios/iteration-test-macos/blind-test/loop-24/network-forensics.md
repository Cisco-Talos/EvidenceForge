# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 68
**Synthetic-Confidence Score:** 18

## Executive Summary

The network records are production-like in the bounded checks performed: connection states, protocol timing, transfer accounting, DNS responses, and TLS certificate relationships remain internally coherent. I lean real, with moderate confidence because well-engineered synthetic telemetry could pass these checks and no packet capture or collection configuration is available to establish provenance.

## Evidence For Synthetic

- No confirmed synthetic indicator emerged from this bounded review. I did not establish a hard contradiction, required-companion gap, or strong distribution artifact, and therefore do not assign a synthetic category to an unsupported suspicion.
- Residual uncertainty concerns the limits of an internally consistent log export: these checks assess observable plausibility, not provenance. This is not scored as a log-visible synthetic defect.

## Evidence For Real

- The sensors have differentiated traffic and failure populations. `zeek-core/conn.json` contains 11,853 rows, including 1,867 S0 and 134 RSTO; `zeek-dmz/conn.json` contains 9,158 rows, including 2,770 S0 and 110 RSTO; `zeek-db/conn.json` contains 452 rows dominated by MySQL. These are compatible with distinct internal, perimeter/DMZ, and database observation paths.
- Protocol details fit their flows. `zeek-core/dns.json:4` records a NOERROR AAAA lookup for `FILE-LNX-01.meridianhcs.local` without an answer, whereas line 10 contains the matching internal reverse-name vocabulary. The records distinguish NODATA from NXDOMAIN rather than filling every successful response with an IPv4 address.
- TLS 1.2 full handshakes carry inspectable certificate chains; TLS 1.3 rows omit certificate chains that passive sensors generally cannot read. For example, `zeek-dmz/ssl.json:4` references two certificate FUIDs for `CZTmnt1aIZnP0mPYG3r`, while line 1 records TLSv13 with `ssl_history=Cs` and no certificate FUIDs.
- Transfer size and lifetime remain compatible with transport evidence in the checked tables. For example, `zeek-core/files.json:1` records a 5,359,834-byte SMB spreadsheet transfer with duration 0.161575 seconds on `CHobQaXTd62NpmDvAm`; its directional connection-byte budget and lifetime accommodate that transfer.
- The collection has actual variation rather than identical hourly counts: core flow starts by UTC hour 13–18 are 1,428, 3,087, 1,709, 1,776, 1,985, and 1,868. This six-hour daytime window cannot establish overnight or weekly behavior.

## Detailed Analysis

### Scope and reproducibility

I examined only the supplied data directory. The main checks parsed `conn.json`, `dns.json`, `http.json`, `ssl.json`, `files.json`, and `x509.json` in `zeek-core`, `zeek-dmz`, and `zeek-db`; a small DHCP sample provided an additional protocol sanity check. All line references are one-based JSON-lines positions. No endpoint authenticity conclusion is implied, and I did not perform an exhaustive firewall, IDS, or endpoint review.

The observed connection-start window runs approximately 2026-11-02 13:00–18:59 UTC. These are start timestamps, not proof that all sessions had to close inside that interval. I treated starts or closures outside the visible window neutrally.

### Connections, states, and byte accounting

Core records include TCP, UDP, and ICMP in counts 6,432, 5,029, and 392. DMZ counts are 7,862, 1,005, and 291. The database sensor has 391 TCP, 50 UDP, and 11 ICMP rows. SF, unanswered SYNs, resets, rejections, partial closure states, and midstream observations coexist.

Native state/history examples are coherent: `zeek-core/conn.json:229` is an LDAP OTH connection with `history=ADad`, consistent with a midstream observation; line 417 is S3 with `history=ShADadf`, indicating a responder close attempt without a visible originator close. `zeek-dmz/conn.json:1` is S0 with only an originator SYN, one originator packet, zero responder packets, and no fabricated completed duration.

Across these connection tables, I checked each TCP direction for `ip_bytes >= payload_bytes + 40 * packets`, a conservative minimum for the visible IPv4 TCP tuples. None violated that minimum. This is a necessary sanity check, not reconstruction of every packet or proof of exact packet accounting.

Service durations have a useful range. Core successful SSH rows span 0.253550–13,302.801688 seconds, median 2,008.442707 seconds; successful RDP spans 0.172759–3,402.524008 seconds, median 1,217.773859. A short transport or protocol identification alone does not establish a successful interactive login, so I did not classify the short tails as contradictions.

### DNS and proxy paths

Core DNS has 3,006 transactions: 2,222 A, 260 AAAA, 248 TXT, 163 PTR, 102 SRV, plus small NS/SOA/MX populations. Responses include 205 NXDOMAIN, 14 SERVFAIL, and one REFUSED. DMZ has 937 DNS transactions, including 132 NXDOMAIN and five SERVFAIL. These are nontrivial response and query-type mixtures, and they remain compatible with the apparent directory, mail, and proxy environment.

The first proxy sequence illustrates appropriate ownership rather than requiring every client to resolve the eventual Internet address. `zeek-dmz/http.json:1` at 1793624490.726012 is a CONNECT from `10.10.1.42:62846` to `10.10.3.20:8080`. `zeek-dmz/dns.json:1` at 1793624490.729597 is the proxy's lookup, with RTT 0.086179 and answer `23.72.51.162`. `zeek-dmz/ssl.json:1` at 1793624491.182604 is the proxy's outbound TLS connection to that address and uses the same hostname. This supports a coherent client-to-proxy-to-origin path; it does not depend on whether the domain/address pair was sanitized.

I checked protocol UID membership locally within each sensor. All 3,986 DNS, 4,431 HTTP, and 2,937 SSL records reference a connection UID in their respective sensor's connection table. Their timestamps fall within the referenced connection interval using a one-second tolerance beyond the recorded end and a one-millisecond tolerance before the start. Mere completeness of this matching is not a synthetic indicator.

The HTTP population is mostly CONNECT: core 1,878/2,078 and DMZ 1,947/2,320. Thus the apparent amount of HTTP should not be mistaken for predominantly plaintext browsing. The DMZ has 1,767 TLSv13 and 866 TLSv12 SSL rows; the database SSL subset is TLSv12-only, a plausible service-specific distinction.

### TLS and certificate semantics

TLS 1.2 resumed handshakes use `CsiI` without new certificate chains in the sampled records, including `zeek-core/ssl.json:2` and `zeek-db/ssl.json:1`. Full TLS 1.2 chains can be followed through `cert_chain_fuids` to X.509 records and certificate file observations. The first DMZ full handshake, `zeek-dmz/ssl.json:4`, references `FERxF79ogF1nzMq8MH` and `FOQQlLL3O5sV29iOS9K`; the corresponding file records are `zeek-dmz/files.json:1-2`, with certificate bytes and SHA-1 fingerprints.

For the available chain references, adjacent issuer/subject names match and referenced certificates are valid at the handshake timestamps. I also checked leaf public-key type against TLS 1.2 authentication cipher families for 81 core, 520 DMZ, and 10 database non-resumed handshakes with certificate references; no mismatch was found. No TLSv13 row exposes certificate-chain FUIDs.

### Files and lifecycle relationships

For each file row linked to a local connection UID, I checked that `seen_bytes` does not exceed the appropriate originator/responder connection payload budget and that file timestamp plus any recorded duration fits the connection interval, with 0.01-second start and 0.1-second end tolerances. No violation was found. Repeated SHA-1 values within each sensor's file table did not carry conflicting observed complete lengths. Hash strings have expected hexadecimal digest lengths.

As another small check, `zeek-core/dhcp.json:1` identifies an existing client `10.10.1.41`, server `10.10.2.10`, a 7,200-second lease, and `msg_types=[REQUEST,ACK]`; `zeek-core/conn.json:1` has the corresponding UDP 68-to-67 tuple and UID. An already addressed renewal is coherent here, so an initial broadcast discovery is not required inside this window.

### Limits of the conclusion

The strongest evidence is absence of contradictions in specific necessary relationships, together with plausible variation in state, duration, query type, and service populations. It is not proof of production origin. The collection is too short to judge weekly seasonality, and a low-volume source or unavailable product is not independently a defect. I found no justified basis to penalize source completeness, missing selected endpoint event families, sanitized naming, or a narratively compact activity sequence.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| None established | Zeek connection/protocol/file/certificate records | Three sensors; bounded consistency checks and representative semantic samples | No demonstrated contradiction or distribution defect; score remains in the production-like band. |

## Realism Score by Category

- **Field format accuracy:** 9 — JSON field types, digest lengths, protocol fields, states, and certificate references are coherent in the checked records.
- **Temporal patterns:** 9 — Protocol/file records fit transport lifetimes and hourly volumes vary; the short window limits broader timing conclusions.
- **Cross-source correlation:** 9 — Local UID references, file budgets, and TLS certificate chains agree in the checked network families.
- **Behavioral realism:** 8 — Proxy use, directory traffic, resets, scanning, and long-lived remote sessions are plausible; packet-level behavior remains unverified.
- **Environmental consistency:** 9 — The sensor populations and proxy/DNS ownership fit distinct network observation paths without demanding unobserved products.

## Recommendations

- No specific data correction is justified by the bounded checks. If this were synthetic, retain the visible transport/protocol/file/certificate relationships and the distinction between passive TLS 1.2 and TLS 1.3 visibility; I found no concrete defect warranting an invented realism fix.
