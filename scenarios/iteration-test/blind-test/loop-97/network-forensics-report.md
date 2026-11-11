# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 80
**Synthetic-Confidence Score:** 28

## Executive Summary

The bounded network sample is mostly production-like: transport and protocol records agree on exact identities, TLS observation respects encrypted certificate visibility, and DNS and connection outcomes show meaningful variety. I found no demonstrated source-native contradiction; the limited six-hour window and 19 inspected records do not establish whether the collection is real or synthetic.

## Evidence For Synthetic

- No high-impact synthetic indicator was demonstrated in the inspected records or descriptive aggregates.
- [weak_signal] The DB sensor has 19/19 TLS records using TLS 1.2, including 11/19 negotiating `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256`; core has 40/413 using that cipher. The inspected DB example is `zeek-db/ssl.json:10`, UID `C86skU4nKOD3QEHD46`, at `2026-11-02T14:17:35.851207Z`, from `10.10.4.10` to `10.10.2.40:443`, SNI `LOG-MON-01.meridianhcs.local`. Such concentration could reflect a narrow cipher pool, but a legacy internal service or client policy readily explains it. This is not a demonstrated defect and carries negligible weight.

## Evidence For Real

- Exact DNS/transport agreement: `zeek-core/dns.json:1` and `zeek-core/conn.json:1` share UID `ClnAf4xMznbwm13HlN`, time `1793624400.006178`, tuple `10.10.2.20:58104 → 10.10.2.11:53/udp`, and `0.000469` seconds DNS RTT/connection duration. The DNS response answers `DC-01.meridianhcs.local` with `10.10.2.10`, with an authoritative 300-second TTL. The connection has one packet in each direction and plausible UDP/IP byte overhead.
- Exact TLS/transport/certificate agreement: UID `CfXsGkkuG9lcJw887K` joins `zeek-core/conn.json:7171` to `ssl.json:207`; both identify `10.10.1.21:42707 → 10.10.2.21:443`. Its certificate IDs resolve to `x509.json:127-128`, with matching leaf SNI/SAN and coherent issuer/CA roles.
- TLS 1.3 records do not expose certificate-chain IDs: 0/214 core and 0/2,125 DMZ TLS 1.3 rows carry `cert_chain_fuids`, consistent with passive observation of encrypted TLS 1.3 certificate messages. This avoids a common implausible certificate-visibility assumption.
- Core DNS includes A 2,398/3,265, AAAA 274, PTR 163, SRV 100, TXT 307 and rarer NS/SOA/MX queries. Outcomes include 222 NXDOMAIN, 14 SERVFAIL and four REFUSED responses rather than universal success.
- HTTP is predominantly proxy tunneling, not an implausibly large volume of plaintext browsing: core has 2,318 CONNECT transactions among 2,520 HTTP records; DMZ has 2,364/2,776. Status distributions include proxy authentication failures, forbidden responses and gateway errors.
- Connection states are varied: core includes 10,406 SF, 1,768 S0, 162 RSTO, 101 RSTR, 29 REJ, and smaller S1/S2/S3 counts among 12,943 rows. DMZ and DB have different state mixes rather than identical outcome proportions.

## Detailed Analysis

### Scope and method

I read only the assigned briefing and files under the assigned data directory. I inspected 19 representative records: two each of core conn/DNS/HTTP/TLS/X.509, one DMZ conn, one DB conn, two additional exact core conn matches, two exact certificate matches, and one each of DMZ TLS, DMZ HTTP and DB TLS. Sampling used first and middle positions, followed by exact UID/FUID pivots; it was not an exhaustive row-level audit. Descriptive aggregates cover conn/DNS/HTTP/TLS families from the three Zeek sensors and X.509 record counts.

The core connection window is `2026-11-02T13:00:00.006178Z` through `18:59:44.793219Z`; other sensor windows are similar. I did not infer overnight coverage, require out-of-window initiators or terminators, or use file metadata. I did not inspect IDS, firewall, proxy-native or endpoint records and cannot claim their collection contracts were verified. Sensor observations may overlap, so per-sensor counts must not be summed as unique enterprise activity.

### Exact cross-source pivot 1: DNS and UDP connection

`zeek-core/dns.json:1` and `conn.json:1` match the exact UID and four-tuple described above. `orig_bytes=41`, `resp_bytes=57`, `orig_ip_bytes=69` and `resp_ip_bytes=85` give 28 bytes of UDP/IPv4 overhead per packet. `history=Dd`, `conn_state=SF`, one packet per side, and matching 469-microsecond RTT/duration are internally coherent for an answered local DNS request. This verifies one transaction, not all DNS behavior; a DNS lookup before a later TCP connection is not mandatory when caches or literal IPs are involved.

### Exact cross-source pivot 2: TLS, connection and certificate chain

`zeek-core/conn.json:7171` starts UID `CfXsGkkuG9lcJw887K` at `16:00:00.175663Z`, with `duration=14.185937`, `conn_state=SF`, `orig_bytes=762`, and `resp_bytes=4082`. `ssl.json:207` timestamps its TLS observation at `16:00:00.230940Z`, approximately 55 ms after transport start and within its interval. It reports TLS 1.2, `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`, successful establishment, no resumption, and SNI `FILE-LNX-01.meridianhcs.local`.

Its leaf FUID `FQKBEGjxMFg4aE9tahU` is `x509.json:127` at `16:00:00.238519Z`; the subject is `CN=FILE-LNX-01.meridianhcs.local`, SAN contains that hostname case-insensitively, and `basic_constraints.ca=false`. Issuer `Meridianhcs Enterprise Issuing CA` matches the subject of the second FUID, `FAg1hiFlqkGBwA3VphH`, at `x509.json:128`; that row has `basic_constraints.ca=true`. Both validity intervals include the observed date. The certificate timestamps are within the transport interval; their slight offset from the TLS row does not prove an ordering fault because these sources record different protocol/file observation milestones. Cryptographic signatures and wire-level handshake sequence were not verified.

### Additional HTTP transport check

Core HTTP line 1, UID `CCNiAm1f7JPR2ix29e`, records `CONNECT preview.redd.it:443` from `10.10.1.41:62106` to `10.10.3.20:8080` at `13:00:08.815497Z`, returning `200 Connection Established`. Exact connection line 10 starts at `13:00:08.687071Z`, lasts `2.967407` seconds, uses the same tuple and `service=http`, and carries 2,065 originator/21,059 responder bytes. The HTTP timestamp is about 128 ms after TCP start, within its interval. Zero CONNECT HTTP body lengths alongside nonzero tunnel connection bytes are plausible and are not contradictory.

### Protocol, TLS and temporal texture

Counts are core 12,943 connections/3,265 DNS/2,520 HTTP/413 TLS; DMZ 10,263/1,165/2,776/3,038; DB 438/48/22/19. Core ports are led by DNS 3,272, Kerberos 2,607, proxy 8080 2,406 and LDAP 1,136; DB has 255/438 connections to 3306. These differing sensor distributions are compatible with observation paths around domain infrastructure, a proxy path and a database segment. Host roles remain inferences from traffic and visible names.

DMZ TLS is predominantly TLS 1.3 (2,125/3,038), with 909 TLS 1.2 and four records without a negotiated version; core is 214 TLS 1.3 and 199 TLS 1.2. The sampled DMZ resumed connection `CcdOSPPMtW0RXrQDec` at `15:40:00.675304Z` runs from apparent proxy `10.10.3.20` to `199.232.64.133:443` with SNI `registry.npmjs.org`, TLS 1.2 and a GCM cipher. No claim about present-day DNS ownership of that IP was made.

Core hourly connection counts for UTC hours 13–18 are 1,829, 3,443, 1,898, 1,769, 2,176 and 1,828; DMZ counts are 1,515, 2,916, 1,496, 1,534, 1,401 and 1,401. The 14:00 increase shows unequal load rather than perfectly smooth activity, but hourly aggregates cannot establish user-level burstiness or long-term realism. Common successful TCP histories dominate, as expected; their repetition alone is not an authenticity indicator. I did not infer a defect from complete joins, the six-hour window, domain sanitization, or the apparent narratability of activity.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| weak_signal | Zeek TLS | DB: 11/19 TLS rows use an older CBC cipher; 19/19 are TLS 1.2; core CBC 40/413 | Negligible: plausible legacy internal service/client behavior; insufficient to support a synthetic verdict |
| No demonstrated high-impact indicator | Inspected Zeek conn/DNS/HTTP/TLS/X.509 | 19 inspected records, exact identity pivots and limited descriptive aggregates | Keeps score in the mostly realistic range; the bounded sample cannot prove real origin |

## Realism Score by Category

- **Field format accuracy:** 9 — Inspected native-looking Zeek fields, types, byte accounting and certificate roles are coherent.
- **Temporal patterns:** 8 — Exact pivots stay within transport intervals and hourly loads vary; the short window limits inference.
- **Cross-source correlation:** 9 — Exact DNS/conn and TLS/conn/X.509 joins agree, with a further HTTP/conn check; only sampled joins were verified.
- **Behavioral realism:** 8 — Proxy tunneling, DNS failures, infrastructure ports and diverse connection outcomes are plausible.
- **Environmental consistency:** 8 — Sensor-specific traffic distributions are credible; apparent legacy internal TLS is possible and observation-path details remain unknown.

## Recommendations

- If this were synthetic, preserve the observed separation between CONNECT transaction body lengths and tunnel traffic, exact tuple/UID continuity, and TLS 1.3 certificate opacity; these inspected relationships already appear realistic.
- If this were synthetic, retain the DB CBC/TLS 1.2 concentration only when it reflects a deliberately modeled legacy service or client policy, rather than selecting that cipher independently from a generic pool. The visible sample motivates a configuration check, not a demonstrated correction.
- No additional concrete repair is supported by this bounded review. Packet-level validation or a broader time window could strengthen an authenticity determination, but their absence is not itself a defect in this collection.
