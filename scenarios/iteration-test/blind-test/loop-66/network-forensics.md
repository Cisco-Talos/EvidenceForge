# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 87
**Synthetic-Confidence Score:** 76

## Executive Summary

The network telemetry is realistic in many respects, including proxy routing, DNS diversity, TLS certificate consistency, and transport-to-application references. A repeated source-native contradiction nevertheless makes synthetic data the more likely explanation: connections identified as confirmed MySQL contain client payload but no server payload, despite showing the initial TCP handshake and no capture gap. This is a localized protocol-semantic defect, rather than a general failure of timing or source coverage.

## Evidence For Synthetic

- [hard_contradiction] **Confirmed MySQL without any server greeting.** `zeek-db/conn.json:4` at `2026-11-02T13:06:54.616676Z`, UID `C64tjS3TXJFhGhEeIe`, reports `10.10.3.10:33317 -> 10.10.4.10:3306`, `service="mysql"`, `orig_bytes=2506`, `resp_bytes=0`, `history="ShADaR"`, and `missed_bytes=0`. The responder supplied only two packets/112 IP bytes, with no responder data marker. MySQL's initial server greeting is required before its client handshake response; the native Zeek analyzer also requires that server-side protocol version before confirming the protocol. The same logical flow appears in `zeek-dmz/conn.json:104`, so this is not an isolated observer losing a greeting. Thirteen no-gap examples repeat this contradiction across the slice; three additional zero-server-payload MySQL connections have reported content gaps and are excluded from the strongest count.
- [weak_signal] **Mobile browser identity dominates a host with direct Mac ownership evidence.** Of 345 HTTP records from `10.10.1.41` in `zeek-core/http.json`, 248 have an iPhone/iOS 17.2 user agent. For example, line 6 at `ts=1793624656.407385` uses source port 62514 and the iPhone agent for a Slack CONNECT. That exact tuple appears in `MAC-MROSS-01.meridianhcs.local/ecar.json:2` as an outbound FLOW from `MAC-MROSS-01`; `zeek-core/dhcp.json:1` also associates that address with `MAC-MROSS-01`. Browser emulation, a local relay, or deliberate user-agent overrides can explain this, so it receives little weight and is not an impossible-platform finding.

## Evidence For Real

- Protocol records have coherent references and timestamps: all 12,436 DNS/HTTP/SSL rows across the three sensors match a same-sensor connection UID and four-tuple, and their timestamps fall within the corresponding connection interval. Complete matching is a positive consistency property, not evidence of synthetic origin.
- The DNS mix is substantially richer than a small pool of successful A queries. Core DNS includes 2,298 A, 258 AAAA, 258 TXT, 135 PTR, 103 SRV, seven NS, four SOA and three MX records; it includes 216 NXDOMAIN, 15 SERVFAIL and three REFUSED responses. `zeek-core/dns.json:31` and `:206` provide concrete unsuccessful-query examples.
- TLS metadata distinguishes full and resumed TLS 1.2 handshakes and TLS 1.3 visibility. Certificate fingerprints retain consistent metadata and observed file sizes, linked chain issuer/subject names agree, and inspected cipher authentication types match the leaf key type.
- Service durations vary appropriately. The first database-sensor SSH connection lasts 3,619.379733 seconds, while successful database-sensor port-8080 connections have a median duration of 2.349388 seconds. Core RDP includes substantial sessions, such as `zeek-core/conn.json:287`, lasting 1,222.248611 seconds with much more responder than originator payload.
- Proxy errors and failed TLS establishment are visible alongside successes. `zeek-core/http.json:62` records a 502 with a 1,079-byte error body; `zeek-dmz/ssl.json:78` records an unestablished TLS exchange. This is not exclusively success-only telemetry.

## Detailed Analysis

### Scope and method

I examined only the supplied neutral briefing and data directory, using system Python from `/private/tmp`. I parsed all JSON records in the three Zeek sensor directories and inspected the supplied proxy, firewall, IDS and selected endpoint ownership records. I did not access repository code, scenarios, project memory, prior assessments or other reviewers' reports. External reference checks used only direct official Zeek and MySQL documentation/upstream source URLs.

The connection slice spans approximately `2026-11-02T13:00:01.771490Z` through `18:59:48.272437Z`. The sensors contain 12,146 core, 9,708 DMZ and 416 database connection rows. These are observer counts, not 22,270 distinct network sessions: shared flows occur at multiple observation points with different Zeek UIDs.

| Sensor | Connections | DNS | HTTP | SSL | X.509 | Files |
|---|---:|---:|---:|---:|---:|---:|
| Core | 12,146 | 3,066 | 2,373 | 372 | 217 | 677 |
| DMZ | 9,708 | 1,071 | 2,608 | 2,876 | 1,184 | 1,768 |
| Database | 416 | 44 | 13 | 13 | 20 | 22 |

### Transport states and the MySQL contradiction

The state distribution is not uniformly successful. Core has 9,690 SF, 1,698 S0, 418 OTH, 167 RSTO, 85 RSTR and 36 REJ rows, with smaller S1/S2/S3 populations. DMZ has 6,785 SF and 2,371 S0 rows. These totals include UDP and ICMP; they should not all be interpreted as TCP establishment outcomes. TCP S0 rows commonly have SYN-only history and zero responder packets; rejected flows use histories such as `Sr`. I found no same-sensor overlapping TCP connections using the same ordered four-tuple, no application record predating its matching connection, and no successful TCP SF row missing both-direction FIN history.

The material exception is the MySQL family. In native Zeek, `service` describes confirmed protocols, rather than merely the conventional name of a destination port. MySQL starts with a server handshake and then a client handshake response. Zeek initializes the MySQL protocol version to zero, learns it from the server initial handshake, and confirms the analyzer when parsing the corresponding versioned client response. [Zeek connection field reference](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html), [MySQL handshake specification](https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_v10.html), [Zeek MySQL protocol parser](https://raw.githubusercontent.com/zeek/zeek/master/src/analyzer/protocol/mysql/mysql-protocol.pac), [Zeek MySQL confirmation implementation](https://raw.githubusercontent.com/zeek/zeek/master/src/analyzer/protocol/mysql/mysql-analyzer.pac).

The example at database line 4 cannot satisfy that interpretation: the initial `S` and `h` are visible, but `resp_bytes=0` and the absence of lowercase `d` say the server never sent payload. It is not a missing pre-window greeting, because the same connection's opening handshake is visible inside the window. `missed_bytes=0`, plus the matching DMZ observation, weakens a loss-based explanation.

The following database-sensor line numbers reproduce the no-gap finding: **4, 24, 80, 90, 150, 159, 163, 169, 245, 266, 305, 347 and 397**. All identify MySQL from `10.10.3.10` to `10.10.4.10`, with positive client payload, zero server payload, `ShADaR`, and zero missed bytes. For example, line 24 at `13:25:58.459989Z`, UID `Cgv8zd8ypwxzAb7O2U`, reports 1,392 client bytes and zero server bytes. There are 260 MySQL-labeled rows in each of the database and DMZ connection files; the 16 zero-server-payload observations at each sensor represent the same logical flow population and must not be counted twice.

Custom port-based service enrichment could explain the label, but no supplied metadata establishes that departure from the visible Zeek field semantics. The repeated contradiction is the principal reason for the verdict. I do not count the duplicated observation as a second independent defect.

### DNS semantics and timing

I checked DNS records against their same-sensor connection UID, tuple, start time and duration. All 4,181 DNS records passed those interval and tuple checks. Core response times range from 82 microseconds to 2.231263 seconds; database DNS ranges from 0.399 to 330.688 milliseconds. Authoritative internal names have stable per-record TTLs: for example, all 160 authoritative core answers from resolver `10.10.2.11` for `DC-01.meridianhcs.local` returning `10.10.2.10` use TTL 300.

A useful visible resolution sequence is database DNS line 1 at `13:09:41.123643Z`, resolving `FILE-LNX-01.meridianhcs.local` to `10.10.2.21`, followed by SSL line 1 at `13:09:42.915641Z` with that hostname as SNI. PTR line 2 supplies the same internal identity. These correlations support plausible name/address ownership.

The TXT population includes concentrated high-entropy queries from `10.10.2.30` and ordinary SPF/DKIM/DMARC-style answers. I validated rendered `TXT N` string lengths, including multi-string answers, and found no mismatch. Neither unusual DNS names nor external name-to-address mappings are authenticity evidence here because the briefing permits sanitization.

### TLS, certificates and files

Core SSL has 195 TLS 1.3 and 175 TLS 1.2 records, with two lacking negotiated versions; DMZ has 1,857 TLS 1.3 and 1,017 TLS 1.2 records, with two lacking versions. The 13 database SSL records are TLS 1.2. Modern AEAD suites dominate; smaller TLS 1.2 CBC populations are possible for older services and do not themselves demonstrate a defect.

No examined TLS leaf used an RSA key with an ECDHE-ECDSA authentication suite, or an EC key with an ECDHE-RSA suite. Repeated certificate fingerprints had consistent certificate metadata and observed file sizes; available chain links agreed on issuer and parent subject, and certificates were within their logged validity intervals. Full TLS 1.2 handshakes have certificate evidence where the certificate is actually observed, while resumed connections such as `zeek-db/ssl.json:2` use `CsiI` without a newly logged chain. I did not require passive TLS 1.3 certificate visibility.

Across files logs, no referenced file timestamp fell outside its matching connection interval. Summed observed file bytes did not exceed the corresponding connection-direction payload, and reported file missing bytes did not exceed the matching connection's missed-byte count. These checks are meaningful protections against superficial UID matching that hides inconsistent byte accounting.

### Proxy paths, host ownership and traffic texture

The proxy at `10.10.3.20:8080` explains the high HTTP CONNECT population; it would be misleading to equate every HTTP row with cleartext web browsing. For example, `zeek-dmz/http.json:1` shows the client control connection to the proxy, while `zeek-dmz/ssl.json:1` shows the proxy's separate outbound TLS connection to the requested host. `PROXY-01.meridianhcs.local/proxy_access.log:1` separates CONNECT control bytes from tunnel bytes and duration.

The database view is dominated by port 3306 (272 connection rows), whereas core exposes DNS, Kerberos, LDAP and SMB, and DMZ exposes extensive proxy/TLS activity. These differences are plausible for the apparent topology. Traffic is uneven within the slice: core hourly connection counts are 1,609, 3,282, 1,768, 1,589, 2,062 and 1,836 for hours 13–18 UTC. I cannot infer overnight or weekend coverage from this six-hour Monday window and assign no penalty for their absence.

The Mac/iPhone user-agent mismatch is a bounded identity concern, not a claim that a network sensor is a native Mac collector. DHCP and endpoint FLOW evidence establish the host association for the cited tuple; user agents remain application-controlled. This concern is much weaker than the MySQL contradiction.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `hard_contradiction` | Zeek MySQL connection semantics | 13 no-gap logical flows, each observed at database and DMZ; three additional gapped examples excluded from strongest count | High: native confirmed-protocol labels conflict with the complete visible absence of required server payload. |
| `weak_signal` | HTTP user agent, DHCP and endpoint FLOW ownership | 248/345 core HTTP rows from one Mac-associated address advertise iPhone | Low: persistent mismatch is unusual, but local relaying or user-agent overrides remain plausible. |

The score is below the highest band because the dominant defect is confined to one protocol family and undocumented service enrichment remains an alternative explanation. The broad positive checks prevent treating this as dataset-wide incoherence.

## Realism Score by Category

- **Field format accuracy:** 8 — JSON types, protocol fields, TXT lengths and byte accounting are convincing; confirmed MySQL labeling has a substantive semantic defect.
- **Temporal patterns:** 9 — Uneven activity, variable service durations and consistent same-sensor application intervals; no demonstrated impossible visible ordering.
- **Cross-source correlation:** 8 — Strong UID, tuple, certificate and file consistency, but multiple sensors reproduce the same MySQL inconsistency.
- **Behavioral realism:** 7 — Credible service mix, failures and proxy behavior; the repeated MySQL exchange shape undermines protocol realism.
- **Environmental consistency:** 8 — Sensor-specific traffic fits the apparent topology; the Mac-associated mobile-agent population is a minor unresolved concern.

## Recommendations

- If this were synthetic, construct failed MySQL exchanges according to the protocol: preserve the server greeting when identifying a parsed MySQL handshake, or leave `service` unconfirmed for a client-only payload exchange. Derive history, direction bytes, packet counts and identification together. Apply this to all 13 no-gap examples, not just the first record.
- If MySQL labeling intentionally represents port-based enrichment, identify that collection transformation explicitly rather than presenting the value with native Zeek confirmed-service semantics.
- If this were synthetic, tie browser identity to the actual local client application on `MAC-MROSS-01`, or explicitly model any mobile relay/emulation responsible for the 248 iPhone-agent records. Do not infer browser identity solely from the human user's device interests.
- Preserve the current separation of proxy control and tunnel traffic, stable certificate identity, varied DNS outcomes, and coherent file/connection byte accounting while correcting the protocol-specific defect.
