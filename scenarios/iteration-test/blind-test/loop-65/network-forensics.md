# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 85
**Synthetic-Confidence Score:** 20

## Executive Summary

The network evidence is strongly production-like: transport accounting, application transactions, explicit proxy behavior, and TLS certificate visibility survive extensive consistency checks. I found no demonstrated impossible ordering, source-native contradiction, or strong generator fingerprint; a few unusual service placements are explainable and cannot establish provenance. The score describes the observed realism, while the inconclusive verdict acknowledges that well-constructed synthetic telemetry can satisfy these same contracts.

## Evidence For Synthetic

- [weak_signal] Some internal application placement deserves scrutiny. `zeek-db/ssl.json:1` shows `10.10.4.10` connecting to `WS-LNGUYEN-01.meridianhcs.local` on TCP/443 with `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256`; `zeek-db/http.json:4` shows the same origin requesting `WS-SMARTINEZ-01.meridianhcs.local:8530` using Wget and receiving HTTP 304. These are unusual workstation-facing services for an origin in the database sensor's scope, but workstation names do not prove exclusive roles, and management or laboratory services can explain both. This is a minor plausibility question, not a protocol contradiction or sufficient evidence for a synthetic verdict.
- No high-impact synthetic indicator was demonstrated. In particular, complete UID/FUID matching, clean correlation, domain naming, visible-window boundaries, and absent source families were not scored as synthetic evidence.

## Evidence For Real

- Protocol and state diversity is substantial. `zeek-core/conn.json` contains 12,286 records with nine connection states, including 155 RSTO, 113 RSTR, 43 REJ, and partially observed states; `zeek-dmz/conn.json` contains 9,634 records with 2,396 S0 alongside normal and reset flows. This is not an all-success traffic model.
- DNS has A/AAAA/PTR/SRV/TXT/MX/NS/SOA coverage in the core sensor, with 220 NXDOMAIN, 16 SERVFAIL, and eight REFUSED responses. `zeek-core/dns.json:6` records an authoritative NXDOMAIN for `oldserver.meridianhcs.local`, while line 2 contains LDAP SRV discovery returning both domain controllers.
- Explicit proxy transactions are coherent. `zeek-dmz/http.json:1` observes a CONNECT from `10.10.1.41:50205` to `10.10.3.20:8080` for `sharepoint.com:443`; `zeek-dmz/ssl.json:1` observes the proxy's separate upstream TLS connection. The proxy access log separately labels CONNECT control bytes and tunneled bytes instead of treating encrypted tunnel payload as HTTP response-body content.
- HTTP includes redirects, cache responses, proxy failures, and persistent connections. `zeek-core/http.json:97-98` share UID `CAh14zeELowvGDx3Z4` with transaction depths 2 and 3 and different image transfers; CONNECT does not account for every HTTP record.
- TLS 1.2 and TLS 1.3 have a plausible cipher mix and resumed/non-resumed sessions. Certificate files are associated only with visible TLS 1.2 handshakes, consistent with passive visibility limitations. `zeek-dmz/ssl.json:107` records an incomplete handshake with `established=false` and `ssl_history=C`, rather than falsely attaching a completed TLS session.
- The lateral transports have differentiated lifetimes and byte counts: `zeek-core/conn.json:157` records an 866.058279-second RDP flow with substantially more responder than originator bytes, while line 40 records a 3,445.808706-second SSH flow with much smaller traffic volume.

## Detailed Analysis

### Inputs, scope, and reproducibility

I read the supplied briefing and enumerated files only inside `/private/tmp/log-study-sucvw85x/data`. Analysis used system Python from `/private/tmp`; I did not inspect a scenario, project source, roadmap, worklog, previous assessment, or another reviewer's output. The substantive review parsed every JSON row in the three Zeek sensor directories and sampled the supplied proxy, ASA, and IDS text logs. Source line references are one-based physical JSON/text lines. Aggregate counts are sensor-local observations, not deduplicated network sessions.

I also consulted official Zeek documentation and upstream UDP implementation solely to verify protocol-field interpretations. Generic inherited operating instructions were not treated as evidence of the dataset's origin.

### Transport state, accounting, and timing

The three sensors contain 22,405 connection observations: core 12,286; DMZ 9,634; database 485. The core begins at 2026-11-02 13:00:00.864789 UTC and ends at 18:59:43.879477 UTC. This is a six-hour daytime slice; it cannot establish overnight, weekend, or day-of-week realism.

Core traffic comprises 6,744 TCP, 5,142 UDP, and 400 ICMP observations. The DMZ has 8,198 TCP, 1,140 UDP, and 296 ICMP, while the database sensor is dominated by TCP (409 of 485 observations). Its 315 MySQL-labeled flows are consistent with the apparent segment role. Neither raw HTTP-to-TLS counts nor duplicate observations across sensors were interpreted as a direct user browsing ratio: explicit proxy CONNECT transactions occupy HTTP records while the corresponding upstream leg occupies TLS records.

For every connection, payload-byte counts were no greater than the corresponding IP-byte counts. Conservative TCP minimum-header and history/packet-count checks produced no contradiction. All 1,206 observations whose histories contain content-gap markers have positive `missed_bytes`; there is no mismatch between gap history and zero reported gaps. For example, `zeek-core/conn.json:6` has `history=ShADadFfg`, `missed_bytes=41`, and coherent directional packet/IP-byte totals. Zeek documents the distinction between payload, IP bytes, history, and missing content in its [connection field reference](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html).

Some UDP records have `history=D` with zero payload and a single 28-byte IPv4/UDP packet, for example `zeek-dmz/conn.json:9`. I explicitly did **not** classify this as a contradiction: the [upstream UDP implementation](https://raw.githubusercontent.com/zeek/zeek/master/src/packet_analysis/protocol/udp/UDP.cc) sets the originator data-history marker upon a valid UDP packet without requiring positive application payload. This illustrates why an unfamiliar field combination needs verification before affecting the score.

Core hourly connection counts are 1,594, 3,232, 1,801, 1,698, 2,054, and 1,907. The variation is inconsistent with a simple constant-rate stream. It does not prove human behavior, but neither does it provide an overly smooth temporal fingerprint.

### DNS transactions

Across the sensors I parsed 4,284 DNS observations. All UIDs resolve to a same-sensor connection with matching endpoint tuple, and all DNS timestamps lie inside that connection's observed interval. Checks using the minimum DNS question size and conservative response resource-record sizes found no response/query too large to fit its reported transport payload.

Core DNS includes 2,281 A, 269 AAAA, 160 PTR, 103 SRV, 320 TXT, six NS, five MX, and one SOA observations. Empty successful answers occur, which is compatible with NODATA, particularly for AAAA, and was not mistaken for NXDOMAIN. Internal and external authoritative flags differ: the internal A query in `zeek-core/dns.json:1` is authoritative, while `zeek-dmz/dns.json:1` is a recursive external result with `AA=false` and TTL 30.

The first database DNS record resolves the workstation name at `ts=1793624473.015994`; the related TLS observations occur later, at `1793624473.877206` in the core sensor and `1793624474.043392` in the database sensor. This is a specific visible resolution-before-connection example. I did not require a new lookup before every connection because caches and pre-window resolution are legitimate explanations.

Core TXT traffic starts late in the slice and is concentrated on `10.10.2.30` (285 of 320 TXT rows). This is a material behavior an investigator could examine, but an unusual or suspicious DNS workload is not itself an authenticity defect. The traffic was not penalized for being easy to characterize.

### HTTP and explicit proxy behavior

There are 4,885 HTTP observations: core 2,321; DMZ 2,545; database 19. All application UIDs and endpoint tuples match their corresponding local connection record, and every HTTP observation timestamp lies inside the associated flow interval. No individual request or response body exceeds its corresponding connection's directional payload total.

For the first CONNECT, `zeek-dmz/conn.json:1` reports 2,794 originator bytes and 15,872 responder bytes. `PROXY-01.meridianhcs.local/proxy_access.log:1` decomposes these into 387 control plus 2,407 tunnel client bytes and 130 control plus 15,742 tunnel server bytes. Those sums agree exactly; the Zeek CONNECT body lengths remain zero, which is the appropriate distinction between HTTP control and later opaque tunnel traffic. This is a valid correlation, not an authenticity penalty for completeness.

Core has 25 connections with multiple HTTP transactions, including transaction depths up to seven. DMZ observes those same transaction sequences on its relevant path. HTTP status variation includes 301/302 redirects, 304 cache responses, 403/407 denials or proxy authentication responses, and 502/503/504 failures. Thus the dataset does not reduce browsing to independent successful 200 requests.

### TLS, certificates, and file evidence

I parsed 3,141 TLS observations. TLS 1.3 accounts for 1,769 of 2,813 DMZ TLS rows, with TLS 1.2 accounting for 1,042 and two rows lacking a negotiated version. DMZ resumption is present in 982 rows. The database sensor has 20 TLS 1.2 observations, plausible for its narrower internal service mix.

All referenced certificate-chain FUIDs resolve to local X.509 records. For visible leaf certificates, TLS 1.2 RSA/ECDSA cipher authentication agrees with the leaf key type; available SNI values agree with leaf SANs, and handshake timestamps lie inside certificate validity intervals. Repeated fingerprints preserve their certificate fields. File SHA-1 values match the X.509 fingerprints for linked certificates.

All 1,518 SSL-source file rows occur on TLS 1.2 observations; none improperly extracts a plaintext certificate chain from a TLS 1.3 connection. File observation timestamps lie within their associated connection intervals, and individual HTTP/TLS file sizes fit the relevant flow's directional payload. This combination is strong evidence of protocol-aware construction or collection, although it cannot distinguish those two origins.

### Lateral activity and environmental interpretation

The supplied network records support internal SSH, SMB, RDP, Kerberos, LDAP, MySQL, syslog, and DNS activity. Windows-browser origins `10.10.1.31` through `.36` use TCP source ports within 49152-65535 in all 1,669 sampled core-originated TCP observations, rather than indiscriminately inheriting another OS's ephemeral-port range.

The workstation-facing TLS and port 8530 examples are unusual but remain possible. Network labels and directory hostnames alone cannot prove that these hosts lack management, development, or test services. No native macOS endpoint expectation was imposed on network-sensor records merely because a Mac was a participant.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| weak_signal | Zeek TLS/HTTP | Database-segment origin contacting named workstations on 443 and 8530 | Minor role-placement question; explainable by installed services and insufficient for a synthetic verdict. |
| No demonstrated high-impact indicator | Zeek connection, DNS, HTTP, TLS, files/X.509 | Full parsed sensor-local corpus | No impossible visible lifecycle, tuple, timing, body-size, certificate, or transport-accounting finding established. |

## Realism Score by Category

- **Field format accuracy:** 9 — Native-looking JSON structures and internally compatible protocol fields; no demonstrated parser or field contradiction.
- **Temporal patterns:** 9 — Bursty hourly counts, varied flow durations, and application observations inside their flow intervals; only a daytime slice is available.
- **Cross-source correlation:** 10 — Checked local UIDs, tuples, file references, certificate fingerprints, and CONNECT byte decomposition agree without a detected contradiction.
- **Behavioral realism:** 9 — Persistent HTTP, failures, redirects, DNS negatives, resumption, scans, and differentiated lateral transports are present.
- **Environmental consistency:** 8 — Segment roles and OS-specific ports are coherent overall; a few workstation-facing services remain unusual but possible.

## Recommendations

- If this were synthetic, preserve the verified protocol distinctions: CONNECT control versus tunnel bytes, passive TLS 1.3 certificate opacity, multi-transaction HTTP, and source-local UID/FUID integrity.
- If this were synthetic, review the concrete workstation-facing 443/8530 activity against the intended service inventory. Keep it when those hosts intentionally provide such services; otherwise move those connections to the appropriate service hosts. The logs alone do not justify automatically removing it.
- No transport, DNS, TLS, or file-correlation repair is supported by the checks performed. Additional source families or out-of-window lifecycle records should not be added solely to satisfy this assessment.
