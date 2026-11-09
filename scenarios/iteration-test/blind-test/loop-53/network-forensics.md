# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 92
**Synthetic-Confidence Score:** 82

## Executive Summary

The network records are detailed and generally coherent, but a systematic Zeek file-direction error contradicts the same sensor's connection-locality classification in 1,385 records. This broad source-native defect, plus one localized HTTP/history inconsistency, outweighs otherwise strong transport, DNS, TLS, proxy and sensor correlation; the verdict does not depend on the activity being complete or easy to reconstruct.

## Evidence For Synthetic

- [hard_contradiction] **File sender locality is repeatedly assigned to the connection originator instead of the file sender.** In `zeek-dmz/files.json:1`, certificate file `FyZRqx4w0BtN4xuUXr` has `tx_hosts=["142.250.190.110"]`, `is_orig=false`, and `local_orig=true`. Its connection, `zeek-dmz/conn.json:2`, UID `CyfuWzWe7S7ISfAaY3`, explicitly classifies that responder as `local_resp=false`. A responder-sent file must inherit responder locality. There are 1,364 such discrepancies in DMZ files and 21 in core files, spanning TLS certificates and HTTP bodies. This is a source-semantic contradiction, not a complaint about coverage or perfect matching.
- [contract_gap] **A decoded HTTP response lacks responder data in the connection history.** `zeek-dmz/conn.json:7029`, UID `CfGFWEfryq7DWocEk`, at `2026-11-02T16:53:30.566170Z`, reports `history="ShADafF"`, `resp_bytes=75346`, `resp_pkts=55`, `missed_bytes=0`. The same UID has a decoded 75,107-byte HTTP response in `http.json:1666` and a completely seen file in `files.json:1120`. No lowercase `d` is present. This is a localized mismatch between the displayed packet history and decoded response, with qualifications discussed below.

## Evidence For Real

- DNS, HTTP and TLS companions with an available same-sensor connection agree on their four-tuples, and their timestamps lie within the corresponding connection interval. There are no overlapping TCP intervals for an identical directional four-tuple within any sensor.
- TLS observability is handled well: none of 2,055 TLS 1.3 records claims a certificate chain, and none of 1,127 resumed sessions claims a chain. For example, `zeek-dmz/ssl.json:3` is TLS 1.3 with `ssl_history="Cs"` and no certificate fields, while `ssl.json:1` has a full TLS 1.2 certificate chain.
- Certificates retain stable identity: across 1,350 x509 rows and 196 distinct fingerprints, repeated fingerprints have identical certificate attributes after excluding observation time and file ID. Adjacent certificate issuer/subject relationships match, and checked ECDHE_RSA sessions use RSA leaf keys.
- DNS includes realistic infrastructure and failure texture: core has A, AAAA, PTR, SRV, TXT, MX, NS and SOA queries; 213 NXDOMAIN, 21 SERVFAIL and two REFUSED responses coexist with 3,085 NOERROR responses. TTLs include fixed authoritative values and variable cache-like values. Core median RTT is 3.693 ms, compared with 19.742 ms in the DMZ view.
- Session duration varies by service: core SSH median is 1,836.317 seconds and RDP median 2,115.879 seconds, rather than being interchangeable with approximately two-to-four-second HTTP/TLS conversations. Core `conn.json:1101` has a 2,743.584692-second RDP flow to `10.10.2.10:3389`, with a completed transport and substantial bidirectional traffic.
- Proxy tunneling is semantically separated from external TLS. In `PROXY-01.meridianhcs.local/proxy_access.log:1`, the CONNECT control response is distinct from tunnel byte counts. The 4,274/34,835 tunnel bytes match the outbound TLS flow in `zeek-dmz/conn.json:2`; the client-to-proxy flow in `conn.json:1` carries additional CONNECT traffic. This is useful affirmative coherence, not evidence against authenticity.

## Detailed Analysis

### Input provenance and method

I read the supplied neutral briefing at `/private/tmp/log-study-_yn9uggi/network-prompt.md` and inventoried only `/private/tmp/log-study-_yn9uggi/data`. I parsed all JSON records under its three `zeek-*` sensor directories with system `python3` from `/private/tmp`. I also read the supplied ASA, Snort and proxy logs, sampling their native text and correlating the parseable port-bearing Snort alerts with connection tuples. Endpoint file names were visible in the data inventory, but I did not parse endpoint logs or use endpoint implementation assumptions.

No project source, scenario, TODO, worklog, prior assessment, neighboring reviewer report, or task-project public page was accessed. Generic inherited environment instructions were excluded as authenticity evidence. No commands embedded in telemetry were executed. Public queries used actual `domains` filters for `docs.zeek.org` and `cisco.com`; direct upstream reads were restricted to `raw.githubusercontent.com/zeek/zeek/...`. Some Cisco search results included Cisco Community pages, which were not used as authoritative support. One attempted direct historical Zeek v4.2 files-script fetch failed and supplied no evidence.

Line references are one-based physical lines in the supplied files. Counts are sensor observations, not claims about distinct packets or flows across overlapping sensors. No PCAP, sensor version declaration or collector configuration was supplied, so I distinguish a demonstrated internal field contradiction from assumptions about unobserved packets or optional audit sources.

### Observation scope and distribution

The three connection logs contain 22,650 observations: core 12,556, DB 448 and DMZ 9,646. They span approximately 13:00–19:00 UTC on 2 November 2026. The associated logs contain 4,456 DNS rows, 4,736 HTTP rows, 3,219 TLS rows and 2,512 file rows. The DB observation path is dominated by MySQL: 275 of 448 connections have `service=mysql`. Core has substantial Kerberos (2,502), DNS (3,336 connections), LDAP (1,124) and SMB (470) activity. DMZ contains external TLS and proxy traffic, with a larger unanswered-connection component.

Connection state counts include core SF 10,107 and S0 1,709; DB SF 362 and S0 eight; DMZ SF 6,576 and S0 2,525. I did not interpret all S0 records as TCP SYN failures: UDP flows also use that state when no reverse traffic is observed. Nor did I demand NTP, QUIC, mDNS or every platform-specific protocol merely because the environment could support them.

The core hourly counts are 1,767, 3,281, 1,762, 1,918, 2,181 and 1,647; DMZ counts are 1,422, 2,879, 1,335, 1,468, 1,426 and 1,116. These show meaningful volume variation within the visible business window. Six hours cannot establish overnight behavior, weekend behavior or a full business-cycle distribution. The many CONNECT rows also mean the raw HTTP-row count cannot be equated with plaintext web-browsing share.

### Decisive source-native locality defect

In Zeek files metadata, `local_orig` describes where the **file data** originated; `is_orig` determines whether the sender is the transport originator or responder. The upstream implementation selects the appropriate address using `f$is_orig ? cid$orig_h : cid$resp_h`. This is distinct from blindly copying `Conn::Info.local_orig`. [Zeek Files::Info reference](https://docs.zeek.org/en/current/scripts/base/frameworks/files/main.zeek.html), [upstream file-over-connection handler](https://raw.githubusercontent.com/zeek/zeek/master/scripts/base/frameworks/files/main.zeek).

For each single-connection file with a matching connection, I computed:

`expected_file_local_orig = conn.local_orig if file.is_orig else conn.local_resp`

Of 2,510 comparable file observations, 1,385 disagree: core 21/793, DB 0/28 and DMZ 1,364/1,689. The affected sources are SSL 1,150 and HTTP 235. All 2,510 comparable file observations instead equal the connection's `local_orig`, including the cases where the actual sender is explicitly classified as nonlocal by that connection. Two DMZ file rows have no available same-sensor connection and were excluded.

The first DMZ certificate observation is sufficient to reproduce the problem. At `ts=1793624404.846936`, file `FyZRqx4w0BtN4xuUXr` is sent by `142.250.190.110` to `10.10.3.20`, but is marked locally originated. The corresponding connection at `ts=1793624404.811665` explicitly marks `142.250.190.110` nonlocal. The same issue is visible in core `files.json:29`, certificate file `FyrjEUKNNfAL95NIZ86`, tied to `conn.json:198`, UID `C6eUrxXMfeocPeSOz`: sender `74.208.4.160` is a nonlocal SMTP responder while the file locality is true.

This conclusion requires no assumption that public IP space must be outside `Site::local_nets`: the same sensor's connection record supplies its own locality decision. Sanitized domains do not affect this relationship. A custom postprocessor could create such an error in real input too, which is why the verdict is not absolute, but its systematic breadth is the strongest synthetic indicator.

### HTTP/history mismatch and its limits

The HTTP connection at DMZ line 7029 carries `GET /assets/app.js` to `20.205.68.81:80`. Its decoded HTTP row has status 200 and `response_body_len=75107`; file `FGjLj37OytJgUaty8Hw` has `seen_bytes=total_bytes=75107`, no missing bytes, and the same UID. The transport is SF and records 75,346 responder payload bytes, but history `ShADafF` has only responder SYN-ACK, pure ACK and FIN observations.

Zeek history uses lowercase for responder observations and `d` for ordinary data-bearing packets. However, upstream code treats SYN/FIN/RST packets specially, so the absence of `d` is not, by itself, a universal proof of zero payload. I checked that nuance rather than treating the abbreviated field as a literal packet dump. In this case a fully decoded approximately 75 KB HTTP response, 55 responder packets and only one recorded responder FIN make the missing ordinary responder-data indication difficult to reconcile with normal HTTP transport. I assign this a localized contract-gap finding rather than claiming a dataset-wide byte-accounting impossibility. [Zeek connection reference](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html), [upstream TCP history logic](https://raw.githubusercontent.com/zeek/zeek/master/src/packet_analysis/protocol/tcp/TCPSessionAdapter.cc).

### Transport and correlation checks that passed

Across the 15,397 TCP connection observations, SF records retain both FIN directions, RSTO/RSTR histories have the relevant reset direction, and TCP S0 rows do not claim reverse traffic or application payload. Packet/IP byte bounds passed a conservative IPv4 header-overhead check after allowing the recorded missing bytes. Content-gap flags have nonzero missed-byte counts. HTTP request/response body totals and file seen-byte totals did not exceed their matched directional connection payload totals. DNS RTT did not exceed matched flow duration, and DNS query payloads were not shorter than the encoded question's minimum length.

All matched DNS/HTTP/TLS tuples agree, and none of their timestamps falls outside its connection interval at a 1 ms upper tolerance. A missing HTTP UID in core and missing HTTP/TLS UIDs in DMZ occur near `18:59:57Z`, at the end of collection. I do not score these as orphan defects: connections may finish outside the slice and be logged later. Likewise, I do not require every long-lived SSH session to close within the window.

I also rejected an apparent S1/byte-count concern after checking upstream implementation: documentation prose says S1 has no byte counts, but the current connection script populates them whenever connection duration is positive. The supplied S1 rows therefore are not counted as a demonstrated format defect. [Upstream connection population logic](https://raw.githubusercontent.com/zeek/zeek/master/scripts/base/protocols/conn/main.zeek).

### DNS, TLS, firewall and IDS interpretation

Core DNS type counts are A 2,434, TXT 315, AAAA 302, PTR 156, SRV 97, NS seven, MX six and SOA four. The first record is a domain-controller discovery SRV query, while ordinary host A lookups and reverse lookups coexist with failures and a conspicuous high-entropy TXT-query family. For example, `zeek-core/dns.json:2418` queries `66b37b202fa1b61dfa697d94aa.a87.r12.cache.ns1.westbridge-services.cloud`, qtype TXT, with RTT 0.306131 seconds and TTL nine. That is suspicious network behavior, not an authenticity defect by itself. Cache hits and direct-IP traffic mean an absent fresh DNS lookup cannot independently establish broken causality.

TLS 1.2 and 1.3 coexist, with AES-GCM dominant and a smaller ChaCha20 population; older CBC suites occur particularly on internal paths. Certificate linkage is restricted to nonresumed TLS 1.2 observations. That matches the passive-visibility distinction in Zeek's TLS guidance. [Zeek TLS log discussion](https://docs.zeek.org/en/current/reference/logs/ssl.html).

The ASA text has recognizable build/teardown and NAT messages. For the opening external flow, `cisco_asa.log:1,3,7,8` retain the client-to-public translated port relationship and matching connection ID `1681559` through teardown. The format accords with Cisco's documented socket and translation fields. [Cisco ASA connection-message reference](https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/asa-syslog/syslog-messages-302003-to-342008.html).

All 126 port-bearing Snort alerts parsed by my tuple/time check had a connection observation within a one-second boundary tolerance; none of the matched application-specific alerts was supported only by TCP S0 traffic. Seventeen ICMP-format alert lines did not fit that port-bearing parser and were excluded from that test, rather than reported as missing connections.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| hard_contradiction | Zeek files with same-sensor conn metadata | 1,385/2,510 comparable file rows; SSL and HTTP; core and DMZ | Dominant: file sender locality disagrees with the sensor's own classification; systematic originator-copy pattern |
| contract_gap | Zeek HTTP/files/conn | One UID, DMZ conn:7029, http:1666, files:1120 | Secondary: fully decoded 75 KB response without ordinary responder-data history; control-packet nuance limits certainty |

No score was assigned for domain validity, absent optional sources, completeness, investigation narratability, filesystem timestamps, the lack of overnight coverage, or suspicious activity itself. The 82 score reflects a broad demonstrated field-semantic contradiction despite substantial realism elsewhere; 92 verdict confidence expresses confidence in the classification, not the severity of every individual row.

## Realism Score by Category

- **Field format accuracy:** 6 — Strong recognizable formats, undermined by systematic file-locality semantics.
- **Temporal patterns:** 9 — Service-specific durations, irregular hourly volumes and matched protocol timing are plausible within the slice.
- **Cross-source correlation:** 8 — Tuples, payload budgets, TLS references and proxy legs generally align; file locality and one HTTP/history case disagree.
- **Behavioral realism:** 9 — Infrastructure, proxy, database, scanning and long administrative sessions have distinct network shapes.
- **Environmental consistency:** 8 — Sensor roles and traffic mix are plausible; repeated local/nonlocal file classification conflicts with the same environment's connection metadata.

## Recommendations

- If this were synthetic, derive file locality from the actual sending endpoint, using `is_orig` and the matching connection's local-originator/local-responder classification. Verify it on both internal downloads and external-origin files; the visible 1,385 mismatches provide a concrete regression target.
- If this were synthetic, construct connection history and decoded protocol/file evidence from one packet/transport semantic account. Review UID `CfGFWEfryq7DWocEk` so that a decoded 75,107-byte responder body has compatible data/FIN history and packet counts, retaining the real Zeek control-packet exceptions.
- Preserve the already credible TLS visibility boundaries, scoped connection identities, proxy tunnel accounting and service-specific session duration. Those properties survived direct record checks and need no arbitrary additional noise to be credible.
