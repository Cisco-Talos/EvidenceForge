# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 64
**Synthetic-Confidence Score:** 29

## Executive Summary

The network evidence is mostly production-like: protocol records agree with their transport tuples, traffic includes successful and unsuccessful states, and DNS, certificate, transfer-size, and SSH timing relationships survive targeted checks. I found weak concerns around unusually short TLS connection lifetimes and one orphaned SMB mapping, but no demonstrated impossible network relationship. The Real assessment is provisional; internally coherent synthetic telemetry could also pass these checks.

## Evidence For Synthetic

- [weak_signal] **Short TLS connection lifetimes across a broad application population.** In `zeek-dmz/conn.json`, the 3,234 connections identified with `service="ssl"` on destination port 443 have a median duration of 2.415 seconds, a 90th percentile of 6.586 seconds, and a maximum of 170.127 seconds; only 12 exceed one minute. `zeek-dmz/ssl.json` contains 476 distinct `server_name` values, including `teams.microsoft.com` on 80 rows. This is compatible with a workload dominated by short requests, but provides little long-lived TLS texture across a six-hour view. Proxy policy, application behavior, and visibility can explain it, so this receives limited weight and is not a protocol contradiction.
- [weak_signal] **One SMB mapping lacks its same-sensor connection row.** `zeek-core/smb_mapping.json` records UID `C5PgTblRidxF4DQCi8` at `2026-11-02T17:35:24.871469Z`, tuple `10.10.1.22:44244 → 10.10.2.20:445`, share `\\FILE-SRV-01\ClinicalExports`; that UID is absent from `zeek-core/conn.json`. The other 144 mapping rows match connections. A row-level export/filtering loss is a credible explanation; this is a minor reference-integrity concern, not evidence of impossible activity or a general coverage deficiency.

## Evidence For Real

- **Transport accounting is internally credible.** Across all 23,014 connection rows, I found no directional IP-byte count smaller than the corresponding payload count. For TCP/UDP rows with zero `missed_bytes`, none violated the conservative minimum of 40 TCP/IP or 28 UDP/IP header bytes per reported packet. Payload and packet counts were also compatible with the basic visible TCP flags checked.
- **Protocol-to-transport relationships hold.** Every DNS, HTTP, SSL, SMTP, and SMB-file UID checked resolves to its same-sensor connection with the same endpoint tuple. Those protocol timestamps were not earlier than connection start by more than 1 ms or later than connection end by more than 100 ms. Aggregated HTTP request and response bodies fit their respective connection payload totals.
- **DNS has substantial operational variety.** Core DNS includes 2,396 A, 294 AAAA, 154 PTR, 106 SRV, 262 TXT, nine NS, five MX, and three SOA records, with 226 NXDOMAIN, 16 SERVFAIL, and five REFUSED responses. `isatap.meridianhcs.local` returns NXDOMAIN at `13:02:40.398372Z`; SRV answers identify domain controllers; resolver RTTs and TTLs vary.
- **TLS relationships are plausible rather than merely populated.** The DMZ has 2,268 TLS 1.3, 953 TLS 1.2, and five records without a negotiated version. No checked TLS version/cipher combination was inconsistent, exposed certificate chains linked issuer-to-subject correctly, and exposed leaf keys were compatible with their TLS 1.2 authentication cipher. Repeated certificate fingerprints retained consistent metadata.
- **SSH authentication follows transport.** All 58 endpoint records explicitly identified as SSH logins had matching visible connection tuples and login timestamps inside the associated transport interval. For example, `10.10.1.21:49410 → 10.10.4.10:22` opens at `13:08:53.520158Z` in `zeek-core/conn.json`; DB endpoint FLOW appears at `13:08:54.468Z` and login at `13:09:02.975Z` in `DB-PROD-01.meridianhcs.local/ecar.json`.
- **Infrastructure timing and state have credible variety.** Eight DHCP clients generate REQUEST/ACK renewals with varied leases and jitter, while TCP includes resets, rejections, partial sessions, and successful closes. Hourly traffic varies substantially rather than repeating fixed counts.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory, following the separate analyst briefing. The analysis parsed every JSON row in the three Zeek directories, performed whole-file checks on transport/protocol relationships, and used targeted eCAR, Windows Security, proxy, firewall, and IDS records to interpret network activity. I did not inspect scenarios, generation code, ground truth, evaluation outputs, or other study material, and did not use filesystem timestamps or domain resolvability as authenticity evidence.

The principal connection window is approximately `2026-11-02T13:00:01Z` through `18:59:50Z`. Counts below are sensor observations, not unique physical connections; sensors overlap.

| Sensor | Connections | DNS | HTTP | SSL | Files | X.509 |
|---|---:|---:|---:|---:|---:|---:|
| zeek-core | 12,379 | 3,229 | 2,615 | 413 | 705 | 193 |
| zeek-dmz | 10,198 | 1,081 | 2,865 | 3,226 | 1,647 | 999 |
| zeek-db | 437 | 56 | 17 | 29 | 24 | 15 |

Without packet captures, I cannot establish cryptographic validity, exact packet sequence behavior, retransmission correctness, or the actual clock synchronization state. A successful consistency check establishes plausibility, not real provenance.

### Connection states, services, and traffic volume

Core states are SF 9,869, S0 1,688, OTH 442, RSTO 182, RSTR 101, REJ 47, S3 23, S2 16, and S1 11. DMZ states are SF 7,257, S0 2,390, OTH 313, RSTO 120, RSTR 67, REJ 32, S2 eight, S1 seven, and S3 four. The failed and unanswered populations are compatible with the visible scans and unsolicited traffic; their presence alone does not establish either origin.

UDP syslog with `conn_state="S0"`, `history="D"`, and nonzero originator payload is valid one-way UDP behavior. I did not misclassify those records as TCP data sent before a handshake. Histories containing content-gap markers also had nonzero `missed_bytes` in the examined population.

The source mix supports a segmented environment: core contains DNS, Kerberos (`service="krb"`), LDAP, SMB, syslog, SSH, and RDP; the DB sensor contains 250 MySQL flows from `10.10.3.10` to `10.10.4.10`; the DMZ sees proxy and external web traffic. The MySQL population includes 191 SF, 32 RSTO, 19 RSTR, four S2, three OTH, and one S3. This is a reasonably varied transport population rather than uniformly successful application traffic.

Core hourly connection observations are 1,595, 3,142, 1,949, 1,744, 2,042, and 1,907 from 13 through 18 UTC; DMZ counts are 1,397, 2,828, 1,480, 1,573, 1,359, and 1,561. The common 14 UTC increase is compatible with activity visible at both sensors. Six daytime hours cannot establish an overnight or weekly business cycle, so I apply no penalty for those unobserved periods.

No concurrent TCP reuse of an identical directed four-tuple was found using a 100 ms overlap tolerance within each sensor. All successful TCP duration/payload triples were unique within each sensor; this rules out one simple repeated-record texture, but is not proof of production origin.

### DNS behavior

DNS response classes and query families are diverse. Core has 2,982 NOERROR out of 3,229 records; the DMZ has 923 NOERROR, 151 NXDOMAIN, and seven SERVFAIL out of 1,081. Answers and TTL vectors had matching cardinality, and no checked query or simple A/AAAA response required more payload bytes than its corresponding UDP connection reported under conservative DNS wire-length lower bounds.

A concrete resolution-before-TLS example appears in the DB sensor: `10.10.4.10` queries `FILE-LNX-01.meridianhcs.local` at epoch `1793625193.806889`, receives `10.10.2.21` with RTT `0.000575`, and then has SSL evidence to that address at `1793625195.152791` on UID `CoqzJj8pa3bM3ZNHN`. This is a coherent sequence. I did not require a fresh DNS query before every connection, because cached answers and direct address use are legitimate.

Core SRV UID `CbFuuNQBLUYTadDlFt`, epoch `1793624402.853047`, queries `_ldap._tcp.meridianhcs.local` and returns both DC names. Core NXDOMAIN UID `CZhtwD8ZrXcuCLxCgO`, epoch `1793624560.398372`, queries `isatap.meridianhcs.local`. These provide concrete internal discovery and negative-answer texture, rather than relying on assumed mandatory Windows behavior for every host.

### HTTP, explicit proxying, and file accounting

Most HTTP observations represent explicit proxy CONNECT control exchanges, not cleartext browsing: core has 2,394 CONNECT, 218 GET, and three POST records; DMZ has 2,436 CONNECT, 423 GET, and six POST records. It would be misleading to call this an excessive cleartext HTTP-to-HTTPS ratio by counting all CONNECT records as cleartext application sessions.

At the start of the window, `10.10.2.10:56522 → 10.10.3.20:8080` appears in core under UID `C5W8btdFdykKhFktWhS` and DMZ under `Ck8t9TVyt9f39ChX4o4`. Both report 4,845 originator and 2,095 responder payload bytes. The proxy access record for `CONNECT ctldl.windowsupdate.com:443` decomposes these exactly into 384 control plus 4,461 tunnel bytes sent and 197 control plus 1,898 tunnel bytes returned. The DMZ separately observes the proxy's upstream TLS leg to port 443. This is coherent proxy accounting; its completeness is not scored as a synthetic clue.

Persistent HTTP behavior exists. UID `CuUOP5MqF21A0spKqK` in core has `/blog` at `13:00:46.744441Z` and `/assets/img/content/70d51605.jpg` at `13:00:48.178211Z`, with transaction depths one and two and appropriate content types. Summing bodies across all transactions on every HTTP UID still fits connection totals. Checked file `seen_bytes` also fit their reported transport direction.

### TLS and certificates

The broad TLS mix fits a proxy-heavy modern network with older internal applications. TLS 1.3 dominates the DMZ, while 28 of the DB sensor's 29 SSL records use TLS 1.2. DB TLS 1.2 includes 20 CBC and eight GCM cipher observations; legacy internal software can explain that concentration, so I do not treat it as a native-format defect.

TLS 1.3 rows generally have `ssl_history="Cs"` and do not expose an encrypted server certificate chain. TLS 1.2 exposes chains on appropriate rows, including DB UID `CoqzJj8pa3bM3ZNHN`, which references two certificate-file identifiers. For certificate metadata that was actually visible, leaf validity intervals included the connection timestamp, issuer-to-subject links were consistent, and repeated fingerprints did not change identity fields. These checks do not verify real signatures.

The short lifetime distribution described above remains the principal weak texture concern: a six-hour sample spanning hundreds of SNI values has only 12 SSL-identified port-443 transports longer than one minute. This might reflect short request workloads or connection policies. I therefore do not claim that collaboration, mail, or browser sessions are required to remain open longer, nor that the missing long tail is an impossibility.

### Lateral activity, lifecycle, and clock interpretation

The observed SSH, SMB, and RDP ports include both legitimate-looking use and failed probes. Successful core SSH flows have durations extending into thousands of seconds; the 52-minute example to the DB server is compatible with an intermittently used administrative shell. All 58 explicitly labeled SSH logins checked occur inside matching transports. I did not treat sessions beginning before the slice or ending after it as defective.

A targeted RDP failure initially appears to reverse causality: `FILE-SRV-01` records Event 5156 at `16:05:21.7835617Z`, Event 4625 at `16:05:21.7916972Z`, and normalized failed-login evidence at `16:05:21.851Z` for source port 36817; core connection UID `CX7hArP6PYQriH1Czk` starts at `16:05:21.969002Z`. That is a 118–185 ms difference across collectors, not a demonstrated same-clock impossibility. Endpoint flow permission precedes failed authentication locally, and sensor comparisons independently show material clock offsets.

Specifically, 5,247 close-in-time core/DMZ tuple matches have core-minus-DMZ start offsets between 110.167 and 118.522 ms, median 114.223 ms. The 262 DB/DMZ matches have DB-minus-DMZ offsets between 168.463 and 188.027 ms, median 180.141 ms. These measurements make subsecond raw timestamp reversals unsuitable as hard authenticity claims without calibrated host clocks. I do not score this RDP example as a synthetic indicator.

The lone orphaned SMB mapping is recorded separately as a weak export-integrity issue. Neither it nor an occasional missing companion establishes a self-contradictory collection profile.

### DHCP and alert interpretation

The 60 DHCP rows cover eight MAC addresses and all represent REQUEST/ACK activity. One client, MAC `d4:be:d9:a1:ac:76`, has a 7,200-second lease and renewals around 13:00:31, 13:59:27, 15:02:07, 16:04:22, 17:04:07, and 18:04:21 UTC. Another has a 3,600-second lease and approximately half-hour renewals with jitter. These are compatible with renewal activity; absence of an initial DISCOVER within the slice is not a defect.

There are 65 core and 106 perimeter IDS alerts, including DNS, ICMP, and TCP detections. I treated signatures as detector assertions rather than proof of the named behavior, and did not assume an alert on encrypted traffic establishes payload visibility or a real compromise. No score is based on how narratively complete suspicious activity appears.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| weak_signal | Zeek conn/SSL | 3,234 DMZ SSL-identified port-443 connections; 12 exceed 60 seconds | Modest concern about connection-lifetime texture; plausible workload and proxy explanations substantially limit weight. |
| weak_signal | Zeek SMB mapping/conn | One of 145 mappings lacks its same-sensor connection UID | Small integrity concern; compatible with export filtering or row loss and not treated as impossible activity. |
| No demonstrated hard contradiction | Transport/protocol/certificate relationships | Whole-file mechanical checks plus targeted endpoint correlation | Prevents a likely-synthetic score; passing these checks does not prove real provenance. |

## Realism Score by Category

- **Field format accuracy:** 9 — Parseable source-shaped records and credible packet/byte/protocol fields; packet captures and native exporter configurations were unavailable.
- **Temporal patterns:** 8 — Uneven activity, jittered renewals, long SSH sessions, and consistent inter-sensor offsets; TLS lifetime texture is comparatively short.
- **Cross-source correlation:** 9 — Transport tuples, bodies, certificates, proxy accounting, and SSH login ordering agree; one SMB mapping UID is orphaned.
- **Behavioral realism:** 8 — Plausible infrastructure, proxying, scans, negative DNS responses, and mixed transport outcomes, with limited long-lived TLS texture.
- **Environmental consistency:** 9 — Segmented core/DMZ/DB visibility and mixed endpoint platforms are compatible with the observed service paths.

## Recommendations

- If this were synthetic, check the connection-duration model against workloads represented by the 476 DMZ SNI values. Where application and proxy policy warrant persistence, include an appropriate tail of long-lived TLS sessions; retain short request traffic rather than imposing arbitrary minimum durations.
- If this were synthetic, ensure row filtering or observation loss preserves intended SMB mapping/connection relationships, or explicitly represents the collection condition responsible for the unmatched UID `C5PgTblRidxF4DQCi8`.
- For any further authenticity study, preserve available clock-calibration information with the collection. The measured 114 ms and 180 ms sensor offsets materially affect interpretation of raw subsecond cross-source ordering; they should be estimated before promoting such differences to causality defects.
