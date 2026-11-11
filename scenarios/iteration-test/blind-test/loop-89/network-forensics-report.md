# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 68
**Synthetic-Confidence Score:** 24

## Executive Summary

The network evidence is mostly production-like: protocol records preserve connection identities, proxy traffic has coherent DNS/TCP/TLS and byte-accounting relationships, and an examined SSH session agrees with endpoint transport and authentication evidence. I found no demonstrated impossible network relationship; the principal reservation is an unusually absolute single-SYN pattern across unanswered TCP flows, including a small number attributed to ordinary application processes. This is a moderate-confidence authenticity judgment, not proof of provenance.

## Evidence For Synthetic

- [weak_signal] All **3,992 TCP S0 sensor observations** across `zeek-core/conn.json` (1,474), `zeek-dmz/conn.json` (2,512), and `zeek-db/conn.json` (6) contain exactly one originating packet, zero response packets, zero payload bytes, `history="S"`, and no duration. Much of this is explainable scanner traffic: 1,232 matching endpoint FLOW records identify `/usr/bin/nmap`. However, the same one-SYN shape also occurs on 19 matched, process-attributed FLOW records outside that scanner family: seven `/usr/sbin/rsyslogd`, eleven `svchost.exe`, and one `PBIDesktop.exe`. For example, `zeek-db/conn.json` UID `CwJgN8XfQbWukJJuSG` at `2026-11-02T13:07:39.860531Z`, `10.10.4.10:42463 -> 10.10.2.40:514`, matches DB-PROD-01 PID 29341, `rsyslogd -n`, with failure outcome at `13:07:40.285Z`. A total absence of multi-SYN timeout shapes across different application families is mildly suspicious, but collection loss, short application cancellation, and scanner policy remain viable explanations. The counts are sensor observations, with overlapping views, not 3,992 independent connections.

## Evidence For Real

- All **14,171 inspected protocol records** with connection UIDs join within their own sensor to a `conn.json` record with the same four-tuple and timestamps within its recorded interval: 4,631 DNS, 5,409 HTTP, 3,622 SSL, 79 SMTP, 156 SMB mapping, and 274 SMB file records. Alignment is evidence of coherence, not independent proof of authenticity.
- A concrete proxy transaction has consistent accounting rather than merely matching hostnames: the MAC-MROSS-01 connection to proxy `10.10.3.20:8080` carries 2,065/21,059 bytes, exactly equal to the logged CONNECT control bytes plus 1,653/20,830 tunnel bytes. The proxy resolves the CONNECT hostname before opening the corresponding TLS connection.
- DNS includes A, AAAA, PTR, SRV, TXT, MX, NS, and SOA questions; successful, NXDOMAIN, SERVFAIL, and REFUSED responses; empty successful answers; varied TTLs; and RTT tails above two seconds. The internal and DMZ profiles differ plausibly.
- TLS version/cipher pairings are internally compatible. TLS 1.3 rows expose no certificate-chain FUIDs, while visible TLS 1.2 chains resolve to X.509 rows with compatible leaf key types. Repeated fingerprints retain the same examined certificate identity fields.
- SSH transport, target-side FLOW, sshd authentication/PAM messages, and normalized session opening appear in plausible order for the exact source port 54935. The visible session close is compatible with the transport end.
- Packet-accounting checks initially identified 197 directional lower-bound discrepancies; every one occurred on an explicitly gap-marked TCP history. None remained after excluding those gap histories. This prevents incorrectly treating sequence-derived payload estimates as fully observed packet payload.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory and assigned briefing. Analysis used the actual JSON records, grouped by sensor, with exact UID/four-tuple joins, connection interval checks, DNS type/response distributions, TLS-to-certificate relationships, HTTP/file byte bounds, TCP history/packet checks, and representative endpoint/proxy/syslog joins. I did not use names or public DNS resolution as provenance clues.

The supplied sensors contain **24,092 connection observations**: core 12,961, DMZ 10,669, and database 462. These are overlapping sensor views and should not be added as unique network transactions. Connection start timestamps span approximately `2026-11-02T13:00:00Z` through `18:59:32Z`. This six-hour slice supports within-window ordering checks; it does not establish daily or overnight behavior, and I did not penalize absent out-of-window lifecycle records.

### Connection behavior and traffic mix

Core observations comprise 7,155 TCP, 5,385 UDP, and 421 ICMP rows. DMZ comprises 9,057 TCP, 1,292 UDP, and 320 ICMP; database comprises 394 TCP, 47 UDP, and 21 ICMP. State counts differ by vantage point: core has 10,459 SF, 1,702 S0, 170 RSTO, 102 RSTR, and 26 REJ rows; DMZ has 7,510 SF, 2,559 S0, 138 RSTO, 73 RSTR, and 27 REJ; database has 349 SF, six S0, 44 RSTO, 28 RSTR, and two REJ. The all-protocol S0 totals include one-way UDP and must not be interpreted as SYN counts.

The mix is consistent with distinct internal, exposed-service, and database observation paths. Core contains 2,506 port-88 and 1,193 port-389 observations alongside DNS, SMB, proxy, syslog, SSH, and RDP. Database traffic concentrates on `10.10.4.10:3306` (305 of 462 observations). Core starts are not flat by hour: 1,829, 3,429, 1,864, 1,768, 2,196, and 1,875 for hours 13–18 UTC. The 14:00 rise includes a substantial scanning component; its concentration is explainable observed activity rather than a synthetic indicator by itself.

The single-SYN pattern warrants only a small score increase. Of 1,251 endpoint FLOW records with explicit process attribution and a near-time exact-tuple S0 match, 1,232 name nmap. The other 19 are too few, and the capture policy too uncertain, to establish a contradiction. Some sensor rows observe the same underlying attempt.

### DNS behavior and causality

Core DNS contains 2,427 A, 324 AAAA, 315 TXT, 183 PTR, 95 SRV, seven MX, five NS, and four SOA records. It has 3,123 NOERROR, 225 NXDOMAIN, nine SERVFAIL, and three REFUSED responses. DMZ contains 992 A, 149 AAAA, 78 PTR, eight SRV, and five TXT questions, with 147 NXDOMAINs among 1,232 records. Core RTTs range from 16 microseconds to 2.351830 seconds; DMZ reaches 2.352680 seconds. Fast cached responses and longer error/lookup tails coexist.

Concrete examples include core PTR UID `CLjaqS8Xw8d38G9lnw` at `13:09:58.164582Z`, resolving `40.2.10.10.in-addr.arpa` to `LOG-MON-01.meridianhcs.local`, and SRV UID `CjDiL5ET9N7H5kjqFl` at `13:00:03.208604Z`, returning both domain controllers for `_ldap._tcp.meridianhcs.local`. NXDOMAIN questions include `isatap`, `wpad.meridianhcs.local`, and stale internal names. No A/AAAA answer containing a literal IP of the wrong address family was found.

Not every connection needs a newly visible DNS question: caching, literal addressing, resolver vantage point, and pre-window state are valid explanations. I therefore checked positive causal examples rather than counting every unmatched hostname lookup as missing evidence.

### Proxy, HTTP, and TLS cross-source example

For `10.10.1.41:62106 -> 10.10.3.20:8080`, DMZ connection UID `CLFU2scNt0xkZzVVXd` starts at `13:00:08.570923Z`; its HTTP record at `13:00:08.699349Z` requests `CONNECT preview.redd.it:443`. DMZ DNS UID `CcZ4vr57Giq6X4wHQG` starts at `13:00:08.704618Z`, has RTT 0.033401 seconds, and returns `151.101.193.140` and `151.101.129.140`. The response therefore precedes upstream TCP UID `C1c41TiuTd6CDcPjdUI`, `10.10.3.20:56547 -> 151.101.193.140:443`, at `13:00:08.746274Z`. Its SSL row at `13:00:08.770452Z` identifies the matching SNI and TLS 1.3 cipher `TLS_AES_256_GCM_SHA384`.

The proxy access row for the same client, hostname, and second records `cs_bytes=412`, `wire_sc_bytes=229`, `tunnel_cs_bytes=1653`, and `tunnel_sc_bytes=20830`. The client connection totals are precisely 412+1,653=2,065 and 229+20,830=21,059 bytes. HTTP CONNECT body lengths of zero correctly avoid interpreting encrypted tunnel payload as an HTTP response body. HTTP timestamps describe the transaction start, so the presence of a final 200 status on that row does not mean the proxy replied before its DNS lookup.

The core view uses a different UID (`CCNiAm1f7JPR2ix29e`) for the same client tuple and is approximately 116 ms later in this example. Separate sensor UIDs and modest sensor clock/observation differences are not contradictions. Across all sensors, no inspected HTTP body aggregate or directional file-byte aggregate exceeded the associated connection byte count.

DMZ SSL rows comprise 2,250 TLS 1.3, 948 TLS 1.2, and one incomplete negotiation without version. Core has 180 TLS 1.3, 220 TLS 1.2, and one incomplete negotiation; database has 22 TLS 1.2 rows. Modern AEAD suites dominate the external profile, with older CBC use concentrated more heavily in the small internal/database profile. No listed certificate-chain FUID was missing from its sensor's X.509 file; examined RSA/ECDSA leaf keys matched the authentication cipher families. I found no inconsistent serial, subject, issuer, validity interval, key type/length, or SAN values under a repeated fingerprint among 1,356 X.509 rows.

### SSH and endpoint ownership cross-check

DMZ UID `CJ7hNyJ6HuWybewWgl` records `10.10.3.10:54935 -> 10.10.2.30:22` beginning at `15:14:50.419091Z`, with `SF`, duration 13,329.301619 seconds, and 18,290/50,217 payload bytes. Core independently observes the same tuple under UID `C1leLGvcByuUptVvlF` at `15:14:50.532658Z`.

`WEB-EXT-01.../ecar.json` records the outbound FLOW at `15:14:50.688Z`; `APP-INT-01.../ecar.json` records the inbound FLOW at `15:14:52.026Z`. APP-INT-01 syslog PID 2953486 then logs the exact remote source/port at `15:14:55.774435Z`, password acceptance for root at `15:15:02.764845Z`, and PAM session opening at `15:15:02.905577Z`. The normalized USER_SESSION LOGIN follows at `15:15:04.333Z`, session ID 411. PAM closes at `18:57:00Z`, shortly before the DMZ transport's calculated end around `18:57:00.720710Z`. An idle, multi-hour SSH transport can legitimately carry relatively little payload.

As a broader consistency check, 28,167 endpoint FLOW rows had a near-time exact-tuple connection match, all within 30 seconds and with observed offsets between approximately −0.849 and +3.236 seconds. Another 856 endpoint FLOW rows had no supplied sensor tuple match; I did not score this as missing network evidence because the sensor coverage contract is unknown. No matched FLOW explicitly reporting failure joined to an SF connection in the check.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| weak_signal | Zeek TCP connection records and normalized endpoint FLOW | All 3,992 TCP S0 sensor rows are single-SYN; 19 process-attributed FLOW matches outside nmap also share that shape | Small increase only: excessive uniformity is possible, but scanner dominance, cancellation, and observation policy prevent a hard finding |

No demonstrated hard contradiction, required-companion gap, or native schema defect was established by these checks. Complete joins were not scored as suspicious.

## Realism Score by Category

- **Field format accuracy:** 9 — Native-looking protocol fields, compatible TLS suites/keys, and plausible gap-aware packet accounting.
- **Temporal patterns:** 8 — Variable traffic and durations, coherent examined causality; single-SYN timeout texture remains a weak reservation.
- **Cross-source correlation:** 9 — Exact protocol joins, coherent proxy byte conservation, and ordered SSH transport/authentication evidence.
- **Behavioral realism:** 8 — Scanning, infrastructure, browsing, database, error, and long-lived session activity coexist; unsuccessful non-scanner TCP attempts show limited shape diversity.
- **Environmental consistency:** 9 — Sensor profiles and service concentration fit the visible roles without requiring unprovided collectors or traffic families.

## Recommendations

- If this were synthetic, examine unsuccessful ordinary TCP application attempts separately from raw scanning. For families such as the seven process-attributed rsyslog attempts, allow realistic retransmission/timeout shapes when the application and visibility assumptions call for them, instead of applying a single-SYN shape universally.
- If one-packet S0 rows intentionally reflect cancellation, sampling, or a restricted observation policy, preserve that policy coherently across sensor and endpoint evidence. The data does not justify adding retries indiscriminately to scanner traffic.
