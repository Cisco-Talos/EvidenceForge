# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 86
**Synthetic-Confidence Score:** 68

## Executive Summary

The Zeek data is substantially production-like: protocol records fit their connection intervals, transport accounting is plausible, and TLS certificates, DNS answers, proxy paths, and service distributions largely agree. The principal evidence for synthesis is a repeated ASA rendering error: outbound endpoint ordering and TCP reset-side labels use originator/responder semantics rather than the source-native ASA conventions. This is a bounded but systematic firewall-family defect, not a claim that the entire network dataset is unrealistic.

## Evidence For Synthetic

- [schema_or_format] Outbound ASA connection messages systematically place the initiating local endpoint after `for` and the foreign endpoint after `to`. In `fw-perimeter/cisco_asa.log:3`, connection `1681558` reads `Built outbound TCP ... for dmz:10.10.3.20/36424 (203.14.220.1/5935) to outside:34.104.142.28/443 ...`. Native ASA outbound connection messages put the foreign endpoint first and the local initiating endpoint second; the initiation direction comes from `outbound`. The same local-first construction occurs in all 4,528 outbound TCP build messages and all seven outbound UDP build messages. This is characteristic of a generic source/destination template being inserted into ASA text.
- [contract_gap] ASA reset reasons disagree with Zeek reset direction on outbound flows. `fw-perimeter/cisco_asa.log:134-135` builds outbound connection `1681607` from `10.10.3.20:34199` to `52.84.148.34:443`, then reports `TCP Reset-O`. The matching `zeek-dmz/conn.json:56`, UID `CapgpoaDasdvOO1ipgT`, has `conn_state=RSTO` and `history=ShAR`: the local originator sent the reset. ASA's `Reset-O` means the outside side, whereas this flow requires the inside-side reset reason. Conversely, firewall lines 652-653 report `TCP Reset-I` for outbound connection `1681796` to `23.72.50.168:443`; `zeek-dmz/conn.json:276`, UID `CTmpxWI45lpinVyoV4`, has `RSTR` and `ShADadrg`, identifying the outside responder as reset sender. Among unambiguous single-tuple Zeek matches, 41 outbound DMZ-to-outside `RSTO` flows use `Reset-O`, and 19 `RSTR` flows use `Reset-I`. The repeated inversion strongly suggests that Zeek's O/R distinction was translated into ASA I/O labels incorrectly.

## Evidence For Real

- All 4,313 DNS, 4,610 HTTP, and 3,142 SSL rows have an existing same-sensor connection UID and matching four-tuple. Their timestamps fall within their connection intervals; additional checks on SMB and SMTP records also found no interval or tuple contradictions. This is evidence of coherent underlying observations, not a synthetic indicator based on completeness.
- The connection mix contains unsuccessful and partial observations rather than only successful sessions. Across 22,148 sensor observations there are 16,919 `SF`, 4,507 `S0`, 310 `RSTO`, 216 `RSTR`, 60 `REJ`, and smaller `OTH`, `S1`, `S2`, and `S3` populations. Duplicate observation paths mean these are sensor-row counts, not distinct physical-flow counts.
- TCP packet and byte accounting passes basic physical checks: IP bytes accommodate payload plus minimum headers, visible data history has corresponding nonzero payload, `SF` TCP histories contain both FIN directions, and gap histories carry nonzero `missed_bytes`. For example, `zeek-db/conn.json:1` presents a short one-way-payload syslog connection with zero responder payload and `ShADaR`, consistently reflecting the final originator reset.
- DNS includes A/AAAA/PTR/SRV/MX/NS/SOA/TXT queries, NXDOMAIN, SERVFAIL and REFUSED responses, suffix-search-like names, and a slow-response tail. `zeek-core/dns.json:58` contains NXDOMAIN for `wpad.local`; `zeek-dmz/dns.json:110` contains a 2.235809-second response for `settings-win.data.microsoft.com` rather than a uniformly tiny RTT.
- TLS behavior respects passive visibility: TLS 1.3 generally has `ssl_history=Cs` without a plaintext certificate chain, while full TLS 1.2 handshakes carry chain references and resumed TLS 1.2 sessions omit them. Certificate fingerprints retain consistent certificate metadata, chain issuer/subject links agree, and ECDSA/RSA leaf keys agree with the corresponding TLS 1.2 cipher authentication family.
- Distinct network roles are visible. The database sensor is dominated by MySQL traffic, core includes Kerberos/LDAP/SMB/DHCP, and the DMZ sensor includes proxy egress and inbound web traffic. This is a more plausible distribution than applying the same service mix to every segment.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory. I parsed every JSON record in the three Zeek sensor directories and examined the ASA, Snort, and proxy text logs. Line numbers here are one-based file line numbers. No repository, scenario, provenance file, or other review informed this assessment.

The visible network slice runs approximately 2026-11-02 13:00–19:00 UTC. Counts are 12,314 core, 9,401 DMZ, and 433 database connection rows. I did not penalize absent out-of-window connection initiators or later closures, uncollected event families, sanitized domains, or source matching completeness.

For protocol consistency I joined each DNS/HTTP/SSL row to its same-sensor connection by UID, compared the four-tuple, and checked timestamp bounds. I also checked HTTP request/response payload lower bounds, DNS query/TXT-answer lower bounds, TCP packet/header accounting, reset and FIN histories, certificate-chain references, stable fingerprint metadata, and TLS cipher/key compatibility. These tests found no demonstrated Zeek-native contradiction.

### ASA endpoint semantics and reset-side mismatch

The clearest defects are in the purported native ASA messages. The very first successful external connection is useful because its NAT translation explicitly establishes which side is local:

- Firewall line 2 maps `dmz:10.10.3.20/36424` to `outside:203.14.220.1/5935`.
- Firewall line 3 labels the connection `outbound`, but renders the local endpoint first and the external server second.
- `zeek-dmz/conn.json:2` observes `10.10.3.20:36424` originating to `34.104.142.28:443`.

The apparent direction label is therefore meaningful, not merely an ambiguous pair of same-security interfaces. ASA's outbound text convention requires foreign-first/local-second ordering, unlike this generic initiator-first layout. There are 4,528 outbound TCP builds and seven outbound UDP builds with that construction. Inbound examples such as `fw-perimeter/cisco_asa.log:22716` use an outside client first and a DMZ web server second, which happens to agree with native ordering for inbound traffic.

The reset labels independently expose the same confusion between transport roles and security sides. For connection `1681607`, Zeek's `ShAR` records an uppercase originator reset after the SYN handshake; the initiating endpoint is explicitly the DMZ proxy, yet ASA calls the reason `TCP Reset-O`. For connection `1681796`, Zeek's lowercase `r` records the external server reset, yet ASA says `TCP Reset-I`. The 41-versus-19 repeated correspondence is materially stronger than an isolated discrepancy that might arise from split vantage points or an intervening middlebox.

A collector that deliberately rewrote ASA messages could explain these defects in otherwise real traffic. The supplied files present native ASA syslog text, however, and provide no evidence of such a rewrite. This alternative limits certainty and is why the score is not in the 81–100 band.

### DNS and protocol behavior

There are 4,313 DNS observations: 3,260 A, 397 AAAA, 213 PTR, 120 SRV, 306 TXT, eight MX, six NS and three SOA. There are 379 NXDOMAIN observations, plus SERVFAIL and REFUSED. These counts combine sensor observations, including traffic observed on more than one path.

The core's first DNS row resolves `_ldap._tcp.meridianhcs.local` to two DC SRV records with 300-second TTLs. The database's first DNS row resolves `LOG-MON-01.meridianhcs.local` to `10.10.2.40`; the DMZ's first DNS row resolves the Tableau hostname associated with the first CONNECT path. These are appropriate to the visible service roles.

I tested near-in-time DNS responses against following TCP starts on the same source and answer address. There were 1,099 core, 511 DMZ and 32 database cases with a query starting within two seconds before the TCP start. Four TCP starts precede the end of that nearby DNS response, including DMZ connection lines 1484, 8674 and 9297. I do not score this: a nearby DNS lookup does not prove it supplied the address, and a proxy can have a cached address or concurrent refresh. The data alone does not establish impossible same-request causality.

Most TXT traffic is concentrated late in the window, but 267 of the core's 300 TXT rows originate from one source, `10.10.2.30`, with encoded-looking subdomains under one domain. This is an activity-specific concentration, not evidence that ordinary enterprise DNS was generated uniformly. I did not score the concentration or the suspicious activity's narratability.

### TLS, HTTP and proxy visibility

Of 3,142 SSL rows, 2,007 identify TLS 1.3, 1,128 TLS 1.2, and seven have no negotiated version. The observed ciphers include AES-GCM, ChaCha20-Poly1305, and an older internal TLS 1.2 CBC population. A mixed internal/public environment can account for that mix.

Core SSL line 1 references a leaf and intermediate for `FILE-LNX-01.meridianhcs.local`; core X.509 line 1 identifies the enterprise-issued RSA leaf. Database SSL line 1 records an unestablished TLS 1.2 handshake and carries no successful-chain fiction. DMZ SSL line 1 records a TLS 1.3 handshake without exposing an encrypted server certificate. These distinctions are plausible.

HTTP record counts should not be read as predominantly cleartext browsing: 3,999 of 4,610 HTTP rows are CONNECT transactions. Proxy log lines 1–2 explicitly distinguish the CONNECT control message from the inspected HTTPS request with the same `tunnel_id=PT-a5e41cdf86225d43`. Later requests can use the same CDN tunnel, and the log names byte scope. I found no demonstrated request/response byte lower-bound violation against Zeek connection payload counts.

OCSP issuer-name and issuer-key hashes remain stable for certificates attributed to the same issuer; I did not find random per-connection issuer identities. Certificate-chain subject/issuer links and repeated-fingerprint metadata were consistent across all examined certificate rows.

### Timing, transport and collection limits

Core/DMZ HTTP and SSL volumes vary across the six hours rather than forming a flat per-hour count. Database connection durations vary, SSH includes long-lived sessions, and failed scans contribute a substantial SYN-only population. The six-hour daytime slice cannot establish overnight or weekly behavior, so I make no judgment about missing overnight infrastructure activity.

Different sensor UIDs and modest timestamp differences for the same tuple are expected for distinct observers. Partial file extraction and missed-byte history are also present. I did not treat these as contradictions or demand identical packet counts across sensor paths.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| schema_or_format | ASA TCP/UDP build messages | All 4,528 outbound TCP and seven outbound UDP builds | Repeated initiator-first endpoint layout contradicts native outbound ASA message convention; suggests source rendering from a generic flow template. |
| contract_gap | ASA versus Zeek reset evidence | 41 outbound DMZ/external RSTO and 19 RSTR flows with unambiguous tuple matches | ASA reset-side labels consistently follow the wrong semantic axis; a concrete source-native correlation defect. |

These are related defects in one source family, not independent failures across all telemetry. Strong Zeek coherence and the possibility of collector rewriting keep the synthetic-confidence score moderate rather than extreme.

## Realism Score by Category

- **Field format accuracy:** 7 — Zeek fields and protocol shapes are strong, but ASA outbound endpoint and reset-side semantics are wrong.
- **Temporal patterns:** 9 — Varied timings and durations, with no demonstrated impossible protocol-within-connection ordering.
- **Cross-source correlation:** 7 — UID, certificate and proxy relationships are coherent; ASA reset-side evidence contradicts Zeek on repeated outbound flows.
- **Behavioral realism:** 9 — Plausible service-specific traffic, failures, DNS diversity and long-lived administration sessions.
- **Environmental consistency:** 9 — Distinct core, DMZ and database service distributions fit the observed hosts and paths.

## Recommendations

- If this were synthetic, render ASA build messages using the native foreign/local endpoint conventions for each direction, including mapped addresses, rather than a universal source/destination sequence.
- If this were synthetic, derive ASA `TCP Reset-I`/`TCP Reset-O` from the reset sender's security side. Keep Zeek originator/responder reset state separate from ASA inside/outside terminology, and validate outbound and inbound examples against the same canonical reset event.
- If actual collection software intentionally rewrites ASA text, identify that transformation in the collection description or emit a clearly normalized format. This would distinguish a normalization artifact from a faulty native-source reconstruction.
