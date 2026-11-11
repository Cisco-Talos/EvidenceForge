# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 75
**Synthetic-Confidence Score:** 19

## Executive Summary

The network evidence is production-like, with coherent source-native connection states, diverse DNS outcomes, plausible TLS visibility, and working joins between network, proxy, certificate, and firewall records. I found no demonstrated hard contradiction or important synthetic indicator in this bounded investigation; the Real verdict is an assessment of the visible evidence, not proof of provenance.

## Evidence For Synthetic

- No substantiated important synthetic indicator was identified. In particular, complete joins, a bounded six-hour window, source omissions, sanitized destination names, and the ability to reconstruct activity were not treated as synthetic evidence.
- [weak_signal] Most successful DMZ TLS connections are brief: among 3,195 TCP `service=ssl`, `conn_state=SF` rows, the median duration is 2.570160 seconds, the 90th percentile is 6.487975 seconds, and the maximum is 165.676599 seconds. Short request-oriented traffic behind a proxy can produce this pattern, and the visible long tail prevents interpreting it as a hard duration cap. This observation carries negligible weight in the score.

## Evidence For Real

- The three Zeek sensors collectively contain 24,092 connection observations with meaningful variation in state, service, packet loss, duration, and observation scope. Core contains 10,459 SF, 1,702 S0, 170 RSTO, 102 RSTR, and 26 REJ observations, together with OTH and half-closed connections. State diversity is accompanied by compatible representative histories, not just populated labels.
- All 13,662 DNS, HTTP, and TLS records have a same-sensor connection UID; every checked originator/responder address and port agrees. Their timestamps fall inside the corresponding connection interval with the stated 1 ms early/100 ms late tolerance. This alignment supports coherence; its completeness alone was not scored as evidence of either origin.
- DNS includes A, AAAA, PTR, SRV, TXT, MX, NS, and SOA records, NXDOMAIN, SERVFAIL, REFUSED, and successful responses without answers. Core DNS RTT spans 0.000016–2.351830 seconds, with a 0.004626-second median, rather than a fixed response delay.
- TLS 1.2 and TLS 1.3 have different visible evidence. All 2,430 TLS 1.3 rows across the sensors omit certificate-chain FUIDs; TLS 1.2 provides certificate/file relationships when appropriate. Resumed sessions, incomplete handshakes, RSA/ECDSA certificate compatibility, and valid-at-observation certificate dates were represented coherently in the checked joins.
- A proxy CONNECT's independently reported control and tunnel byte totals exactly reconcile with its Zeek TCP payload totals, while its HTTP response body remains zero. The firewall example also preserves the private tuple, public NAT tuple, connection identifier, and plausible build/teardown chronology.

## Detailed Analysis

### Scope and method

I examined only the assigned data directory and briefing. The review covered all JSON records in the three Zeek sensor directories for bounded aggregate and identity checks, followed by selected raw-record analysis; I also inspected representative proxy, ASA, and Snort lines. It was not an exhaustive application reconstruction or a packet-level verification.

The core connection observation window is 2026-11-02 13:00:00.006178–18:59:32.005975 UTC. DMZ runs 13:00:01.266334–18:59:32.192172 UTC; the database sensor has a narrower first/last observed connection range. These are collection bounds, not evidence that processes or sessions must begin and terminate inside them.

| Sensor | conn | DNS | HTTP | TLS |
|---|---:|---:|---:|---:|
| zeek-core | 12,961 | 3,360 | 2,566 | 401 |
| zeek-dmz | 10,669 | 1,232 | 2,828 | 3,199 |
| zeek-db | 462 | 39 | 15 | 22 |

Sensor observations can describe the same traffic with different sensor-local UIDs; totals are observations, not deduplicated physical connections. For DNS/HTTP/TLS, I checked same-sensor UID existence, the complete address/port tuple, and the timestamp against `ts` plus `duration`. There were zero missing parents, tuple disagreements, or out-of-interval records under the tolerance described above.

### Connection semantics, service mix, and timing

Core has 7,155 TCP, 5,385 UDP, and 421 ICMP observations. Its major services include DNS (3,372), HTTP (2,535), Kerberos (2,506), LDAP (1,163), SMB (460), and TLS (395). The database sensor is dominated by MySQL: 276 recognized MySQL observations among 462 connections. The DMZ has 3,330 TLS and 2,808 HTTP connection observations. Analyzer record counts need not equal service-tagged connection counts because a connection may contain multiple transactions or multiple protocol phases.

Representative reject `zeek-db/conn.json` UID `CeSkMqcrLfCF2U5uXgm` has `conn_state=REJ`, `history=Sr`, no payload, and one packet per direction. Representative reset UID `CUHsyO3nGC5IxBfHJ` has `RSTO`, `ShAR`, and no payload, rather than implausibly carrying an established application exchange. UDP syslog UID `CKXtZNjRpm3SaGWIID` in core has S0, `history=D`, 1,548 originator bytes, and no reply; I did not misinterpret that UDP state as an impossible TCP handshake.

There is a service-dependent duration tail. Core's 45 successful TCP SSH connections have median 2,184.210558 seconds and maximum 13,329.301508 seconds; its 13 successful RDP connections range from 0.211563 to 2,993.552070 seconds. Successful DMZ MySQL connections have median 3.012547 seconds and maximum 29.404270 seconds. Different durations are consistent with administrative sessions versus request/response services. Brief RDP observations were not assumed to be authenticated sessions without an exact endpoint join.

Packet loss is not universally zero: 574/12,961 core connection observations, 678/10,669 DMZ observations, and 47/462 database observations have positive `missed_bytes`. Across all connection records, neither direction's IP byte count is smaller than its payload count. I found no established TLS row attached to an S0 or REJ connection.

Hourly core connection volumes are 1,829, 3,429, 1,864, 1,768, 2,196, and 1,875 from 13 through 18 UTC. These vary substantially. A six-hour daytime slice cannot establish or disprove realistic overnight/weekend behavior.

### DNS and infrastructure behavior

Core's 3,360 DNS records comprise 2,427 A, 324 AAAA, 315 TXT, 183 PTR, 95 SRV, seven MX, five NS, and four SOA queries. Outcomes are 3,123 NOERROR, 225 NXDOMAIN, nine SERVFAIL, and three REFUSED; 217 NOERROR records have no answer. This includes negative and no-data outcomes rather than universal successful resolution.

Core DNS UID `CjDiL5ET9N7H5kjqFl`, at epoch 1793624403.208604, queries `_ldap._tcp.meridianhcs.local` from 10.10.1.31 to 10.10.2.11 and receives DC-01/DC-02 names with 300-second TTLs. PTR UID `CLjaqS8Xw8d38G9lnw` resolves `40.2.10.10.in-addr.arpa` to LOG-MON-01. These records fit the infrastructure traffic visible in the connection logs. I did not require every connection to have a new DNS query because caches and collection scope matter.

A concrete DMZ resolution-to-TLS sequence starts with `CjVM5E9tahqlhC42hw` at 13:00:01.266334 UTC: 10.10.3.20 queries `data.fastreach.com` and receives 52.84.46.244. Connection `CG295AL9K2PwDjLsPO` opens toward that address on TCP/443 at 13:00:03.677411; its TLS row follows at 13:00:03.783765 with the same SNI and tuple. The ordering is plausible without demanding a particular external real-world DNS mapping.

### TLS, certificates, and file relationships

TLS versions are core 220 TLS 1.2 / 180 TLS 1.3 / one unnegotiated; DMZ 948 / 2,250 / one; database 22 TLS 1.2. TLS 1.3 selects AES-GCM or ChaCha20 suites. I found no joined TLS 1.2 ECDHE_RSA/ECDHE_ECDSA certificate key-type disagreement and no certificate whose observation timestamp was outside its validity interval.

For `CG295AL9K2PwDjLsPO`, the TLS 1.2 cipher is `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`. Leaf FUID `FQsAdfFUiyDy4spKsce` joins to `files.json` and `x509.json`: the file has `source=SSL`, 1,334 seen/total bytes, zero missing bytes, and the certificate has subject `CN=data.fastreach.com`, an RSA 2048-bit key, and an Amazon issuer. The SHA-1 file hash equals the x509 fingerprint. The leaf file appears after the TLS record, inside the transport interval.

A separate internal database example uses UID `Cuo3xGerK7sVIeAs6EY` toward LOG-MON-01. Leaf FUID `FqoBbyIBAg5tU7URKg` joins a 1,239-byte certificate file to an RSA certificate issued by the visible enterprise CA. The later OCSP response `FobD6oY0yA335jyZJB` references the same certificate serial `2A9B319C1EAC30EBEAE02F06ACC689E070BC` and joins to an HTTP response with MIME type `application/ocsp-response`. These are concrete field-level relationships, not an inference from domain names alone.

For HTTP responses with a known response FUID, I checked that its `seen_bytes` did not exceed the corresponding connection's responder payload; no violation was found. This is a necessary accounting check, not a claim that every possible byte or multi-transaction sum was exhaustively audited.

### Proxy and firewall cross-source checks

Core UID `CCNiAm1f7JPR2ix29e` is 10.10.1.41:62106 → 10.10.3.20:8080, starting 13:00:08.687071 UTC. Its CONNECT transaction at 13:00:08.815497 requests `preview.redd.it:443`, returns 200 Connection Established, and reports zero HTTP request/response body lengths. The corresponding proxy access line at 13:00:08 identifies maya.ross and reports control-message bytes 412/229 plus tunnel bytes 1,653/20,830. Those sum to 2,065/21,059, exactly the connection's originator/responder payload bytes. Thus zero HTTP response-body length is not wrongly equated with zero encrypted tunnel payload.

The DMZ sensor sees the same client tuple as `CLFU2scNt0xkZzVVXd` with matching byte totals and a roughly 116 ms sensor timestamp offset. Its nearby outbound TLS 1.3 connection `C1c41TiuTd6CDcPjdUI` names `preview.redd.it`. I treat this as supporting context, not an exact application-owner proof based only on SNI/time proximity.

For the independent 10.10.3.20:42181 → 52.84.46.244:443 connection above, `fw-perimeter/cisco_asa.log` records dynamic NAT to 203.14.220.1:3228, build ID 1681560 at 13:00:03, and teardown of that same ID at 13:00:07 with duration 0:00:03 and TCP FINs. That chronology fits Zeek's approximately 3.545-second lifetime at the firewall's one-second timestamp resolution. I did not mistake the translated source address for a different originating host.

### Limitations and rejected suspicions

I did not infer a native Mac endpoint collector from network visibility, require absent Sysmon event families, demand NTP/QUIC/Bonjour merely because they exist, or score a lack of overnight observations. Packet captures, actual certificate DER, and sensor clock configuration are unavailable, so exact packet reconstruction and cryptographic verification remain outside this review. The clean joins increase confidence in internal coherence but do not prove that the records came from a live network.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| weak_signal | DMZ Zeek TLS connections | 3,195 successful TCP TLS observations; median 2.570160 s, maximum 165.676599 s | Brief duration concentration is explainable by proxy request traffic; negligible weight. |
| hard_contradiction | Network sources reviewed | No demonstrated instance | No increase. |
| contract_gap | DNS/HTTP/TLS parent joins; representative proxy/ASA/certificate relationships | 13,662 parent joins plus the specified independent examples | No demonstrated gap; completeness itself was not scored. |
| schema_or_format | Representative native records and bounded field checks | Three Zeek sensors plus proxy and ASA examples | No demonstrated important defect. |

## Realism Score by Category

- **Field format accuracy:** 9 — Native connection, DNS, HTTP, TLS, file, and certificate field relationships are convincing in the records examined.
- **Temporal patterns:** 8 — Variable loads, realistic service-dependent duration tails, and plausible observed ordering; the daytime slice limits broader cadence assessment.
- **Cross-source correlation:** 9 — Exact protocol-parent tuples, certificate/file identities, proxy accounting, and a firewall NAT lifecycle agree.
- **Behavioral realism:** 8 — Infrastructure, administrative sessions, proxy traffic, failures, and partial observations coexist plausibly.
- **Environmental consistency:** 9 — Sensor-specific service mixes and enterprise/public certificate contexts fit the visible topology without requiring unobserved source families.

## Recommendations

- If this were synthetic, preserve the demonstrated distinction between HTTP CONNECT control bytes and tunnel bytes, and the passive visibility differences between TLS 1.2 and TLS 1.3.
- No corrective recommendation is warranted solely by the brief DMZ TLS durations: their visible long tail and proxy context provide an ordinary explanation. No concrete log-visible network defect requiring repair was substantiated in this bounded review.
