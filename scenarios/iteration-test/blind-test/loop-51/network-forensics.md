# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 76
**Synthetic-Confidence Score:** 58

## Executive Summary

I lean synthetic because the visible public-certificate population repeatedly uses long validity periods inconsistent with the apparent 2026 issuance era across several unrelated named public issuers. This is a qualified environmental finding, not an impossible packet sequence: the flow, DNS, TLS visibility, proxy, and multi-sensor relationships otherwise hold up unusually well under mechanical checks, so the appearance score remains in the mixed range.

## Evidence For Synthetic

- [environment_or_collection_plausibility] **A widespread certificate-era inconsistency:** In `zeek-dmz/x509.json`, 66 of 184 distinct non-CA, non-self-issued certificates attributed to named public issuers have `certificate.not_valid_before >= 1773532800` (2026-03-15 UTC) and validity periods longer than 200 days. These account for 258 rows, not 258 distinct certificates. For example, line 1, fingerprint `9b54b1825bdbdbc674d339c26979936f055d9c96`, describes `CN=registry.npmjs.org`, issued by `DigiCert Global G2 TLS RSA SHA256 2020 CA1`, with validity `1784757011` through `1818885011`: 2026-07-22 21:50:11 through 2027-08-21 21:50:11 UTC, exactly 395 days. Line 12 attributes a 377-day certificate beginning 2026-04-11 to Amazon RSA 2048 M01; line 20 has a 387-day certificate beginning 2026-04-15 from the same issuer. The relevant public TLS requirements limit certificates issued from 2026-03-15 to 200 days. [CA/Browser Forum requirements, §6.3.2](https://cabforum.org/working-groups/server/baseline-requirements/requirements/)
- [distribution_texture] **The certificate issue is a population pattern rather than one anomalous site:** Among the 66 affected distinct certificates, 20 name DigiCert Global G2 TLS RSA SHA256 2020 CA1, 19 Amazon RSA 2048 M01, 17 Sectigo RSA Domain Validation Secure Server CA, five Microsoft Azure RSA TLS Issuing CA 08, and five DigiCert SHA2 Extended Validation Server CA. For example, `zeek-dmz/x509.json:46` gives `CN=graph.microsoft.com` a 389-day lifetime (`1783233639`–`1816843239`); line 126 gives `CN=aws.amazon.com` another 389-day lifetime. The combination resembles reuse of an older public-certificate lifetime model. This is the same underlying issue as the previous bullet and is not scored a second time.

**Qualification:** `not_valid_before` is a validity boundary, not an explicit issuance timestamp. I cannot prove issuance chronology, public trust, or cryptographic authenticity without DER certificates and trust-chain validation. A documented timestamp-shifting sanitization process could also explain the historical mismatch. Private enterprise certificates and self-issued IP certificates were excluded from the 66/184 count; domain spelling and real-world domain-to-IP mappings were not used as authenticity evidence.

## Evidence For Real

- **TCP state and byte accounting are coherent.** Across all three sensors, every TCP `SF` row includes both FIN directions, no same-sensor TCP five-tuple has overlapping visible intervals, and minimum IPv4/TCP header-byte checks pass when accounting for reported gaps. Zero-gap, non-retransmission records also have header-byte differences divisible by four. These are supportive consistency checks, not a claim that the underlying packets were recovered.
- **Protocol rows remain inside their own transport intervals.** Every DNS, HTTP, and SSL UID resolves to a same-sensor connection with matching four-tuple. None starts before its connection or after its recorded end. This covers 4,313 DNS, 4,610 HTTP, and 3,142 SSL rows. Completeness itself is neutral; the absence of contradictions in these tests supports plausibility.
- **TLS visibility respects encryption boundaries.** None of the 2,007 TLS 1.3 rows exposes `cert_chain_fuids`. None of the resumed TLS rows exposes a fresh certificate chain. TLS 1.2 full handshakes carry certificate references, while TLS 1.3 examples such as `zeek-dmz/ssl.json:1` have `ssl_history="Cs"`, no certificate chain, and `established=true`. This is compatible with passive TLS 1.3 visibility. [Zeek TLS log explanation](https://docs.zeek.org/en/current/reference/logs/ssl.html)
- **Failure and partial-observation behavior are present and consistent.** `zeek-dmz/conn.json:1` has a one-packet SYN-only attempt from `10.10.3.10:42178` to `10.10.2.21:443`, `S0`, no response packets, and no identified application service. `fw-perimeter/cisco_asa.log:1` independently records that exact tuple being denied. Database traffic includes both originator and responder resets, rather than every operation being a clean close.
- **Administrative sessions have credible transport lifetimes.** `zeek-core/conn.json:96` records a 3,384.936579-second SSH session from `10.10.1.35:53592` to `10.10.2.30:22`. Line 361 records a 2,220.787110-second RDP session from `10.10.1.31:61765` to `10.10.2.27:3389`, with substantially more responder than originator bytes. These differ appropriately from short DNS and web transactions.
- **DNS has meaningful variety.** Core DNS includes A, AAAA, PTR, SRV, TXT, MX, NS, and SOA records; NOERROR, NXDOMAIN, SERVFAIL, and REFUSED responses; variable TTLs; and short internal as well as longer external response times. The packet rows support the transaction timing.

## Detailed Analysis

### Actual input provenance, method, and limits

I read the complete neutral briefing at `/private/tmp/log-study-xgpo00ey/network-prompt.md` and enumerated only its supplied `/private/tmp/log-study-xgpo00ey/data` directory. I parsed all 38,537 JSON records under the three `zeek-*` directories, including conn, DNS, HTTP, SSL, X.509, OCSP, files, DHCP, SMTP, SMB, and PE files where present. I also read the supplied proxy-access, ASA, and both Snort alert files to count their records and examine source-native examples; the ASA build/teardown inventory was checked programmatically. I did not inspect endpoint file contents, shell histories, project files, scenarios, TODO/worklogs, neighboring reviews, or prior assessment results. Logged commands were not executed.

Public reference searches used actual `docs.zeek.org` and `cabforum.org` domain filters. References concern protocol/source semantics and certificate policy only. No project public pages or snippets were accessed. Generic inherited operating context exists in the agent environment but was not used as evidence of origin. I am applying the requested network-analyst perspective, not claiming a personal employment history or expert-witness credential.

All line references are one-based physical lines, paths are relative to the supplied data directory, and timestamp conversions use UTC. The visible connection starts span approximately 2026-11-02 13:00–19:00 UTC. This six-hour slice cannot establish daily or overnight behavior. No packet capture, sensor build/version, detailed capture configuration, certificate DER, or sanitization transformation specification was supplied. Checks establish internal consistency of the records, not validation against wire bytes.

| Sensor | Connections | DNS | HTTP | SSL | X.509 | Files |
|---|---:|---:|---:|---:|---:|---:|
| zeek-core | 12,314 | 3,188 | 2,159 | 403 | 225 | 678 |
| zeek-dmz | 9,401 | 1,075 | 2,431 | 2,725 | 1,079 | 1,686 |
| zeek-db | 433 | 50 | 20 | 14 | 14 | 21 |

The supplemental files contain 3,524 proxy rows, 22,721 ASA rows, 73 core Snort alerts, and 102 perimeter Snort alerts. Different sensors may observe the same activity; these are observation counts and must not be added as unique sessions.

### TCP behavior, packets, and sensor correlation

Core TCP states comprise 4,944 SF, 1,409 S0, 150 RSTO, 116 RSTR, 28 REJ, 27 OTH, and small S1/S2/S3 tails. DMZ has 5,369 SF and 2,317 S0 among 7,960 TCP rows. The larger unsuccessful DMZ population is consistent with visible probes and denied traffic; its size alone is not proof of artificiality. Database TCP has 274 SF, 31 RSTO, and 30 RSTR among 357 rows.

For example, `zeek-db/conn.json:1` has `RSTO`, history `ShADaR`, originator payload 1,100 bytes and no responder payload: a sensible reset-after-client-data representation. Line 2 has `RSTR`, history `ShADadr`, and responder data before responder reset. No reported TCP SF row lacks both close directions. Reported content gaps occur in 524 core, 552 DMZ, and 37 database connections; no row with a G/g history flag reports zero `missed_bytes`. Zeek documents these history and gap meanings in its [connection schema](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html).

Matching on protocol/four-tuple and connection start within one second produced 4,850 core–DMZ, 157 core–database, and 288 DMZ–database pairs. Among matched zero-gap TCP SF conversations, I found no disagreement in application byte totals. Median start offsets were approximately -114 ms for DMZ relative to core, +65 ms for database relative to core, and +180 ms for database relative to DMZ. Those offsets can reflect independent sensor clocks; they are not impossible packet ordering and were not scored.

### DNS and protocol mix

Core DNS type counts are A 2,333, TXT 300, AAAA 279, PTR 154, SRV 105, MX eight, NS six, SOA three. Its response-code distribution is NOERROR 2,943, NXDOMAIN 227, SERVFAIL 14, REFUSED four. DMZ includes 150 NXDOMAINs among 1,075 transactions. This is more plausible than universal success and a single query type, although distributions alone do not authenticate a dataset.

`zeek-core/dns.json:1` is a domain-controller SRV lookup with a 28.925-ms response and two DC answers; line 2 resolves the file server with a 0.928-ms response. Their respective conn rows agree on UID, tuple, and transaction interval. No query label exceeds 63 characters and no visible query name exceeds 253 characters. All DNS query payloads meet a basic minimum encoded-query size check.

Core traffic includes Kerberos, LDAP, SMB, DNS, DHCP, SMTP, SSH, and RDP. The database sensor is dominated by MySQL: 260 connections identify `mysql`. These observations support the inferred Windows-domain and application/database topology. I did not demand NTP, Bonjour, QUIC, or any other protocol merely because one of the observed platforms can produce it.

### Proxy path, HTTP, and TLS

Most HTTP rows are explicit proxy CONNECT requests rather than plaintext browsing: core has 1,863 successful CONNECT responses, plus authentication, policy, and gateway failures. Consequently the raw HTTP-to-SSL row ratio cannot be interpreted as the fraction of browsing that uses encryption.

`PROXY-01.meridianhcs.local/proxy_access.log:1–2` ties a CONNECT and inspected HTTPS GET to `tunnel_id=PT-a5e41cdf86225d43`, client port 40446, and the same user agent. The log explicitly distinguishes CONNECT control-message bytes from tunnel totals, which avoids a common ambiguity when comparing proxy bytes with transport totals. The network files represent the client-to-proxy and proxy-to-server legs separately. The domain names were treated as potentially sanitized.

TLS versions are mixed: core has 199 TLS 1.3, 201 TLS 1.2, and three versionless rows; DMZ has 1,808 TLS 1.3, 913 TLS 1.2, and four versionless rows; database has 14 TLS 1.2. Cipher suites include AES-GCM and ChaCha20, with some TLS 1.2 CBC suites on internal services. Without software configuration evidence, the latter is possible legacy configuration, not an authenticity defect.

I found no TLS certificate-key/cipher authentication mismatch, no child-certificate signature algorithm incompatible with its visible issuer key type, no same-fingerprint disagreement in certificate fields, no changing size/hash for the same certificate fingerprint, and no certificate-chain byte total exceeding its connection's responder payload. Files begin inside their referenced connection intervals. All logged certificates are within their own validity boundaries at observation time. The concern is the **length and apparent issuance era** of a subset of public certificates, not expiry, TLS 1.3 certificate visibility, or private-CA policy.

### Why the score is qualified

The date/lifetime pattern is concrete and broad, but does not establish an impossible protocol transcript. Multiple real issuers independently producing so many apparently post-transition year-long certificates is less plausible than an outdated model or a date transformation. Conversely, a coherent timestamp shift of genuine older telemetry could produce exactly this issue. That alternative materially reduces verdict confidence and prevents a score in the strongly synthetic or hard-contradiction range.

I found no basis to score suspicious activity's linearity, completeness, compactness, lack of mistakes, selected endpoint event coverage, or high source alignment. I also did not convert missing pre-window initiators or post-window closure into defects. ASA has 8,519 TCP/UDP build identities and 8,516 teardown identities, with no repeated build or teardown identities; the three unmatched builds are not independently suspicious in a slice.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| environment_or_collection_plausibility | Zeek X.509 / TLS certificate population | 66 distinct named-public-issuer leaf certificates, represented in 258 DMZ rows | Apparent post-2026-03-15 validity starts paired with >200-day lifetimes create a repeated certificate-era mismatch; main reason for leaning synthetic. Issuance timestamps, DER, and sanitization history are unavailable. |
| distribution_texture | Same certificate population | Five named public issuer families | Breadth makes an isolated misissuance explanation weak and suggests shared lifetime assumptions. Same underlying finding, not an additional independent penalty. |

No demonstrated hard contradiction, lifecycle contract gap, or source-format defect was established by the network checks.

## Realism Score by Category

- **Field format accuracy:** 9 — Consistent Zeek tuples, types, state histories, certificate references, and source-native supplemental examples; no demonstrated schema failure.
- **Temporal patterns:** 9 — Protocol times stay inside transport intervals, plausible varied durations, no overlapping same-sensor TCP identities; six hours limits circadian assessment.
- **Cross-source correlation:** 9 — Matching sensor byte totals and protocol UIDs withstand checks, and denied traffic has compatible firewall evidence.
- **Behavioral realism:** 8 — Credible infrastructure mix, session durations, resets, failed requests, and DNS diversity; records alone cannot establish organic user behavior.
- **Environmental consistency:** 6 — Topology is coherent, but repeated public-certificate lifetimes do not fit the apparent 2026 certificate-policy era without an additional explanation.

## Recommendations

- If this were synthetic, make public-certificate validity selection depend on the modeled issuance era and the applicable issuer policy. Revisit the 66 affected distinct DMZ certificate identities; preserve stable fields, hashes, and sizes across every reference when replacing a certificate.
- If this is sanitized real telemetry with shifted dates, disclose that transformation. Preserve the relationship between certificate validity, issuance-era policy, and event dates, or explicitly qualify certificate-era authenticity checks. This recommendation follows the measured date/lifetime mismatch and is not a request to add unrelated log sources.
