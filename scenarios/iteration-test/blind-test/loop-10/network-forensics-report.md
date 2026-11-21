# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 80
**Synthetic-Confidence Score:** 36

## Executive Summary

The network evidence is mostly production-like: TCP state histories, DNS exchanges, HTTP bodies, TLS certificate identities, and protocol-to-connection relationships withstand several independent consistency checks. A recurring arithmetic texture in TCP packet accounting raises a limited suspicion of modeled traffic, but I found no hard network contradiction that establishes synthetic origin. My confidence concerns the inconclusive verdict; the separate score of 36 places the observed evidence in the mostly realistic range.

## Evidence For Synthetic

- [weak_signal] TCP packet accounting repeatedly clusters around a small arithmetic pattern across otherwise different traffic. For each direction, define `R = ip_bytes - bytes - 52 * pkts`. Among successful TCP connections without recorded gaps or retransmission history, both directional residuals belong to `{4, 8, 12}` in 1,966/3,963 core records, 137/231 database records, and 2,427/4,723 DMZ records. This may reflect a simplified packet-accounting model, although common TCP options and a standardized network stack are credible alternatives. I assign this limited weight, not the weight of an impossible field value.
- [weak_signal] The same residual choices recur within one stable application pair, not only in the aggregate: `zeek-db/conn.json` shows `10.10.3.10 -> 10.10.4.10:3306` at `13:01:16.993250Z` with residuals `(12,12)`, at `13:06:11.439150Z` with `(60,292)`, at `13:06:55.853537Z` with `(12,4)`, and at `13:10:36.901584Z` with `(8,12)`. Among 173 clean successful MySQL records for this pair, 103 use one of the nine small-residual combinations. This makes the texture worth checking against packets, but option variation, segmentation and capture characteristics prevent a stronger conclusion. This is supporting detail for the preceding indicator, not a second independent defect.

## Evidence For Real

- The three sensors have meaningfully different protocol distributions. The core observes substantial DNS, Kerberos, LDAP, SMB and proxy traffic; the database sensor is dominated by MySQL; the DMZ includes large HTTPS and unsolicited SYN populations. This agrees with the roles implied by the addresses and services.
- Across 23,144 connection records, all examined DNS, HTTP, TLS, SMTP and SMB file records resolve to a connection UID with the same four endpoint fields. Their timestamps lie within the corresponding visible connection interval. The one exception to UID resolution is a standalone SMB mapping row discussed below; there are no tuple contradictions among resolved records.
- All successful TCP connection records contain both FIN directions in their histories. No `S0` TCP record has responder packets. I found no overlapping TCP connections with the same ordered four-tuple within an individual sensor.
- Summed HTTP request and response bodies never exceed their respective TCP payload totals. File observations stay within their associated connection intervals and do not exceed the visible stream byte totals for the non-TLS files checked.
- Certificate fingerprints retain consistent certificate attributes across all three sensors; ECDSA and RSA TLS 1.2 ciphers agree with the referenced certificate key types. Referenced certificates are valid at the observed TLS timestamp, and TLS 1.3 records do not expose certificate chains as though they were plaintext TLS 1.2 handshakes.
- DNS contains A, AAAA, PTR, SRV, TXT and infrastructure query types, with negative and server-failure responses. Internal versus external response-time medians differ plausibly. Complete-file hashes do not identify different reported file sizes under the same digest.
- All parseable single-line IDS alerts checked have a corresponding Zeek flow with the same tuple within the flow interval or a two-second observation allowance: 68 core and 79 perimeter alerts. This is corroborating coherence, not proof of origin.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory. Network analysis covered every JSON row in the three Zeek directories, with targeted inspection of the proxy, firewall, IDS and Linux endpoint examples. No repository content, scenario, ground truth, other review or external source informed this verdict. All timestamps below are UTC on November 2, 2026; connection counts are sensor observations, not deduplicated network sessions.

| Sensor | Connection records | TCP | UDP | ICMP | DNS records | HTTP records | TLS records |
|---|---:|---:|---:|---:|---:|---:|---:|
| zeek-core | 12,337 | 6,999 | 4,897 | 441 | 3,183 | 2,631 | 406 |
| zeek-db | 436 | 371 | 43 | 22 | 40 | 31 | 23 |
| zeek-dmz | 10,371 | 8,869 | 1,191 | 311 | 1,139 | 2,924 | 3,246 |

Connection start times span approximately `13:00:02Z` through `18:59:50Z`. A six-hour slice does not support claims about weekend behavior, full-day traffic rhythms, or absent pre-window session creation. I did not require other collectors or platform-specific traffic that the visible collection does not establish.

### TCP state, lifecycle and accounting

Core state counts include 9,907 `SF`, 1,638 `S0`, 150 `RSTO`, 80 `RSTR` and 41 `REJ`; the remainder includes `OTH` and partial-close states. DMZ counts include 7,415 `SF`, 2,375 `S0`, 127 `RSTO`, 71 `RSTR` and 40 `REJ`. The greater unsuccessful-SYN component at the DMZ is plausible for an exposed service segment. These state counts include UDP and ICMP where applicable, so `SF` should not be read as TCP-only.

For a concrete failed TCP example, `zeek-dmz/conn.json` UID `CvgdoLdmzCXBgmFL1k` at `13:00:05.975614Z` describes `185.220.233.25:12544 -> 10.10.3.10:443`, `S0`, history `S`, one originating packet and zero responder packets. It does not fabricate a completed application exchange.

For a long-lived successful session, core UID `CyB9hLBGyrvvCmpvEsl` begins at epoch `1793632503.273031` (`15:15:03.273031Z`), connects `10.10.3.10:59437 -> 10.10.2.30:22`, and lasts `13316.188029` seconds. Its `SF` state, `ShADadfF` history and small payload totals are compatible with a long, mostly idle SSH transport. Its close falls inside the visible six-hour interval.

I specifically tested whether IP-byte totals were smaller than payload plus minimum IPv4/TCP headers. Some rows trigger that naive test, but every such example examined records missed bytes and corresponding gap history. For example, core UID `CRU4kpUSxtqCSeNgPv` records `missed_bytes=32768` and history `ShADadfFG`. Sequence-space payload estimates can exceed captured payload when packets are missing. I therefore do not classify these rows as impossible packet accounting.

The residual clustering described above is the principal remaining concern. It is visible in different sensors and services, but is an inference about texture rather than a demonstrated transport violation. The residual is a diagnostic transformation, not a native field or a claim that real packets must all have 52-byte headers. There is also substantial residual variation outside the small cluster, which weakens any claim of one universal formula.

### DNS and infrastructure traffic

Core DNS includes 2,344 A, 299 AAAA, 265 TXT, 160 PTR, 103 SRV, six NS, four MX and two SOA records. Responses include 244 NXDOMAIN, 17 SERVFAIL and one REFUSED. DMZ DNS includes 155 NXDOMAIN and four SERVFAIL among 1,139 records. This provides negative outcomes and infrastructure diversity rather than only successful browsing lookups.

The first core DNS exchange, UID `Cy7bKJVXGBLSw4N5M0b` at `13:00:02.649837Z`, asks `_ldap._tcp.meridianhcs.local` as SRV and receives two domain-controller names with 300-second TTLs. That agrees with the internal directory traffic visible elsewhere in the sensor.

A concrete external lookup occurs at `13:01:41.515391Z` in DMZ DNS: `10.10.3.20` asks for `pypi.org`, receiving `151.101.0.223` and `151.101.64.223`, with `rtt=0.021716`. DMZ connection UID `CKwX338KD937UMIYSN` then opens from `10.10.3.20:58360` to `151.101.0.223:443` at `13:01:41.561833Z`, followed by the TLS observation at `13:01:42.070793Z`. The DNS response can finish before that transport starts.

Median recorded DNS RTT is approximately 3.808 ms at core, 1.394 ms at database and 18.312 ms at DMZ. No DNS RTT exceeds its matching connection duration, and A/AAAA answers contain no demonstrated IP-version mismatch. I do not penalize connections without a fresh DNS lookup because caching, literal addressing and proxy resolution can explain them.

Core DHCP has 60 records. For example, `MAC-MROSS-01` receives an acknowledged renewal for `10.10.1.41` at `13:00:31.115394Z`, `lease_time=7200`, using the matching UDP 68-to-67 connection UID `CJByZnSE7lbvLtMvdHu`. This is consistent with a slice that begins after the original lease acquisition.

### HTTP and proxy semantics

Most core HTTP records are explicit-proxy CONNECT controls: 2,419 CONNECT versus 202 GET and ten POST. Consequently, raw HTTP-record count is not a measure of cleartext web browsing. The proxy log explicitly separates CONNECT control bytes from tunnel byte totals and also contains `proxy_action=ssl` request observations; I did not demand that encrypted request bodies appear as ordinary passive Zeek HTTP rows.

The proxy has 4,571 access lines: 2,486 CONNECT, 2,029 GET and 56 POST, with no exact duplicate lines. Its actions include tunnel, SSL, forward, deny, gateway failure and authentication handling. Examples include the `13:01:41Z` CONNECT to `pypi.org:443` with `tunnel_cs_bytes=4704` and `tunnel_sc_bytes=33664`, matching the external TLS connection's payload totals. The tunnel has a finite duration and distinct control-message byte scope.

I summed HTTP bodies by UID before comparing them to TCP payload totals, so persistent connections with several transactions were not incorrectly treated as separate full byte budgets. Core and DMZ both contain multiple transactions per UID, including three, four, six and seven transaction observations. No aggregate body-over-stream contradiction was found.

### TLS, certificates and extracted objects

DMZ TLS comprises 2,097 TLS 1.3, 1,148 TLS 1.2 and one record lacking a negotiated version. Core is 190 TLS 1.3, 215 TLS 1.2 and one lacking a version; database is predominantly TLS 1.2. Ciphers include AES-GCM and ChaCha20 for TLS 1.3 and RSA/ECDSA ECDHE suites for TLS 1.2, with some CBC usage in internal traffic. I do not infer a software release solely from a browser user-agent string.

UID `CKwX338KD937UMIYSN` identifies TLS 1.3 to `pypi.org`, `TLS_AES_256_GCM_SHA384`, `resumed=true`, with no exposed certificate-chain FUID. Internal certificate example core FUID `FbuozjPXMp7g6NrDLJ` identifies `LOG-MON-01.meridianhcs.local`, an enterprise issuer, a 2048-bit RSA key and matching SAN values. The same fingerprint carries consistent subject, serial, issuer, validity and key fields across sensors.

I checked all complete, non-timed-out file observations with equal seen and total sizes for SHA-1, MD5 and SHA-256 digest-to-size contradictions; none were found. This includes objects visible along proxy-related paths. It does not establish that the recorded hashes are the hashes of real captured bytes, because no packet or extracted-object bytes were supplied.

### Lateral activity, observation gaps and alerts

The database sensor contains 270 MySQL-classified flows to port 3306, while core includes SMB, SSH and RDP-classified traffic. Core UID `CFTXn6BOHTlnERMTUYe` begins at `13:04:43.208649Z` from `10.10.1.34` to `10.10.2.11:445`; its SYSVOL mapping follows at `13:04:43.326657Z`, and `Scripts\groups-approved.xml` is read at `13:04:44.090070Z`. The read fits the 1.919174-second connection and its 66,668 responder bytes. This is a coherent file-service exchange.

One SMB mapping at `17:35:24.869741Z`, UID `CDvU7F7ECk5HefE3QX`, has no corresponding core connection row. Its endpoints are `10.10.1.22:36927 -> 10.10.2.20:445` and its share is ClinicalExports. A single absent connection observation can arise from collection loss or filtering; without a collection-completeness guarantee or a conflicting visible connection, I do not score it as a synthetic defect.

IDS single-line tuple correlations were checked against all visible sensor flows with a two-second allowance for collection timing. The result supports contextual consistency; it does not validate proprietary signature payload conditions, and multiline scan-summary records were not counted in that test. Firewall examples expose private/public address mappings and connection identifiers, but this review does not claim an exhaustive independent reconstruction of every ASA translation lifecycle.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| weak_signal | Zeek TCP connection packet accounting | All three sensors; 4,530/8,917 clean successful TCP observations have both residuals in the small three-value set | Limited upward influence: recurring arithmetic texture, with real TCP option and capture explanations still available |
| weak_signal | Zeek MySQL connection accounting | 103/173 clean successful records for one application/database pair show the same small residual combinations | Supports the same observation within one host pair; not counted independently |

No demonstrated hard contradiction, generator identity leak, impossible visible causality, certificate identity conflict or body-over-stream violation was found. The singleton unresolved SMB mapping is recorded as an observation limitation and receives no independent synthetic penalty.

## Realism Score by Category

- **Field format accuracy:** 9 — Structured protocol fields, address types, hashes and cipher/certificate relationships are consistent in the checks performed.
- **Temporal patterns:** 9 — Protocol and file timestamps stay within transport lifetimes; short DNS exchanges and long SSH sessions coexist without demonstrated impossible ordering.
- **Cross-source correlation:** 9 — UID/tuple, proxy tunnel-byte and IDS-flow checks agree; one unresolved SMB mapping remains explainable by collection effects.
- **Behavioral realism:** 8 — Roles, service mix, failures and proxy behavior are plausible; TCP accounting retains a mildly parametric texture.
- **Environmental consistency:** 9 — Core, DMZ and database observations differ in ways consistent with their visible services and observation paths.

## Recommendations

- If this were synthetic, validate the repeated TCP accounting residuals against representative packet traces from each modeled stack and service. Derive byte and packet totals from explicit packet/header assumptions, preserving real option negotiation, ACK behavior, segmentation, retransmissions and gaps rather than adding numerical noise solely for variety.
- If this were synthetic, investigate the unresolved SMB mapping UID `CDvU7F7ECk5HefE3QX`. Either retain its connection record or ensure the intended source-collection loss model explains why that source-local companion is absent. This is a consistency check prompted by one visible gap, not a recommendation to make coverage universally complete.
- Preserve the coherent DNS-to-TLS ordering, explicit proxy byte scopes, certificate identity reuse and observed transport lifetimes. No change to source coverage or suspicious-activity narrative is justified by this review alone.
