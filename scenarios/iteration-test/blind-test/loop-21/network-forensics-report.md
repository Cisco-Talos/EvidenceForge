# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 79
**Synthetic-Confidence Score:** 67

## Executive Summary

The network records are convincing at the individual flow and protocol level, with varied connection states, coherent DNS/HTTP/TLS identifiers, and consistent certificate identities. My synthetic verdict rests on a narrower but widespread inconsistency: successful proxy CONNECT tunnels frequently fail to preserve byte accounting between the declared tunnel counters and the closely matched upstream TLS connection. This is a contract gap rather than an established impossible packet sequence; undocumented TLS interception or counter semantics remain alternative explanations.

## Evidence For Synthetic

- **[contract_gap] CONNECT tunnel byte accounting diverges across its two legs.** In a bounded comparison of 1,208 uniquely matched, successful CONNECT/upstream TLS pairs, 698 (57.8%) had upstream application-stream byte totals different from the proxy's `tunnel_cs_bytes` or `tunnel_sc_bytes`. Both selected Zeek connections had `conn_state=SF` and `missed_bytes=0`; the upstream began within 0–0.5 seconds after the client connection. Matching used the proxy client's IP, CONNECT target, timestamp, and upstream TLS SNI, with unique candidates required. Files: `PROXY-01.meridianhcs.local/proxy_access.log`, `zeek-dmz/http.json`, `zeek-dmz/ssl.json`, `zeek-dmz/conn.json`. These are inferred tunnel pairs, not a shared-UID join, so the aggregate is evidence of a pattern rather than proof for every individual pair.
- **[contract_gap] A particularly restrictive example has more upstream request bytes than the entire client stream.** At 2026-11-02 13:17:01 UTC, client flow `CG0yFMvovjlI1Trm11`, `10.10.1.35:52427 → 10.10.3.20:8080`, has `orig_bytes=786`. Its proxy row declares CONNECT to `ctldl.windowsupdate.com:443`, `cs_bytes=422`, `tunnel_cs_bytes=364`, and `proxy_action=tunnel`. The upstream connection `C94XuVK3KPtstF6zdLv` starts 206.625 ms later from `10.10.3.20:40231 → 52.114.132.73:443` with the matching SNI, but has `orig_bytes=816`. Both have ordinary `ShADadfF` histories, successful closure, and no missed bytes. A transparent CONNECT relay does not create these extra client-to-server TLS bytes. TLS interception could do so, but that behavior is not expressed by the visible tunnel labeling.
- **[weak_signal] Some DNS queries refresh the same answer before the previous TTL expires.** In `zeek-core/dns.json`, 119 of 1,486 adjacent repeat successful A-query pairs to the same resolver, for the same client and name, repeat the same answer before expiry. For example, `10.10.1.31` queries `10.10.2.10` for `DC-01.meridianhcs.local` at 17:13:56.028734 and 17:16:07.920781 UTC, receiving `10.10.2.10` and TTL 300 both times. Application-specific resolver behavior, cache bypasses, or restarts can explain this; it carries little weight and is not a contradiction.

## Evidence For Real

- Every examined DNS, HTTP, TLS, SMB-file, and SMTP record joins to a connection UID in its own sensor, with matching endpoint tuples. I found no protocol timestamp earlier than its connection by more than 1 ms, or later than its connection interval by more than 0.5 seconds.
- TCP states have a credible mix, rather than only successful sessions. `zeek-core/conn.json` includes 9,869 SF, 1,688 S0, 182 RSTO, 101 RSTR, 47 REJ, and smaller S1/S2/S3 populations; these counts include non-TCP rows in the full source totals. I found no S0 history showing an established handshake and no RSTO/RSTR history with the reset direction reversed.
- DNS contains A, AAAA, PTR, SRV, TXT, MX, NS, and SOA activity, along with NXDOMAIN, SERVFAIL, and REFUSED results. Internal AAAA lookups can return NOERROR without an answer, rather than being forced to return IPv6 addresses.
- Certificate references resolve, fingerprint widths are consistent, and certificate-file SHA-1 values agree with X.509 fingerprints. Repeated observations of the same certificate retain consistent certificate metadata and file identity.
- The proxy records distinguish CONNECT control-message bytes from tunnel bytes. For the first visible tunnel at 13:00:19 UTC, the client stream is exactly `384 + 4,461 = 4,845` request bytes and `197 + 1,898 = 2,095` response bytes. This demonstrates meaningful internal accounting even though the upstream response count differs.
- Connection activity varies across the six hours, and remote administration includes both short failed/aborted interactions and sessions lasting tens of minutes or hours. The visible variation is consistent with interactive use and infrastructure traffic.

## Detailed Analysis

### Scope and method

I read only the supplied data directory and the assessment instructions. The network review covered all JSON records in `zeek-core`, `zeek-dmz`, and `zeek-db`, plus selected proxy, firewall, and IDS records and limited endpoint records to identify a client's platform. No repository implementation, scenario, ground truth, evaluation output, prior assessment, or domain-resolution assumptions were used.

The three Zeek sensors contain 23,014 connection observations: 12,379 core, 10,198 DMZ, and 437 database. These are observations, not necessarily distinct network sessions, because sensors overlap. They include 4,366 DNS, 5,497 HTTP, and 3,668 TLS observations. The core window extends from 2026-11-02 13:00:01.809034 to 18:59:50.447763 UTC. The dataset therefore cannot establish overnight traffic, weekend behavior, or complete beginning/end lifecycles.

### Transport states, packet counters, and lifecycle

I checked individual sensor TCP tuples for overlapping connections with the same directional four-tuple; none overlapped by more than 10 ms. I also checked reset histories and whether data-history letters were accompanied by positive stream bytes. These checks did not establish a contradiction.

All byte counters were nonnegative and IP-byte totals were at least application-byte totals. All UDP counters passed the basic IPv4-plus-UDP overhead check. Some TCP IP/application differences fall below a simple 40-bytes-per-observed-packet bound, but those examples have reported content gaps: Zeek's logical stream accounting can include unobserved sequence space. I do not classify them as impossible packet accounting.

Capture gaps affect 594/7,011 core TCP observations, 711/8,748 DMZ TCP observations, and 41/363 database TCP observations. Within each sensor, gap history letters agree with the presence of nonzero `missed_bytes`. Capture loss is an available explanation for some discrepancies, but the reported tunnel comparison explicitly excluded these rows.

SSH includes genuinely long sessions: core UID `Cp18EN60koScLZ227` starts at 13:00:44.583201 UTC, `10.10.1.21:40111 → 10.10.3.10:22`, with duration 3,631.909177 seconds. The DMZ record `Ce0EWXJ12qcDAdQ5IX`, from `10.10.3.10:60743 → 10.10.2.30:22`, starts at 15:14:58.898815 and lasts 13,320.733152 seconds. Long duration alone is plausible, including near-window-end termination.

### DNS and name resolution

Core DNS includes 2,396 A, 294 AAAA, 262 TXT, 154 PTR, 106 SRV, nine NS, five MX, and three SOA records. Responses include 2,982 NOERROR, 226 NXDOMAIN, 16 SERVFAIL, and five REFUSED. The mix is consistent with an AD-connected environment with additional application traffic; it is not just external browser A queries.

The 13:00:01.809034 query by `10.10.1.31:57565` to `10.10.2.11:53` resolves `DC-02.meridianhcs.local` to `10.10.2.11`, with RTT 57.582 ms and TTL 300. At 13:00:02.853047 the same client makes an LDAP SRV query. These are plausible prerequisites to domain activity. I did not assume each connection needs a fresh visible DNS lookup: caching, literal addresses, and pre-window resolution are legitimate.

AAAA answers that contain IP addresses have the appropriate IPv6 family; A answers have the appropriate IPv4 family. Internal authoritative responses and external recursive responses differ in their AA flags. TTL values include short external cache residuals and longer internal values. The small premature-refresh population is a weak behavioral signal only.

### TLS and certificates

DMZ TLS contains 2,268 TLS 1.3 observations, 953 TLS 1.2 observations, and five with no negotiated version. Core has 187 TLS 1.3, 224 TLS 1.2, and two without a negotiated version. Database TLS is mainly TLS 1.2. The cipher/version combinations agree: AES-GCM and ChaCha20 suites appear under TLS 1.3, while ECDHE suites appear under TLS 1.2. The visible CBC minority is not by itself a defect.

TLS 1.3 records generally have `ssl_history=Cs` and no certificate-chain FUIDs, a plausible passive-observation limitation. TLS 1.2 resumed sessions generally have `CsiI`, and non-resumed observations commonly carry certificate references. I did not penalize TLS 1.3 certificate invisibility or expect decryption without evidence.

For database UID `CoqzJj8pa3bM3ZNHN`, the TLS row references leaf `FBTXrynqCxUI1qZ1eZ`. Its X.509 subject is `CN=FILE-LNX-01.meridianhcs.local`, matching SNI; the certificate-file SHA-1 and X.509 fingerprint both read `43e521283ed308a7fc18a4c720c60dcd300ce161`. There were no missing referenced certificate/file IDs or conflicting metadata for repeated fingerprints within the inspected sensors.

### HTTP, CONNECT, proxy and firewall accounting

Most HTTP records are CONNECT requests: 2,394 core and 2,436 DMZ. Consequently, the HTTP/HTTPS ratio cannot be interpreted as a large population of unencrypted web browsing. Many HTTP rows describe access to the explicit proxy, while the upstream leg is TLS. Proxy errors include authentication, policy, and upstream failure responses rather than only 200.

The important defect is conservation of the tunneled stream. At 13:00:19 UTC, client UID `Ck8t9TVyt9f39ChX4o4` has 4,845/2,095 request/response bytes, exactly equal to the proxy's declared control-plus-tunnel totals. Its closely matched upstream UID `CVLqENoLEv13zc7PMM`, beginning 58.562 ms later to `52.114.132.73:443`, has 4,461/2,225 bytes. The 4,461 request bytes match the tunnel, while the upstream response exceeds declared tunnel response by 327 bytes. Both flows report SF and zero missed bytes.

A second example at 13:04:52 UTC illustrates divergence in both directions. Client UID `CcLaM8TsPT45KeRjpG`, `10.10.3.10:52523 → 10.10.3.20:8080`, has 913/3,047 bytes. Its proxy row declares control 315/200 and tunnel 598/2,847, which sum exactly to those client totals. Upstream UID `CEOm8E81KrDvtrQDMD` begins 135.142 ms later to `172.217.129.94:443`, with matching target SNI `20-205-153-145.microsoft.com`, but has 897/4,442 bytes. Both are SF without missed bytes.

Individual differences can arise from buffering, unforwarded tail data, distinct interception sessions, or undocumented counter scope. Those alternatives prevent calling this a hard contradiction. However, divergences in 698/1,208 tightly timed, uniquely matched successful pairs across 22 client IPs are a substantial repeated cross-source defect under the stated `proxy_action=tunnel` semantics. The strongest examples also have no retransmission or gap markers. I found no corresponding systematic tunnel-duration defect: declared tunnel durations did not exceed the uniquely matched downstream TCP duration by more than 10 ms.

The initial ASA records provide a plausible NAT identity: `10.10.3.20:41424` translates to `203.14.220.1:49116` for the external TLS connection. Different sensor UIDs and modest timestamp offsets are expected and were not scored as synthetic.

### Traffic distribution and interpretation limits

Core hourly connection counts are 1,595, 3,142, 1,949, 1,744, 2,042, and 1,907 from 13:00 through 18:00 UTC. DMZ counts are 1,397, 2,828, 1,480, 1,573, 1,359, and 1,561. The shared 14:00-hour increase is coherent across vantage points; it is not flat per-hour generation.

Database visibility is dominated by 250 MySQL connections from `10.10.3.10` to `10.10.4.10:3306`, alongside DNS, syslog, TLS, and administration. The core and DMZ also include substantial uncompleted connection attempts, with varying destination ports. I do not score suspicious activity's completeness, compactness, or apparent narrative as an authenticity indicator. I also do not penalize absent QUIC, NTP, or other sources without evidence that the collection required them.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the score |
|---|---|---|---|
| contract_gap | Proxy access and DMZ Zeek HTTP/TLS/conn | 698 of 1,208 uniquely matched, successful, no-gap CONNECT/upstream pairs; 22 client IPs in the compared population | Declared transparent-tunnel byte totals frequently disagree with the upstream stream; some upstream request totals exceed the entire client input. Main basis for a score in the likely-synthetic range. Pairing and undocumented interception remain limitations. |
| weak_signal | Core DNS | 119 of 1,486 adjacent repeat successful A-query pairs to the same resolver | Same answer repeated inside the previous TTL. Explainable by client behavior; very little weight. |

## Realism Score by Category

- **Field format accuracy:** 9 — Parseable source-shaped records, consistent identifiers, hash widths, and cipher/version combinations; no demonstrated native schema defect.
- **Temporal patterns:** 9 — Variable activity, plausible long sessions, no demonstrated protocol-before-flow ordering, and no overlapping TCP four-tuple lifetimes.
- **Cross-source correlation:** 6 — Strong protocol UID and certificate agreement, but substantial proxy-to-upstream byte-accounting divergence.
- **Behavioral realism:** 8 — Credible protocol/state diversity and administrative traffic; premature DNS refreshes provide only a weak concern.
- **Environmental consistency:** 8 — AD, proxy, DMZ, database, and NAT roles are coherent, while tunnel-versus-interception semantics remain unresolved.

## Recommendations

- If this were synthetic, derive the two CONNECT legs and the access-log tunnel counters from one directional byte ledger. Exclude CONNECT control messages from upstream totals while preserving the same tunneled byte stream on each leg.
- If TLS interception or deliberate buffering/discarding is intended, represent that behavior explicitly in the visible proxy action and counter semantics, with evidence that distinguishes two TLS sessions or identifies unforwarded bytes. Validate the 13:17:01 and 13:04:52 examples first.
- Apply the accounting check specifically to uniquely matched successful no-gap sessions, then model documented exceptions. Avoid forcing equality across captures with actual content gaps or across genuinely distinct intercepted sessions.
- For DNS, if ordinary shared client caching is intended, reuse unexpired answers across application activity; retain premature refreshes where a visible or intentionally modeled cache bypass explains them. The current repeat rate alone does not require removal.
