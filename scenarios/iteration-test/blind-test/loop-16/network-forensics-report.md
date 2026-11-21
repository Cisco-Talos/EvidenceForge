# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 34

## Executive Summary

The supplied network telemetry is mostly production-like: transport accounting, protocol visibility, TLS handshakes, and sensor-local flow references withstand several concrete consistency checks. Repeated successful DNS queries inside still-valid TTLs provide a limited synthetic hint, but application-specific resolvers and cache behavior could explain them; I found no defensible hard contradiction sufficient to identify the dataset as synthetic.

## Evidence For Synthetic

- [weak_signal] Repeated positive DNS lookups sometimes ignore substantial remaining cache lifetimes. In `zeek-core/dns.json`, grouping successful A responses by originating host and exact query produces 1,637 successive-query comparisons, of which 429 occur before the preceding answer's minimum TTL expires. For example, `10.10.1.21` resolves `FILE-LNX-01.meridianhcs.local` to `10.10.2.21` at **2026-11-02 16:45:06.431602 UTC** (`CZNe76OFisSFEfjWeY`) and again **1.152892 seconds later** (`CSLvJt1aroVjbHyyON`), despite both answers carrying **86400-second** TTLs. The first query goes to `10.10.2.11`, the second to `10.10.2.10`; both succeed, with RTTs of 0.050895 and 0.001364 seconds. This resembles repeated activity-triggered resolution rather than a consistently shared host cache, but it is possible with separate processes or resolver implementations. It is a weak indicator, not a protocol violation or proof of generation.

## Evidence For Real

- The three Zeek sensors expose different operational views. `zeek-core/conn.json` has **12,166** rows and substantial DNS, Kerberos, LDAP, SMB, and proxy-client traffic; `zeek-dmz/conn.json` has **9,962** rows dominated by TLS, HTTP/proxy traffic, and unsuccessful connection attempts; `zeek-db/conn.json` has **439** rows, including **305** MySQL connections from `10.10.3.10` to `10.10.4.10:3306`. These differences fit the visible addressing and service placement.
- Failed and incomplete traffic is present alongside successful exchanges. Core connection states include **9,748 SF, 1,617 S0, 161 RSTO, 92 RSTR, and 39 REJ**, plus partial and other states. The DMZ has **2,287 S0** connections. ICMP includes both returned echo traffic and unanswered probes; it is not uniformly successful.
- TLS visibility respects encryption boundaries. Across the supplied SSL records, no TLS 1.3 connection exposes a certificate-chain FUID, and resumed handshakes also do not acquire fresh certificate chains. In contrast, full TLS 1.2 handshakes can reference certificate files and X.509 records. Certificate public-key types agree with the RSA/ECDSA authentication indicated by the checked cipher suites.
- Source-local application joins are coherent. Every DNS, HTTP, SSL, SMTP, and SMB-file row checked resolves to a connection in the same sensor, agrees with its endpoint tuple, and falls inside its connection interval to a 1 ms tolerance. One SMB mapping has no retained conn row; that isolated omission does not establish an authenticity problem.
- The DNS mix includes IPv4 and IPv6 questions, reverse lookups, service discovery, failures, and long-tail types. Core has **2,385 A, 312 AAAA, 158 PTR, 99 SRV, 220 TXT, 9 MX, 5 NS, and 2 SOA** rows; responses include **232 NXDOMAIN, 14 SERVFAIL, and 3 REFUSED**. Examples include ordinary `wpad`/`isatap` failures and successful directory-service records.
- Proxy and SMTP visibility is plausible. Most HTTP is CONNECT control traffic rather than decrypted HTTPS content. Core SMTP includes **56** TLS-upgraded transactions, all with an SSL record sharing their UID; visible STARTTLS transactions do not pretend to expose encrypted message content.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory. The primary analysis parsed all JSON rows in `zeek-core`, `zeek-dmz`, and `zeek-db`, with supporting inspection of the firewall, proxy, and Snort text logs. I did not consult scenarios, ground truth, repository content, other reviewers, external domain ownership, or file modification times.

The observed connection-start window is approximately **2026-11-02 13:00–19:00 UTC**. These are connection start timestamps, not a guarantee that every connection ends before 19:00. I did not infer missing pre-window initiators or post-window endings as defects. The limited six-hour window also cannot establish overnight or weekly traffic behavior.

### Transport states, packet counts, and flow lifetimes

The combined sensor files contain **22,567 connection observations**, with overlap between sensors; this is not a count of unique network sessions. No negative duration was found. IP-byte counters never fall below the corresponding payload-byte counters, no TCP payload exceeds the maximum possible total for its packet count, and no observed direction averages more than 1,500 IP bytes per packet. TCP SF rows have both FIN directions represented in history and at least three packets on each side. No overlapping TCP lifetimes using the same oriented four-tuple were found in the core sensor.

Service durations vary in sensible ways. Core median durations are approximately **0.003 seconds for DNS, 0.021 seconds for Kerberos, 2.069 seconds for LDAP, 3.855 seconds for SMB, 4.556 seconds for SSL-classified connections, 1,183 seconds for RDP, and 1,668 seconds for SSH**. These are heterogeneous service populations, so the medians should not be read as expected durations for every use of a protocol.

A long-lived example is the SSH connection `10.10.3.10:54589 -> 10.10.2.30:22`, seen in `zeek-dmz/conn.json` as `CrkD3E3xyAnPHRdR0o9` at **15:14:56.742677 UTC**, duration **13322.344988 seconds**, state **SF**, with **21,993 originator bytes and 10,228 responder bytes**. The core sensor sees the same tuple and byte totals under its own UID. A multi-hour, lightly used SSH channel is possible; its final close being later than the last connection-start timestamp is not itself an error.

### Cross-sensor observations

Pairing identical oriented five-tuples with start times within two seconds yields **5,224 core/DMZ pairs, 323 DMZ/database pairs, and 111 core/database pairs**. This is a heuristic pairing method and not a claim of global identifier equivalence.

Most paired payload totals agree, while sensor-local UIDs, histories, packet counts, and occasional gaps differ. For example, the TLS flow `10.10.1.21:38937 -> 10.10.3.10:443` appears in core as `ComWVF0Hku1I788OQgy` and DMZ as `CxYVd5Vk2vetqF3Js7U`. Core records 2,942 originator bytes; DMZ records 2,935 and **missed_bytes=7**, with an originator gap marker in its history. Such an explained discrepancy is compatible with sensor capture differences. Sensor timestamp offsets mean subsecond ordering across collectors should not be treated as globally synchronized without calibration.

Complete matching is useful for assessing coherence, but I have not counted completeness itself as evidence of synthesis.

### DNS semantics and timing

All DNS rows join to local conn records and stay within their flow intervals. Query payload lengths satisfy the basic minimum needed for the visible question, and checked response lengths accommodate their questions and A answers. Negative and no-data responses are distinguished: an internal AAAA question can return NOERROR without an address rather than being forced to NXDOMAIN.

Authoritative internal answers have stable TTLs within the same responder/name/answer grouping. For instance, `DC-02.meridianhcs.local` A answers from `10.10.2.11` consistently carry 300 seconds, while `_ldap._tcp.meridianhcs.local` answers from `10.10.2.10` consistently carry two 300-second TTLs. I found no evidence of arbitrary per-query TTL changes in those internal groupings.

The early requery behavior described above is the main reservation. Grouping by host and name does not identify individual application caches, and changing DNS servers can reflect independent resolver clients. Therefore the 429 early repeats are not 429 demonstrated faults. Similar early repeats are less frequent in the DMZ view: **37 of 440** positive A successive-query comparisons. This difference warrants investigation if the logs were generated, but it does not establish impossible DNS behavior.

I did not treat sanitized names or apparent public-IP/domain ownership mismatches as authenticity evidence.

### TLS, certificate chains, and plaintext boundaries

There are **442 core, 3,043 DMZ, and 22 database SSL rows**. Modern TLS 1.3 AES-GCM and ChaCha20 suites coexist with TLS 1.2 ECDHE suites and some AES-CBC. Full, resumed, and failed handshakes are represented.

The **209 core, 1,150 DMZ, and 10 database certificate-chain references** all resolve to files and X.509 records in their respective sensors. Identical certificate fingerprints retain consistent certificate properties. Checked TLS 1.2 responder-byte totals are large enough to carry the exposed certificate bytes. I found no RSA/ECDSA leaf-key mismatch against the negotiated authentication suites.

For example, core SSL UID `C1rWEW59w65cwbI3lw` at **13:05:17.390618 UTC** connects `10.10.2.26:45168` to `10.10.2.21:443`, with SNI `FILE-LNX-01.meridianhcs.local`, TLS 1.2, `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`, and two certificate FUIDs. The leaf is an RSA certificate under the enterprise issuer, and its file/X.509 references are present.

No HTTP record is represented as plaintext on port 443, and no UID appears in both HTTP and SSL in these files. CONNECT traffic to the proxy is separate from the proxy's outward TLS connections, which is a plausible explicit-proxy observation path. This avoids conflating tunnel control bytes with the encrypted application payload.

### Traffic shape and operational context

Core hourly connection counts are **1,561, 3,255, 1,724, 1,926, 1,894, and 1,806** from 13:00 through 18:59 UTC. DMZ counts are **1,227, 2,849, 1,394, 1,783, 1,204, and 1,505**. The shared 14:00-hour increase is a visible burst, not a flat fixed event rate. I cannot assign a business-hours interpretation without an established organizational timezone.

The protocol mix is influenced by explicit proxying: core HTTP contains **2,123 successful CONNECTs**, alongside 403, 407, 502, 503, and 504 responses. Counting these control transactions as ordinary unencrypted web browsing would mischaracterize the HTTPS share. Server-to-database traffic, directory traffic, administrative SSH/RDP, and failed inbound probes give the network plausible operational breadth without requiring every possible infrastructure protocol to be collected.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| weak_signal | Zeek DNS | Core: 429/1,637 successive successful A-query comparisons repeat inside the prior TTL; a concrete example repeats after 1.153 seconds despite an 86400-second TTL | Modest increase only. Separate application caches and resolver behavior remain viable explanations. |

No confirmed hard contradiction, contract gap, or source-native schema defect was established in this network review. The score reflects a mostly realistic dataset with a limited unresolved texture concern, not confidence in its provenance.

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed network records have coherent types, packet/byte relationships, cipher/key relationships, and certificate references.
- **Temporal patterns:** 8 — Service lifetimes and hourly bursts are credible; early positive DNS requeries merit investigation.
- **Cross-source correlation:** 9 — Protocol tuples and flow intervals agree, while some sensor-specific differences have visible gap accounting.
- **Behavioral realism:** 8 — Proxy use, directory traffic, administrative sessions, scans, failures, and database activity form plausible network populations.
- **Environmental consistency:** 9 — Sensor-specific service distributions and encrypted/plaintext observation boundaries fit the visible topology.

## Recommendations

- If this were synthetic, model or document DNS caching at the application/resolver scope, then verify why a host repeats successful long-TTL A questions within seconds. Preserve real exceptions such as independent application caches rather than enforcing one universal host cache.
- If this were synthetic, retain the observed protocol boundaries, certificate reuse, flow accounting, and sensor-local gap behavior during any revision; the supplied records already handle these relationships credibly. A provenance verdict should not be strengthened without additional concrete defects.
