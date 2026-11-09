# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 66
**Synthetic-Confidence Score:** 31

## Executive Summary

The network records are mostly production-like: protocol metadata, TCP state, byte accounting, certificate identities, and overlapping sensor observations remain coherent under cross-checks. I lean Real, with modest confidence because an unusually small-gap-heavy capture-loss distribution is a possible modeling artifact, although it is not a demonstrated contradiction.

## Evidence For Synthetic

- [distribution_texture] Very small TCP content gaps recur across all three sensors and unrelated application families. In `zeek-core/conn.json`, 571 connections report positive `missed_bytes`, with a median of 21 bytes and 318 at 32 bytes or less; the corresponding figures are 50/20.5/31 for zeek-db and 677/22/388 for zeek-dmz. Examples include core line 2684, UID `CnB4XlBKnhA1tuUhzpQ`, with 210,684 responder bytes but only 2 missed bytes; core line 5731 has 309,967 responder bytes and 4 missed bytes. Small missing segments can occur, so this is a limited distribution concern, not an impossible packet-level condition.
- [weak_signal] Similar small-gap texture crosses different workloads: core gaps include HTTP, LDAP, Kerberos, SMB and TLS; database gaps are predominantly MySQL; DMZ gaps are predominantly TLS and HTTP. This could reflect common capture infrastructure, but the repeated texture warrants investigation if the data were synthetic. I did not find a separate high-impact hard contradiction or schema defect to strengthen this indicator.

## Evidence For Real

- All 4,069 DNS, 4,749 HTTP and 3,013 TLS records have a same-sensor connection UID, matching four-tuple, and timestamps consistent with that connection interval under a 100 ms end tolerance. There were no protocol records preceding connection start by more than 1 ms.
- File observations stay within their associated connection byte budgets and lifetimes. For example, `zeek-core/files.json:2` records a 5,359,834-byte SMB spreadsheet read, linked to `Cljp2zAewMfpXP8gvH`; the associated flow supports the transferred volume. Across all 2,442 file records, I found no single-file observed-byte excess over its direction's connection budget.
- TLS visibility respects protocol differences. `zeek-dmz/ssl.json:3`, UID `CeaR6qnHJz1acy2RQoN`, reports TLS 1.3/AES-256-GCM with `ssl_history:"Cs"` and no exposed certificate chain. No TLS 1.3 record in any sensor carries certificate-chain FUIDs. TLS 1.2 records do carry usable chains where appropriate.
- Certificate identities are stable: 1,174 X.509 records represent 182 fingerprints, without conflicting certificate attributes for the same fingerprint. All referenced certificate FUIDs resolve, adjacent chain issuer/subject names agree, and referenced certificates are valid at the observed TLS timestamp. ECDSA cipher selections did not point at RSA leaf keys.
- DNS contains ordinary operational noise and multiple query types. `zeek-core/dns.json:14` is an NXDOMAIN for `isatap.meridianhcs.local`; line 6 is an AD SRV lookup with two domain-controller answers, priorities/weights/ports and matching TTLs. NXDOMAIN, SERVFAIL and REFUSED responses coexist with successful queries.
- Different network zones have different service and state distributions. The database sensor is dominated by port 3306; core traffic includes domain authentication, LDAP, SMB and explicit-proxy connections; the DMZ has substantial HTTPS and incoming scan traffic. These are plausible role differences rather than a single undifferentiated traffic pool.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory, concentrating on every JSON record in the three Zeek sensor directories, plus representative ASA, IDS and explicit-proxy records. Connection counts are 12,170 core, 9,278 DMZ and 446 database, for 21,894 observations, including observations of the same flow at different sensors. This is a roughly six-hour window on 2 November 2026, approximately 13:00–19:00 UTC; it does not support conclusions about overnight or weekly behavior.

I checked protocol UID/four-tuple references, connection-relative timestamps, TCP direction byte/packet accounting, file byte budgets, TLS version/cipher/certificate relationships and repeated certificate identities. Checks passing establish internal plausibility, not provenance or proof of packet capture.

### Connections, timing and accounting

The core state distribution includes 9,879 SF, 1,899 S0, 157 RSTO, 107 RSTR, 45 REJ and smaller partial/midstream states. The DMZ has 6,304 SF and 2,748 S0, consistent with substantial unanswered probing. UDP entries using S0/history D were not incorrectly counted as failed TCP handshakes.

For every TCP record, each direction's reported IP bytes can support its payload plus at least 40 bytes per observed IPv4/TCP packet. There are no positive payload counts on directions with zero packets. Successful TCP histories include both FIN directions. Among established flows without retransmission/gap markers, header-byte differences are multiples of four, consistent with IPv4/TCP header sizing.

Durations vary by workload. Core successful SSH connections have a median duration of approximately 1,559 seconds, versus about 20 ms for port 88 and 4 ms for DNS. `zeek-core/conn.json:1742` is a successful 2,585.452316-second RDP flow from `10.10.1.31:61399` to `10.10.2.27:3389`, with substantially more responder than originator bytes. Such directionality and session length are credible for an interactive desktop connection.

Overlapping sensors use distinct UIDs and have a persistent clock/observation offset around 114 ms. I compared nearby same-four-tuple observations: 43 TLS pairs agreed on version, cipher, SNI, resumed and established flags; 967 DNS pairs agreed on query, qtype, rcode, answers, TTLs and transaction ID. A stable sensor-clock offset is plausible and is not itself evidence of synthesis.

There were 47 HTTP body-length disagreements among 2,232 matched transaction pairs. For example, DMZ HTTP line 4 reports 75,766 bytes while core HTTP line 4 reports 75,716 bytes for the same tuple, URI and transaction depth. Capture gaps exist in the dataset, so disagreement in observed body volume alone is insufficient to establish contradictory application content. I did not score these differences as a separate defect.

### DNS and application mix

Core DNS has 2,239 A, 291 AAAA, 143 PTR, 101 SRV, 307 TXT and small MX/SOA/NS populations. Its 196 NXDOMAIN, 22 SERVFAIL and 7 REFUSED records provide non-success traffic. DMZ DNS has a different composition: 768 A, 107 AAAA, 47 PTR, 8 SRV and 2 TXT, including 130 NXDOMAIN responses. This is a plausible distinction between endpoint/infrastructure resolution and DMZ/proxy resolution.

I did not require every connection to have a fresh DNS lookup; caches, IP literals and pre-window resolution are legitimate. DNS query wire lengths fit the associated UDP originator byte counts.

The raw HTTP count is dominated by CONNECT: 1,927 of 2,249 core transactions and 1,973 of 2,472 DMZ transactions. Therefore, interpreting that count as mostly unencrypted browsing would be misleading. The proxy access records explicitly distinguish CONNECT control-message bytes from tunnel bytes; the first proxy record, for example, includes `byte_scope=connect-control-message`, tunnel-direction byte counts and a tunnel duration. HTTP responses also include authentication demands, policy denials, redirects, partial content and upstream errors.

### TLS and certificates

The DMZ has 1,883 TLS 1.3 observations and 767 TLS 1.2 observations; three records lack a negotiated version. Core has 157 TLS 1.3, 185 TLS 1.2 and three without a version. Database TLS is predominantly TLS 1.2. Negotiated cipher families align with their protocol versions and observed leaf-key types. Resumed and non-resumed sessions both occur.

`zeek-core/ssl.json:1` references the LOG-MON certificate and its issuer. `zeek-core/x509.json:1` and `zeek-db/x509.json:1` represent the same fingerprint, serial, subject and validity period despite different sensor-local FUIDs. That is the expected separation of certificate identity from observation identity.

### Firewall and IDS context

ASA records distinguish admitted SYNs that time out from completed flows. For example, ASA line 11 tears down the first incoming TCP/23 attempt after 30 seconds with zero bytes and `SYN Timeout`; line 7 closes an incoming HTTPS connection with 702,467 bytes and `TCP FINs`. The window contains 7,390 TCP builds and 7,388 TCP teardowns; the small difference does not by itself imply an orphan because closure may fall outside the visible window.

IDS output includes recognizable policy and DNS alert shapes, with tuples that can be found in connection records. I did not infer a required alert for every suspicious connection or treat thin alert coverage as an authenticity defect.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Zeek TCP connection records | 1,298 positive-gap observations across three sensors; many gaps of 1–32 bytes | Modest upward weight: repeated tiny-gap texture deserves scrutiny, but capture behavior remains a viable explanation. |
| weak_signal | Cross-zone capture characteristics | Similar small-gap medians across distinct application mixes | Limited additional weight; correlated with the first indicator and not counted as an independent hard defect. |

No demonstrated hard contradiction, required companion gap, or source-native schema defect materially raised the score.

## Realism Score by Category

- **Field format accuracy:** 9 — Native-looking fields, internally viable TCP accounting and coherent TLS/certificate references.
- **Temporal patterns:** 9 — Workload-dependent durations, failed attempts and session-length variation; no impossible tested protocol ordering.
- **Cross-source correlation:** 9 — Sensor-local identity is preserved while shared protocol facts and certificate identities agree.
- **Behavioral realism:** 8 — Plausible infrastructure, proxy, external HTTPS, interactive administration and scanning mix; no packet capture is available to verify individual behaviors.
- **Environmental consistency:** 9 — Core, database and DMZ traffic have credible and distinct roles within the visible window.

## Recommendations

- If this were synthetic, inspect the model producing `missed_bytes`, especially repeated 1–32-byte gaps in otherwise large streams. Derive losses from concrete packet or segment behavior and collector conditions so small and large gaps have a defensible workload-dependent distribution.
- If this were synthetic, verify that sensor-specific HTTP body-count differences represent particular missing body segments and agree with file-level observed/missing bytes and stream gaps. The visible 75,766/75,716-byte example is explainable, but an explicit shared loss model would make that explanation auditable.
