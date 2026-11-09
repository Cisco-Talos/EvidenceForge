# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 70
**Synthetic-Confidence Score:** 56

## Executive Summary

The network evidence is technically coherent and substantially production-like, but a repeated hourly concentration of SSH connection endings across different clients and servers makes synthetic generation somewhat more likely. This is a distribution finding, not an impossible protocol relationship: I found no comparable hard contradiction in the checked UID relationships, flow accounting, protocol timestamps, or TLS certificate identities.

## Evidence For Synthetic

- [distribution_texture] SSH close times repeatedly collect immediately after wall-clock hour boundaries. In `zeek-core/conn.json`, among 48 SSH flows with `duration > 60`, 18 end within the first 90 seconds of an hour, and all 18 actually end between second 24.327669 and second 86.731943. These are varied-duration sessions from several clients to several servers. For example, lines 39, 301, 362, 500, and 1000 start between 13:03 and 13:34 UTC, but end at 14:00:38.862716, 14:01:23.635152, 14:00:36.313471, 14:01:12.547276, and 14:00:34.868499. Similar groups recur after 15:00, 16:00, 17:00, and 18:00. A shared hourly administrative policy could explain this, but the repeated boundary-relative truncation is the strongest visible generation-like texture.

## Evidence For Real

- The transport state mix is varied and appropriate to the visible paths. The core has 12,279 connections, including 9,996 `SF`, 1,918 `S0`, 166 `RSTO`, 98 `RSTR`, and smaller `REJ`, `OTH`, and partial-close populations. The DMZ has substantially more unanswered probes: 2,620 `S0` among 9,287 connections. For a concrete example, `zeek-dmz/conn.json:1` records an external SYN to TCP/6379 with `history=S`, one originator packet, no responder packets, and zero payload.
- DNS includes A, AAAA, PTR, SRV, TXT, NS, and MX queries, NXDOMAINs, SERVFAILs, and refusals. In the core, 197 A queries return NXDOMAIN, alongside 266 successful AAAA queries, 135 successful PTR queries, and 100 successful SRV queries. `zeek-core/dns.json:1` is a plausible AD SRV response with two domain-controller targets and matching TTL entries.
- Explicit proxying explains the considerable visible HTTP population. Many HTTP records are `CONNECT` requests to port 8080, rather than implausibly extensive cleartext web browsing. `zeek-dmz/http.json:1` shows a client-to-proxy CONNECT for `www.bing.com`, while `zeek-dmz/ssl.json:1` shows the proxy's separate outbound TLS connection with that SNI.
- TLS versions and ciphers include TLS 1.3 AES-GCM/ChaCha20 and TLS 1.2 ECDHE suites, with resumed and full handshakes. The small database-side TLS sample is predominantly TLS 1.2, unlike the much larger DMZ sample. Certificate visibility is not falsely required for encrypted TLS 1.3 handshakes.
- Checked protocol UIDs join to the local sensor's connection records, and protocol timestamps lie within the corresponding connection interval under a small tolerance. Files' observed byte counts fit within their associated directional flow payload budgets. These are positive consistency checks; completeness itself was not scored as a synthetic indicator.
- Packet loss and imperfect sessions have internally compatible representations. For instance, `zeek-core/conn.json:37` has `history=ShADadfFg` and `missed_bytes=64`; `zeek-db/conn.json:2` has retransmission/gap markers, `missed_bytes=427`, and associated certificate-file visibility with missing bytes (`zeek-db/files.json:1`).

## Detailed Analysis

### Scope and method

I inspected only the supplied data directory. The detailed network checks cover all connection, DNS, HTTP, TLS, file, and X.509 JSON records in `zeek-core`, `zeek-dmz`, and `zeek-db`, with supplementary inspection of the other Zeek protocol families. Counts are sensor-local: observations of the same traffic at multiple sensors are not counted as independent real-world sessions.

The connection start timestamps span approximately 13:00–19:00 UTC on 2026-11-02. This is a six-hour daytime window, so overnight traffic, weekend behavior, and out-of-window session closure cannot be assessed. File modification timestamps, sanitized domain names, selected endpoint event coverage, and the completeness of the suspicious activity were not used as authenticity evidence.

### Transport and protocol populations

The sensors have different distributions that match their apparent network placement. Core traffic includes 3,048 DNS-designated connections, 2,576 Kerberos, 1,101 LDAP, 450 SMB, and substantial proxy HTTP. The DMZ is dominated by TLS, proxy traffic, and unsuccessful probes. The database sensor has 307 MySQL-designated connections among 464 total connections. That is a credible service concentration rather than an identical protocol mix copied across all sensors.

Duration distributions are broad. Core LDAP connections range from about 0.010 to 60.443 seconds, SMB from about 0.036 to 238.493 seconds, and TLS from about 0.014 to 178.826 seconds. Long SSH and RDP sessions coexist with short unsuccessful or reset connections. TCP originator/responder IP-byte counts did not undercut payload-plus-minimum-header budgets in the checked records, and no average per-packet IP size exceeded 1,500 bytes. These checks do not establish that packets were captured, but they remove several common elementary inconsistencies.

The core hourly start-count distribution is uneven: 1,696 at 13 UTC, 3,149 at 14, 1,825 at 15, 1,785 at 16, 2,021 at 17, and 1,803 at 18. I do not treat the burst at 14 UTC as synthetic by itself; scanning or other concentrated activity can produce it.

### Repeated SSH close-time concentration

The close-time finding uses the source-native calculation `end = ts + duration`, with `service == "ssh"` and `duration > 60`, in `zeek-core/conn.json`. The resulting 48 flows have 18 ends in the first 90 seconds of their respective hours, even though their start times and durations vary widely.

At 14 UTC, the five cited flows involve clients `10.10.1.21`, `.31`, and `.32`, and targets `10.10.2.30`, `.40`, `.25`, `.21`, and `10.10.3.20`. At 16 UTC, lines 4920, 5377, 5696, and 6019 end between 16:00:30.474954 and 16:01:06.926012. At 17 UTC, lines 6768, 6863, 7048, 7105, and 7418 end between 17:00:33.075975 and 17:01:26.731943. This is repeated end-time alignment, rather than simply scheduled connections opening at an hourly job boundary.

The other sensor views corroborate the existence and timing of relevant long flows. For example, core line 362 and DMZ line 187 describe the same tuple with sensor-specific UIDs and an approximately 115 ms clock offset; both produce the same boundary-relative ending. This is not a second independent synthetic indicator, but it shows that the cluster is not caused merely by counting duplicate observations in the core statistic.

Possible real explanations include centrally scheduled jobs or enforced administrative session windows. The data does not establish that those explanations are absent. I therefore treat this as a moderately strong distribution artifact, not a hard contradiction, and keep the synthetic-confidence score in the mixed band.

### DNS causality and timing limits

I joined DNS records to their corresponding DNS connections and checked query/response size lower bounds for literal A/AAAA answer sets; those checks did not expose undersized wire representations. Local and external DNS response-time populations differ, and NXDOMAIN/refusal/error responses are present.

Some subsequent connections begin before completion of a nearby same-client DNS transaction. For example, `zeek-dmz/dns.json:591` has query timestamp `1793639933.318044` and `rtt=1.073936`; a connection to a returned address begins roughly 0.870 seconds before that transaction's inferred reply. I do **not** count this as an impossible ordering: a nearby DNS transaction is not proof that the connection depended on that exact lookup, and cached addresses or concurrent requests can explain it. The same restraint applies to repeat queries under long TTLs; application resolver behavior is not established here.

### TLS and file correlation

I checked that TLS 1.2 ECDSA cipher selections with visible leaf certificates use compatible leaf-key types, and that repeated X.509 fingerprints do not change their certificate fields. Neither check produced a contradiction. The TLS 1.3 absence of visible certificate material is compatible with passive observation.

File-flow accounting is also coherent. For example, `zeek-core/files.json:1` identifies a 5,359,834-byte SMB transfer from `10.10.2.21` to `10.10.1.21` using connection UID `CGGIhzcd1Hc4Y0cAlD`; its bytes and timestamps fit within that connection's observed responder direction. Across the checked sensor-local file records, I found no file whose `seen_bytes` exceeded the summed corresponding directional connection payload, or whose timestamp fell materially outside its associated connection interval.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `distribution_texture` | Zeek SSH connection timing | 18 of 48 core SSH flows longer than 60 seconds close within the first 90 seconds of an hour; repeated across five hourly boundaries and varied endpoint pairs | Primary reason to favor synthetic; substantial but explainable scheduling artifact, keeping the score in the mixed band |

No demonstrated hard contradiction, mandatory companion-record gap, or native schema defect was established by this network review.

## Realism Score by Category

- **Field format accuracy:** 9 — Zeek-style values, protocol fields, UID references, and checked byte accounting are coherent.
- **Temporal patterns:** 6 — Varied traffic and session durations, but a conspicuous repeated hourly SSH ending concentration.
- **Cross-source correlation:** 9 — Checked local protocol/connection/file joins are compatible, and repeated sensor observations have plausible clock differences.
- **Behavioral realism:** 8 — Scans, proxy browsing, infrastructure services, lateral administration, and database traffic form a credible mix.
- **Environmental consistency:** 8 — Sensor-specific service distributions and different TLS populations fit the apparent observation paths.

## Recommendations

- If this were synthetic, avoid imposing common wall-clock hour endings on otherwise varied SSH sessions unless the modeled environment explicitly includes a policy or job schedule that explains them. Preserve the observed variation in connection starts and durations while allowing independent session lifetimes and realistic out-of-window continuations.
- If the hourly close clusters are intended to represent real scheduled administration, make their network timing follow the intended operational mechanism: job completion, an explicit session deadline, or an idle timeout anchored to activity. The current repeated end-time placement is the specific feature that warrants improvement or explanation.
