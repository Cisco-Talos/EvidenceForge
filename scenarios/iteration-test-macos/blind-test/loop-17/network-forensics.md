# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 63

## Executive Summary

The network telemetry is structurally strong: Zeek protocol records join to `conn.json` by UID, observed connection states and TLS versions are varied, and the sampled Snort alerts match Zeek tuples and timestamps closely. The clearest synthetic tell is a recurring family of DNS names with semantic prefixes plus exactly eight apparently random characters, queried across several internal sources and associated with nonstandard TLD alerts; this is suggestive rather than a protocol contradiction, so the score remains below the high-confidence range.

## Evidence For Synthetic

- [distribution_texture] In `zeek-core/dns.json`, 28 queries match the repeated form `<word>-<8 alphanumeric characters>.<cloud|bit|top|to|tk>`; examples include `api-ckm63zwt.cloud` (line 257, 2026-11-02 13:32:11 UTC), `telemetry-l3uwwdar.cloud` (line 274, 13:36:34 UTC), `resolver-nt1w67u4.bit` (line 297, 13:38:42 UTC), and `assets-78tle2r4.to` (line 703, 14:36:39 UTC). The family spans 12 source addresses in the core sensor, with repeated purpose-like prefixes and fixed-length random-looking suffixes. The DMZ sensor independently observes 13 of the same queries, including `update-xdi6sumw.top` (line 247, 15:04:45 UTC) and `cdn-2ybyycle.to` (line 317, 15:36:36 UTC), both returning `NOERROR` with `0.0.0.0`. Domains may be sanitized and sinkhole responses are possible; the indicator is the repeated naming grammar and spread, not domain reputation or the response alone.
- [weak_signal] The Snort alert file repeatedly reports the same small set of TLD-rule families (14 `.cloud`, 13 `.top`, 8 `.bit`, 5 `.to`, and 4 `.tk` detections among 58 alerts; see `snort-core/snort_alert.log`, lines 3–14 and 23–24). This recurring alert texture supports the templated-DNS observation, but the alerts accurately correspond to the DNS/flow records and could represent deliberate threat activity in a real network.

## Evidence For Real

- Zeek UID integrity is clean in the examined sensor datasets: every row in `dns.json`, `http.json`, `ssl.json`, `smb_files.json`, and `smb_mapping.json` with a UID references a `conn.json` UID in its sensor directory. No examined protocol row predates its connection start. This is coherent cross-source behavior, though completeness itself is not treated as synthetic evidence.
- The Snort alerts I checked have the same source/destination addresses, ports, and protocol as Zeek connections, with a consistent roughly 0.21–0.32 second sensor timestamp difference. For example, the first CONNECT alert at `snort-core/snort_alert.log:1` (13:19:39.045946) matches a Zeek connection beginning at 13:19:38.834062; the STUN alert at line 2 (13:24:09.127263) matches 13:24:08.912252. DNS alert examples at lines 3–5 also match the corresponding Zeek connection tuples within about 0.25 seconds.
- Connection behavior has a plausible mix rather than one state repeated everywhere. `zeek-core/conn.json` contains 9,660 `SF`, 1,932 `S0`, 155 `RSTO`, 91 `RSTR`, and smaller counts of rejected, partial, and other states. The DMZ sensor has 6,016 `SF` and 2,687 `S0`, consistent with both successful service traffic and inbound attempts; it also records successful HTTP/TLS and internal application traffic.
- Protocol and service mix fits the visible routed environment: core records include DNS, Kerberos, HTTP, LDAP, SMB, TLS, SMTP, SSH, and RDP; the database sensor is predominantly MySQL (313 service-attributed connections); DMZ observations include HTTP/TLS, DNS and service traffic. The sensor windows span approximately 13:00–19:00 UTC on 2026-11-02.
- TLS records show both TLS 1.2 and TLS 1.3 and a varied set of AES-GCM, ChaCha20-Poly1305, and older TLS 1.2 ciphers. HTTP has a mix of CONNECT, GET, and POST methods and statuses including success, proxy/auth failures, redirects, partial content, and server errors. These are credible protocol-level details.
- Ordinary DNS has a mix of A, AAAA, PTR, SRV, TXT, MX, SOA, and NS queries, with NOERROR, NXDOMAIN, SERVFAIL, and REFUSED outcomes. The queried infrastructure includes internal host and directory-service names as well as external service traffic.

## Detailed Analysis

### Scope and volume

The available network datasets are `zeek-core`, `zeek-db`, and `zeek-dmz`, plus `snort-core/snort_alert.log`. Each Zeek connection dataset covers roughly six hours on Nov. 2, 2026. The core sensor contains 11,956 connections, the DMZ sensor 8,943, and the database sensor 513. The corresponding core and DMZ HTTP logs contain 2,059 and 2,261 rows; DNS logs contain 3,041 and 941; TLS logs contain 306 and 2,520. These volumes and sensor-specific differences are plausible for a routed enterprise environment, although the high DMZ HTTP/TLS volume suggests a web-facing or proxy-rich segment.

### Flow states and service behavior

Most connections end `SF`, while `S0` is also substantial (1,932 core; 2,687 DMZ), with smaller reset/reject and partial states. This is a believable mixture of completed traffic, unanswered attempts, and interrupted sessions. Representative core rows include the DHCP exchange at `zeek-core/conn.json:1` (`10.10.1.41:68` to `10.10.2.10:67`, `SF`, bidirectional packet counts) and a UDP syslog datagram at line 2 (`10.10.2.40` to `10.10.2.21:514`, `S0`, data sent without a response). A database example at `zeek-db/conn.json:1` is a completed MySQL exchange from `10.10.3.10` to `10.10.4.10:3306`, with 3.9 seconds duration and traffic in both directions; subsequent MySQL rows include resets and partial sessions, so database activity is not uniformly successful.

The DMZ has external sources reaching internal web addresses, including an unanswered SYN at `zeek-dmz/conn.json:1` from `185.220.233.25` to `10.10.3.10:8080` (`S0`), alongside established flows. Those external attempts are network-visible and plausible as background scanning. The 405 ICMP records in the core and 299 in DMZ are not treated as anomalous based on source coverage alone.

### DNS and cross-source joins

DNS queries use ordinary resolver port 53 and include A/AAAA lookups, PTRs, SRV service discovery, and a small number of mail/zone-related types. In core, the leading responses are NOERROR (2,811), NXDOMAIN (210), SERVFAIL (17), and REFUSED (3). The first row of `zeek-core/dns.json` resolves `DC-01.meridianhcs.local` to `10.10.2.10`; the next row queries `_ldap._tcp.dc._msdcs.meridianhcs.local` and returns two directory controllers. These records have plausible query metadata, answer/TTL structure, and resolver behavior.

For the repeated random-label DNS family, the core examples at lines 257, 274, and 297 are temporally spaced rather than a tight burst. Some fail with NXDOMAIN/SERVFAIL; others receive a sinkhole-like `0.0.0.0` answer, as in the DMZ examples at lines 247 and 317. The same names appear at both observation points with close timestamps, which fits a shared flow seen at two sensors. The repeated naming pattern is my primary synthetic indicator, but it could also be actual DGA or test-like activity in real telemetry.

### Snort alignment and protocol records

The sampled Snort alerts align to Zeek flow tuples, including DNS and non-DNS traffic. Across the sample, the Snort time is consistently a fraction of a second after the Zeek connection timestamp; this looks like a small sensor observation/clock offset, not an impossible ordering. In particular, alert line 17 reports an SSH scan from `10.10.3.10:47058` to `10.10.2.30:22` at 15:15:02.957423; the corresponding Zeek flow starts at 15:15:02.639053. Alert labels and priorities vary by rule family rather than appearing as a single repeated generic message.

The Zeek HTTP and TLS records retain connection UIDs, with no orphan UIDs in the examined files. Core HTTP includes 1,825 CONNECTs, 224 GETs, and 10 POSTs, with mostly 200 responses plus 403/407 proxy outcomes, redirects, partial responses, and 5xx errors. DMZ TLS includes both TLS 1.2 and 1.3; SNI values include ordinary external services and internal application names. The 10.10.3.10 to 10.10.4.10 MySQL session is observed in both the database and DMZ connection datasets with matching endpoints and near-identical timing, consistent with multiple network observation points.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the score |
|---|---|---|---|
| `distribution_texture` | Zeek DNS, with Snort TLD alerts | 28 core DNS entries match semantic-prefix plus fixed eight-character suffix names under five uncommon TLDs; 13 are also observed in DMZ | The repeated query grammar across internal source addresses is more generator-like than the otherwise varied DNS background. This is suggestive, not a hard protocol contradiction. |
| `weak_signal` | Snort alerts | 58 alerts, with repeated detections from a small TLD-rule set | Reinforces the unusual DNS family but maps cleanly to the network evidence and could be real suspicious traffic. |

## Realism Score by Category

- **Field format accuracy:** 9 — Zeek JSON records use coherent source-native fields and valid connection references; Snort rows are parseable and consistently structured.
- **Temporal patterns:** 8 — Six-hour flow timing and alert alignment look plausible, with a small consistent sensor offset; DNS queries are distributed over the window.
- **Cross-source correlation:** 9 — Protocol UIDs resolve to connection rows, and sampled Snort alerts match Zeek tuple/time evidence.
- **Behavioral realism:** 7 — Traffic includes normal web, directory, mail, SMB, SSH, and database behavior plus failures and scans; the recurring randomized DNS family is the notable tell.
- **Environmental consistency:** 8 — Separate core, DMZ, and database observation points have different service distributions and overlapping internal flows where expected.

## Recommendations

- If this were synthetic, vary or reduce the repeated DNS label grammar and distribute suspicious-domain behaviors more selectively by source and time. The current prefix-plus-fixed-length suffix pattern is visible across unrelated addresses and is more distinctive than the ordinary DNS mix.
- Preserve the current flow/protocol UID joins and Snort-to-Zeek timing relationship; these are strong network-level realism features.
