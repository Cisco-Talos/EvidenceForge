# Network Forensics Analyst — Authenticity Assessment
## Verdict
**Assessment:** Synthetic  
**Verdict Confidence:** 74  
**Synthetic-Confidence Score:** 68

## Executive Summary
The network telemetry is internally coherent: the DNS, HTTP, TLS, and SMTP records I checked all join to a connection UID, and the Zeek views show a plausible proxy path, ordinary enterprise services, and both successful and failed traffic. The strongest synthetic-like signal is a sharply concentrated sweep from `10.10.3.10` across nearly the entire `10.10.2.0/24` range on a repeated set of ports, with single-packet unanswered probes; that can be a real scanner, so the network records support a moderate rather than definitive synthetic assessment.

## Evidence For Synthetic
- **[distribution_texture]** In `zeek-core/conn.json`, around 14:39:55–14:40:15 UTC on 2026-11-02, source `10.10.3.10` probes 253–255 distinct `10.10.2.x` destinations on each of ICMP, TCP/22, TCP/80, TCP/445, and TCP/3306. The bulk TCP probes are `S0` with `orig_pkts: 1` and `resp_pkts: 0`; the ICMP probes are `OTH` with one originating packet and no response. For example, 14:40:07.740 UTC to `10.10.2.70:22` is `S0`, `1/0` packets, UID `CRtyqmSiHpoKhJrGFZ`; 14:40:07.825 UTC to `10.10.2.131:80` has the same one-way pattern, UID `Cc95xLHKh0lIUp08FO`. The sweep's near-complete address and port matrix, compressed into seconds, is unusually regular and materially raises synthetic likelihood, though it is consistent with an intentional production scan.
- **[distribution_texture]** `zeek-dmz/conn.json` contains the same sweep signature over the same address range and ports, with the same per-destination source ports/tuples for almost all shared probes (e.g., 253 shared port-0 tuples, 253 shared port-22 tuples, 254 shared port-80 tuples, and 253 shared port-3306 tuples). Repeated observation at two sensors is plausible for a mirrored route, but the highly complete shared scan matrix is another strong regularity.
- **[weak_signal]** The scan accounts for unusually large groups of low-information one-way connection rows in both sensors. Without a visible scanner inventory or capture topology, I cannot distinguish authored scan workload from a scheduled internal inventory scan.

## Evidence For Real
- **[schema_or_format]** All records examined use coherent Zeek-style fields and valid JSON. `zeek-core` has 12,891 connection records and 3,318 DNS, 2,521 HTTP, 398 SSL, and 79 SMTP records; `zeek-dmz` has 10,334 connections and 1,138 DNS, 2,776 HTTP, and 3,098 SSL records; `zeek-db` has 478 connections and smaller protocol-specific sets. I found no DNS, HTTP, SSL, or SMTP record without a matching connection UID in its corresponding sensor directory.
- **[environment_or_collection_plausibility]** The protocol mix is consistent with an enterprise network: `zeek-core` shows DNS, Kerberos, HTTP proxy traffic, LDAP, SMB, syslog, SMTP, SSH, and RDP; `zeek-db` is dominated by MySQL on TCP/3306 (291 connections), with fewer DNS and administrative/service flows. The DMZ view shows proxy egress and TLS/HTTP to external services.
- **[distribution_texture]** There is nontrivial traffic variation rather than one uniform success-only pattern. `zeek-core/conn.json` includes `SF`, `S0`, `OTH`, `RSTO`, `RSTR`, `REJ`, `S1`–`S3`; DNS includes 241 `NXDOMAIN`, 17 `SERVFAIL`, and 3 `REFUSED` out of 3,318; HTTP includes 407/407-like failures (`403`, `407`, `502`–`504`) alongside 2,363 status-200 responses. TLS records include TLS 1.2 and TLS 1.3, multiple cipher suites, and both resumed and non-resumed sessions.
- **[environment_or_collection_plausibility]** Proxy use is represented in separate legs: core HTTP `CONNECT` rows terminate at `10.10.3.20:8080` with target host/URI metadata, while DMZ SSL rows show `10.10.3.20` opening TLS to destination IPs and preserve SNI (for example `cache.dataforge.net`, `download.windowsupdate.com`, and `registry.npmjs.org`). This is a plausible explicit-proxy observation path.
- **[weak_signal]** DNS includes ordinary enterprise SRV/A/PTR lookups, internal host resolution, public software/service domains, and ordinary negative lookups such as `wpad.local` and `printer01.meridianhcs.local`. The records span roughly 13:00–19:00 UTC, rather than being confined to a single short burst.

## Detailed Analysis

**TCP states and scan behavior.** Across the six-hour window, successful `SF` sessions are the largest state group in both core (10,417 of 12,891) and DMZ (7,240 of 10,334); incomplete `S0` rows are also substantial (1,705 core; 2,531 DMZ), with smaller reset/reject and partial states. The abrupt `10.10.3.10` to `10.10.2.x` sweep is the main concern: it traverses 253–254 distinct destinations on common service ports, with most probes unanswered. Its rows are separated from normal service flows by single-packet counts and the concentrated time window. This resembles a deliberate scan, but the data alone cannot establish whether that scan was authorized or generated.

**DNS and order.** DNS rows use UDP/53 and corresponding connection UIDs. `zeek-core` has a broad query type mix (A 2,427; TXT 315; AAAA 291; PTR 171; SRV 102, plus MX and NS), and response codes include ordinary negative and server-error outcomes. Sampled DNS rows align by UID and timestamp with their UDP connection row; I found no orphaned DNS record. There are frequent DC name lookups and application/public-domain lookups. This is plausible for a business network; the repeated DC lookups alone are not evidence of fabrication.

**HTTP and proxy path.** HTTP is dominated by `CONNECT` (2,306 core and 2,339 DMZ rows), with GET/POST traffic also present. Core rows generally have the proxy as responder on port 8080, while DMZ rows include the proxy-to-destination TLS flows. The path is internally coherent at the protocol level. I did not infer endpoint collection or user ownership from HTTP user agents.

**TLS.** Core SSL rows are mostly TLS 1.2/1.3 (203/194); DMZ SSL rows are mostly TLS 1.3 (2,037) and TLS 1.2 (1,055). Cipher suites include AES-GCM, ChaCha20-Poly1305, and a smaller set of TLS 1.2 CBC suites. Most sessions are marked established, and session resumption occurs in both core and DMZ. `zeek-db` is narrower (40 SSL records, all TLS 1.2), consistent with its smaller observed traffic set. I did not find a TLS-field contradiction in the inspected samples.

**External and business traffic.** DMZ traffic includes common service destinations such as Microsoft, Google, GitHub, PyPI, and public certificate-status services, as well as unusual/blocked or failed requests and direct probes. `zeek-core` also contains a few external SMTP and P2P-style connections. These are plausible individual events but cannot validate authenticity by themselves. `zeek-db` has very little external egress and is principally associated with MySQL traffic to `10.10.4.10:3306` from `10.10.3.10`.

## Synthetic Indicator Summary
| Category | Family | Scope | Score impact |
|---|---|---|---:|
| distribution_texture | Near-complete multi-port sweep with one-way probes | `zeek-core/conn.json`, `zeek-dmz/conn.json`; source `10.10.3.10`, destinations `10.10.2.1–254`, concentrated near 14:40 UTC | +20 |
| distribution_texture | Near-identical scan tuples repeated across two views | `zeek-core/conn.json` and `zeek-dmz/conn.json`; shared source/destination/port tuples | +9 |
| weak_signal | High concentration of unanswered internal probes | Same scan groups; most TCP samples `S0`, one origin packet and zero response packets | +5 |

## Realism Score by Category
- **Field format accuracy:** 9/10 — JSON and Zeek-style fields are coherent; record UIDs resolve to matching connection rows for the protocol files checked.
- **Temporal patterns:** 7/10 — broad six-hour spread and plausible session durations, but the compact, near-complete internal scan is highly concentrated.
- **Cross-source correlation:** 9/10 — DNS, HTTP, SSL, and SMTP rows join cleanly to connection UIDs within each sensor; proxy legs are plausible.
- **Behavioral realism:** 7/10 — realistic service and failure variety, offset by the unusually regular internal multi-port sweep.
- **Environmental consistency:** 7/10 — enterprise services, proxy behavior, and database traffic fit together; the role/authorization of `10.10.3.10` and sensor placement are not established by these network records.

## Recommendations
If these are synthetic logs, vary scan timing, target coverage, and port selection across runs, and include a mix of responsive, filtered, and closed destinations that is not nearly a full subnet-by-port matrix. Preserve the existing UID joins and proxy-leg correlation, which are strong realism features. For a real-data determination, validate whether `10.10.3.10` was an authorized scanner and whether core/DMZ sensors would both observe that same internal sweep.
