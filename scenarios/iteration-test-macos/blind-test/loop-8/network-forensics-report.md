# Network Forensics Authenticity Review — Loop 8

## Verdict

**Likely synthetic, with moderate confidence.** The Zeek records are internally coherent and many patterns look production-plausible, but the unusually clean, repeated protocol behavior and one stale TLS chain make synthetic generation somewhat more likely than a direct production capture. The attack-like bursts are plausible in a real incident and are not treated as proof of synthetic origin.

## Verdict Confidence (0–100)

**65**

## Synthetic-Confidence Score (0–100, lower is more production-like)

**62**

## Executive Summary

The network data covers three Zeek views (`core`, `dmz`, and `db`) over roughly six hours on 2026-11-02. It contains realistic internal service traffic, web proxying, external connections, inbound scanning, and multi-protocol activity. Zeek UIDs, tuples, HTTP-to-connection references, and TLS certificate file references are unusually consistent. DNS, HTTP, connection-state, and TLS distributions are varied rather than uniformly successful.

The strongest concern is an established TLS 1.2 record for `www.reddit.com` at 17:38 UTC whose certificate chain includes an R3 intermediate that expired in September 2025. That is a concrete age inconsistency, though the Zeek record alone cannot establish that a client rejected the chain or rule out an alternate trust path. A second concern is the high degree of repeated proxy and TLS behavior. A 14:40–14:50 UTC burst from the visible web host is conspicuous but resembles a plausible compromised-host scan, so it is weak evidence about data origin.

## Evidence For Synthetic

- **Stale certificate-chain member:** `zeek-dmz/ssl.json` records an established TLS 1.2 session to `www.reddit.com` at 17:38:14 UTC. Its referenced chain contains `CN=R3, O=Let's Encrypt, C=US`, whose `not_valid_after` in `zeek-dmz/x509.json` is 2025-09-15. It was expired by about 413 days at capture time. This is a genuine certificate-age inconsistency; successful TLS transport does not prove that a client accepted the chain.
- **Very regular, high-volume proxy pattern:** In the `core` view, five workstation sources each make roughly 262–355 TCP connections to `10.10.3.20:8080` over the window, and CONNECT dominates HTTP records (2,197 of 2,400). Such proxy use is plausible, but the concentration and repeated browser-profile mix look highly templated.
- **Sharp event concentration:** During 14:40–14:50 UTC, the core view contains 1,923 connections, versus a usual 10-minute range mostly around 192–447. Most of the burst is sourced by `10.10.3.10`; the DMZ view shows a corresponding 1,484-connection interval. This could be a real incident, but the narrowly concentrated and strongly synchronized activity is also compatible with a scripted scenario.

## Evidence For Real

- **Plausible network segmentation and roles:** Private subnets contain DNS/AD services (`10.10.2.10` and `.11`), a proxy (`10.10.3.20` on TCP/8080), a web-facing host (`10.10.3.10`), and a database endpoint (`10.10.4.10:3306`). Zeek records show corresponding DNS, LDAP/Kerberos, proxy, inbound web, and application-to-database traffic.
- **Protocol-native connection behavior:** Across `core` and `dmz`, completed `SF` sessions are the majority, with `S0`, reset, reject, and partial states also present. Zero-byte `S0` probes and the associated missing duration fields are consistent with incomplete TCP handshakes. DNS includes successful answers, NXDOMAIN, SERVFAIL, and REFUSED responses.
- **Coherent event linkage:** Every DNS, HTTP, and SSL UID examined has a corresponding connection record in its sensor view; HTTP endpoint tuples match their connection tuples. All referenced TLS certificate IDs resolve to `x509.json` records, and each chain's issuer names match the following certificate subject. This is stronger than mere cross-source completeness because the references and tuple semantics agree.
- **DNS/TLS behavior is mostly credible:** Named TLS sessions have preceding queries for their SNI names in the same sensor view, apart from cases consistent with inbound sessions or cached resolution. Leaf certificate SANs/subjects generally agree with SNI, and nearly all observed certificates are valid at capture time.
- **Plausible hostile traffic:** `zeek-dmz/conn.json` contains repeated inbound zero-payload `S0` attempts from external sources to common exposed ports such as 445, 3389, 135, 5985, and 139. A burst from `10.10.3.10` also fans out across internal services and includes many incomplete connections. These are recognizable scan or compromised-host patterns rather than intrinsically unrealistic records.
- **Useful traffic and error diversity:** The logs contain varied TLS 1.2/1.3 cipher suites, HTTP CONNECT/GET/POST with successes and denials, ordinary update and collaboration destinations, internal TLS, SMTP, SMB, DNS, and MySQL. Traffic rates vary by interval rather than following a single fixed count.

## Detailed Analysis

### Scope and volume

The review used only Zeek data under `data/zeek-core`, `data/zeek-dmz`, and `data/zeek-db`. The core view has 12,532 connection records, 3,158 DNS records, 2,400 HTTP records, 353 SSL records, and 211 X.509 records. The DMZ view has 9,830 connections, 984 DNS, 2,610 HTTP, 2,921 SSL, and 1,168 X.509 records. The database view is smaller, with 449 connections and limited DNS/HTTP/TLS detail. The primary core and DMZ views span approximately 13:00–19:00 UTC.

### Connections and network patterns

Core connection states are predominantly `SF` (10,294), with 1,869 `S0`, plus reset, reject, and partial states. The DMZ view has 6,816 `SF` and 2,805 `S0`, with other states represented. Core traffic includes dense DNS, Kerberos, LDAP, SMB, proxy HTTP, TLS, and service telemetry. DMZ traffic includes TLS and HTTP, inbound web flows, external probes, and application-to-database connections. The observed external scan traffic is concentrated on plausible service ports and normally has no completed handshake.

One concrete high-volume interval occurs around 14:40–14:50 UTC: 1,923 core connections and 1,484 DMZ connections, much of it sourced by `10.10.3.10`. Many of the associated attempts are incomplete and span multiple services; this is consistent with a scan or incident response target, though the concentration is unusually sharp. The full interval’s counts and connection states do not indicate an impossible transport pattern.

A separate external source, `185.70.41.45`, makes 429 connections to `10.10.3.10` on port 443 between 13:29 and 14:20 UTC. Most complete and carry SNI `ehr-portal.meridianhcs.com`. This averages about one new connection every eight seconds over the active period. It is high for one source but plausible for a busy client, proxy, or automated integration; the network records alone do not establish which.

### DNS and HTTP

The core DNS records have expected A/AAAA/PTR/SRV and other query types, with NOERROR dominating and a meaningful minority of negative or error responses. DNS UIDs resolve to connection rows, and the top queries include the domain controllers and internal services. The DMZ view includes public service lookups and certificate-status-related domains. DNS answers do not precede every connection—cached, inbound, and unresolved cases are expected—but named outbound TLS activity generally has a preceding query for its SNI name.

HTTP is dominated by proxy CONNECT transactions, with ordinary GET and POST traffic also present. Statuses include successful tunnels, policy denials, redirects, cache responses, and server errors. HTTP UIDs and endpoint tuples agree with the corresponding Zeek connection records. The CONNECT-to-TLS pairing is strongest in the DMZ view and is temporally close for many records. This is consistent with separate client-to-proxy and proxy-to-destination observations rather than a broken tuple model.

### TLS and certificates

TLS 1.2 and 1.3 both appear, with varied modern cipher suites. Most sessions are established; a small number lack SNI or do not establish, which is plausible. TLS certificate chain IDs point to present X.509 records. For the examined chains, child issuer and next certificate subject agree. Leaf subjects or SANs generally match the SNI, and certificates are mostly within their validity intervals.

The exception is the `www.reddit.com` TLS 1.2 chain at 17:38:14 UTC containing the expired R3 intermediate noted above. This is the strongest synthetic-leaning indicator. It should be treated as an anomaly rather than a definitive impossibility: Zeek reports observed certificates and transport-level establishment, not the client’s certificate-validation result, and alternate trust paths may exist.

## Synthetic Indicator Summary

- **Certificates:** One TLS chain includes an intermediate expired about 413 days before capture. Moderate indicator; not definitive without client validation evidence.
- **Temporal distribution:** A sharp 14:40–14:50 UTC increase is concentrated on one visible web host and appears in both core and DMZ views. Weak-to-moderate indicator because a real scan or intrusion can produce this shape.
- **Repeated behavior:** Proxy CONNECT activity and browser-profile counts are high and repetitive across several endpoints. Weak indicator because enterprise proxy workloads commonly repeat.
- **Structural integrity:** No significant UID, tuple, or certificate-reference breaks found. This weighs against careless synthetic construction.

## Realism Score by Category

| Category | Score / 100 | Notes |
|---|---:|---|
| Connection states and TCP behavior | 84 | Plausible mix of completed, reset, rejected, and incomplete sessions; scan traffic is recognizable. |
| DNS behavior and ordering | 82 | Varied query types and responses; named outbound TLS generally has prior DNS evidence. |
| HTTP and proxy behavior | 78 | Credible CONNECT-heavy enterprise proxy pattern with varied methods and statuses; repeated profile mix is conspicuous. |
| TLS and X.509 | 72 | Good TLS diversity and chain linkage, offset by one expired intermediate in an established session. |
| Timing and volume distribution | 70 | Variable baseline and plausible activity, but one sharply concentrated burst and high single-source web volume stand out. |
| Tuple, UID, and file-reference integrity | 94 | Strong protocol-level linkage and no observed HTTP tuple or certificate-reference mismatch. |
| **Overall network realism** | **78** | Production-plausible network evidence with several synthetic-leaning anomalies. |

## Recommendations

- Replace or explain the expired R3 chain member for the `www.reddit.com` TLS session; if retaining it, include client-side validation evidence to clarify whether an alternate path or acceptance applied.
- Preserve the scan-like activity if it is intended to model an incident, but review the 14:40–14:50 UTC concentration against the desired operational baseline and surrounding service context.
- For greater production-like variation, broaden the mix of proxy session lengths, request cadence, and client behavior while retaining the realistic TLS, DNS, and connection-state diversity already present.
