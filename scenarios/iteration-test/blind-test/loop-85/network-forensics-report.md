# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 68
**Synthetic-Confidence Score:** 66

## Executive Summary

The Zeek data has strong protocol and cross-log coherence: DNS, HTTP, and SSL records join to connection records by UID; AD discovery queries and responses look plausible; and TLS versions, SNI, certificates, and OCSP records are broadly consistent.

The main synthetic signal is a sharp, coordinated traffic surge between **14:30 and 14:45 UTC on 2026-11-02**. The `zeek-core/conn.json` count rises to 2,093 in that 15-minute interval from 209–534 in neighboring intervals. `zeek-dmz/conn.json` shows a concurrent rise to 2,029 from 267–718. This concentrated burst warrants scrutiny, but the network logs alone do not establish that it is impossible in production.

## Evidence For Synthetic

- **[distribution_texture] Coordinated 15-minute surge.** `zeek-core/conn.json` contains 2,093 records from 14:30–14:45 UTC, including 1,528 connections initiated by `10.10.3.10`. `zeek-dmz/conn.json` contains 2,029 records in the same interval. The preceding and following 15-minute counts are 209–718 in core and 267–561 in DMZ. This abrupt alignment across sensors is the clearest synthetic indicator.
- **[distribution_texture] Noticeable scan-like activity.** `zeek-dmz/conn.json` has repeated inbound `S0` connections to `10.10.3.10` on ports 22, 80, 443, 445, and 3306. Across the full window, several external sources show repeated attempts to that host, including `185.220.88.13`, `185.220.163.140`, and `185.220.233.25`. This could be ordinary internet scanning, but its concentration alongside the traffic surge adds texture that merits review.
- **[environment_or_collection_plausibility] Uneven sensor volumes.** `zeek-core` has 12,891 connections, `zeek-dmz` 10,334, and `zeek-db` 478. The differing counts are compatible with distinct sensor placements, but the observed topologies are concentrated: for example, `zeek-db/conn.json` has 291 connections from `10.10.3.10` to `10.10.4.10`, mostly MySQL. This is plausible for a proxy-to-database path, though narrow.

## Evidence For Real

- **UID integrity check (not an authenticity clue by itself).** Within each sensor directory, every DNS, HTTP, and SSL UID checked appears in the corresponding `conn.json`. This is concrete internal coherence, but completeness alone does not support either authenticity verdict.
- **[distribution_texture — counterevidence] DNS activity is credible.** `zeek-core/dns.json` includes ordinary A and AAAA lookups, PTR queries, and SRV lookups such as `_ldap._tcp.meridianhcs.local`, along with a modest mix of NXDOMAIN, SERVFAIL, and REFUSED outcomes. The first core DNS record at **13:00:02 UTC** is an SRV lookup that returns both DC hostnames.
- **[environment_or_collection_plausibility — counterevidence] TLS records show varied outcomes.** `zeek-dmz/ssl.json` has 2,037 TLS 1.3 and 1,055 TLS 1.2 records. SNI values include familiar software and business services as well as internal names. Failed or incomplete handshakes also appear; for example, at **13:47:36 UTC**, an SSL record has `ssl_history: "C"` and no negotiated version.
- **[schema_or_format — counterevidence] Certificate and status evidence is varied.** `zeek-dmz/x509.json` contains host and CA certificates with plausible issuer chains and SANs. `zeek-dmz/ocsp.json` contains `good` statuses and update windows. This evidence is consistent with the associated TLS activity.
- **[environment_or_collection_plausibility — counterevidence] Service mix fits observed network roles.** Core traffic includes DNS, Kerberos, LDAP, SMB, HTTP proxy traffic, and mail. The database sensor is dominated by MySQL, while DMZ traffic includes HTTPS, HTTP, proxy connections, and inbound scan attempts. Completed flows have varied durations and byte counts rather than one uniform profile.

## Detailed Analysis

The supplied Zeek directories cover approximately **13:00–19:00 UTC on 2026-11-02**. In `zeek-core/conn.json`, most records are TCP or UDP; common services include DNS, Kerberos, HTTP, LDAP, and SMB. Completed flow durations vary substantially, and the data includes successful connections, incomplete handshakes, resets, and rejections.

DNS records generally precede or coincide with the relevant connection evidence. For example, in `zeek-core/dns.json`, the query for `www.statuspage.com` at **13:00:02 UTC** resolves to `104.18.75.212`; the corresponding DNS and connection records share a UID. Core DNS records also include expected internal service discovery and ordinary negative responses.

The proxy path is represented coherently: HTTP CONNECT records in `zeek-dmz/http.json` target `10.10.3.20:8080`, while TLS records capture subsequent connections from the proxy to named destinations. The **14:30–14:45 UTC** surge is not just a single sensor’s count anomaly; both core and DMZ show a coincident rise. That makes it the principal distribution concern, although the burst includes a mix of proxy traffic, normal services, and scan-like attempts rather than a single identical event repeated throughout.

I found no clear network-level contradiction in connection state, DNS outcomes, protocol/port use, or TLS and certificate fields. The concerns are chiefly about traffic distribution and the concentration of some observed paths, not malformed Zeek records.

## Synthetic Indicator Summary

- **[distribution_texture]** Coordinated 14:30–14:45 UTC connection-count surge in `zeek-core/conn.json` and `zeek-dmz/conn.json`.
- **[distribution_texture]** Repeated inbound `S0` scan-like attempts against `10.10.3.10` on multiple common service ports.
- **[environment_or_collection_plausibility]** Traffic is concentrated on a small number of paths, including `10.10.3.10` to `10.10.4.10` in `zeek-db/conn.json`.

## Realism Score by Category

Scores indicate observed realism, with **10 = highly realistic**.

- **Field format accuracy:** 9/10 — Zeek-style fields, timestamps, and source records are consistent.
- **Temporal patterns:** 5/10 — timestamps and durations vary, but the synchronized 15-minute spike is conspicuous.
- **Cross-source correlation:** 9/10 — DNS, HTTP, SSL, and connection UIDs join within each sensor; this coherent linkage is not counted as a synthetic clue by itself.
- **Behavioral realism:** 7/10 — protocols, states, DNS outcomes, and TLS negotiation behavior are varied and plausible.
- **Environmental consistency:** 7/10 — service mixes fit plausible network roles, with some narrow and concentrated paths.

## Recommendations

- Review the **14:30–14:45 UTC** interval across core and DMZ sources, especially the high connection volume from `10.10.3.10`, to determine whether it represents a plausible workload burst or an overly synchronized generated episode.
- If tuning the data, vary the surge’s onset and duration across sources and spread its activity more naturally across neighboring intervals.
- Preserve the existing DNS, HTTP, SSL, and connection UID relationships; they provide useful protocol-level coherence.
