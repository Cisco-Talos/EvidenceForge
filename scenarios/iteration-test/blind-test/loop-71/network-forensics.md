# Network Forensics Analyst — Authenticity Assessment

## Verdict

- **Assessment:** Inconclusive
- **Verdict Confidence:** 62/100
- **Synthetic-Confidence Score:** 54/100

## Executive Summary

The network evidence is coherent across Zeek, ASA, Snort, and proxy logs. Zeek protocol records join to connection records by UID and tuple; all 209 Snort alerts matched a Zeek connection with the same direction and tuple within 0.32 seconds. ASA connection builds and teardowns are nearly balanced. These are strong realism signals, though cross-source consistency alone does not establish authenticity.

I found no hard contradiction. The remaining uncertainty comes from the difficulty of distinguishing well-constructed telemetry from genuine telemetry on these logs alone.

## Evidence For Synthetic

- **[distribution_texture — weak signal]** There is substantial repeated traffic to the same internal services and resolver records: `zeek-core/dns.json` contains 559 queries for `DC-01.meridianhcs.local` and 542 for `DC-02.meridianhcs.local` over roughly six hours. This could reflect normal domain activity, but the recurrence merits scrutiny.
- **[environment_or_collection_plausibility — weak signal]** The same external scanner, `45.33.68.24`, repeatedly probes `10.10.3.10` on management and file-sharing ports. For example, `zeek-dmz/conn.json` records a SYN-only attempt to port 5985 at 13:00:13 UTC, while `fw-perimeter/cisco_asa.log` records its teardown at 13:00:43 with `SYN Timeout`. The behavior is plausible, but its repeated appearance is a weak synthetic indicator without broader collection context.

## Evidence For Real

- **[cross-source — strong realism signal]** All 62 alerts in `snort-core/snort_alert.log` and all 85 in `snort-perimeter/snort_alert.log` matched Zeek connections by direction and tuple within 15 seconds; the largest observed start-time difference was 0.311 seconds. The first `.bit` alert at 13:00:33.990436 also appears in the perimeter Snort log at 13:00:33.841843 and is consistent with the matching DNS flow.
- **[cross-source — strong realism signal]** Every DNS, HTTP, and SSL record in `zeek-core`, `zeek-dmz`, and `zeek-db` had a connection record with the same UID and matching endpoint tuple. No UID or tuple mismatches appeared in those joins.
- **[temporal / lifecycle — strong realism signal]** `fw-perimeter/cisco_asa.log` has 8,641 built TCP/UDP connection IDs, 8,638 teardown IDs, and no teardown without a build. The three builds without observed teardowns are consistent with a bounded capture window; the file ends at 18:59:23.
- **[field format / sensor timing — realism signal]** Proxy and Zeek records show sensible differences between client-facing proxy requests and outbound traffic. At 13:00:42, `PROXY-01.meridianhcs.local/proxy_access.log` records a CONNECT for `widget.clearstream.com` with tunnel byte counts and a 915 ms duration; Zeek sees the client-to-proxy HTTP event and a separate proxy-to-site TLS session.
- **[distribution_texture — realism signal]** The six-hour connection volumes vary by hour rather than following a flat count: `zeek-core/conn.json` ranges from 1,751 to 3,446 connections per hour, while `zeek-db/conn.json` ranges from 66 to 110. The logs contain a mix of successful sessions, failed handshakes, resets, rejects, and one-sided attempts.

## Detailed Analysis

- **Zeek connection states and durations:** `zeek-core/conn.json` contains 12,715 connections, mostly `SF` (10,265), with 1,674 `S0`, 448 `OTH`, and smaller reset/reject/partial-session counts. `zeek-dmz/conn.json` has 9,518 connections with a similar mix. Successful and unsuccessful flows coexist; the logs are not an all-successful stream. Connections longer than 100 seconds are present in both core and DMZ views.
- **DNS:** Core DNS includes common enterprise lookups, A/AAAA/TXT/SRV/PTR traffic, and a smaller number of NXDOMAIN, SERVFAIL, and REFUSED responses. For example, `zeek-core/dns.json` records `_ldap._tcp.meridianhcs.local` at 13:00:02.333512 with SRV answers for both DCs. DMZ DNS includes ordinary service lookups and suspicious TLD queries; Snort alerts for those queries align closely with the Zeek flows.
- **HTTP, TLS, and proxy:** The Zeek HTTP logs are CONNECT-heavy, as expected for proxy traffic, with a smaller set of GET and POST records. The DMZ SSL log has mostly established TLS sessions with both TLS 1.2 and TLS 1.3. Proxy entries distinguish tunnel setup, inspected requests, response sizes, and tunnel byte counts. This gives a plausible explanation for why proxy request counts exceed Zeek HTTP counts.
- **ASA and Snort:** ASA logs include inbound and outbound connection builds, teardown records, NAT translations, denials, and ICMP events. The 13:00:13 external SYN probe to `10.10.3.10:5985` is corroborated by the ASA SYN timeout. Snort alerts cover DNS, scanning, ICMP, STUN, HTTP, and other traffic; the two sensor files have different alert volumes and match their corresponding Zeek views.
- **[contract_gap]** None observed.
- **[hard_contradiction]** None observed.
- **[schema_or_format]** None observed. The inspected Zeek JSON records and text logs had usable fields and timestamps.

## Synthetic Indicator Summary

- **Hard contradictions:** None.
- **Contract gaps:** None.
- **Distribution texture:** Weak signal from repeated DC-name queries and a recurring external scanner; overall event volumes, states, and service mix remain varied.
- **Schema or format:** No issue identified.
- **Environment or collection plausibility:** The repeated scanner behavior is plausible, though its wider context cannot be established from network logs alone.
- **Weak signal:** Strong record-to-record correlation raises confidence in collection coherence but does not determine whether the source telemetry is real or synthetic.

## Realism Score by Category

| Category | Score |
|---|---:|
| Field format | 9/10 |
| Temporal | 8/10 |
| Cross-source | 9/10 |
| Behavioral | 8/10 |
| Environmental | 7/10 |

## Recommendations

- Retain the existing Zeek UID/tuple and Snort/ASA timing alignment; it is internally coherent.
- If increasing confidence is important, review the repeated resolver traffic and scanner cadence against the intended collection window and sensor vantage points. No specific network-log correction is warranted by this review.
