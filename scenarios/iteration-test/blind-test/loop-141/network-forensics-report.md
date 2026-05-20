# Network Forensics Analyst — Authenticity Assessment
## Verdict
**Assessment:** Synthetic
**Confidence:** 78

## Executive Summary
The dataset is quite realistic at the macro level: Zeek connection mix, proxy behavior, TLS/X.509 handling, DNS noise, external scans, and OS-aware source-port behavior all look deliberately modeled. The deciding issue is a systematic Zeek-native DNS timing inconsistency where `dns.json` timestamps, `dns.rtt`, and same-UID `conn.json` windows cannot all be true for one-query/one-response UDP DNS flows.

## Evidence For Synthetic
- `zeek-dmz/dns.json:225` UID `C0fF31oVySZ6SG6ha` has `dns.ts=2024-03-18T14:59:48.825658Z`, `rtt=0.100923`. Matching `zeek-dmz/conn.json:1836` has `conn.ts=2024-03-18T14:59:48.730463Z`, `duration=0.100923`, `orig_pkts=1`, `resp_pkts=1`. For Zeek-style DNS, the DNS transaction timing is shifted inside/outside the connection window.
- Same pattern in `zeek-core`: `zeek-core/dns.json:724` UID `C73HoC6uHP9HDdh0U` has `dns.ts=2024-03-18T17:03:24.698902Z`, `rtt=0.322141`; matching `zeek-core/conn.json:3847` has `conn.ts=2024-03-18T17:03:24.603120Z`, `duration=0.322141`, one packet each direction. If `dns.ts` is query time, the response occurs after the conn window; if it is response time, the log semantics differ from normal Zeek.
- This is systematic, not isolated: 526 of 868 one-request/one-response DNS pairs in `zeek-core` and 956 of 1,033 in `zeek-dmz` show this timing defect under same-UID comparison.
- Background scan traffic in `zeek-dmz/conn.json` is plausible but somewhat pool-shaped: 856 external `S0` SYN-only records distribute across a small fixed port set with near-balanced counts: 443/125, 3389/115, 25/114, 80/112, 23/106, 22/103, 445/91, 8080/90. Real background scan traffic is often more campaign-skewed.

## Evidence For Real
- Zeek coverage has credible enterprise texture: `zeek-core/dns.json` includes WPAD and ISATAP NXDOMAINs, PTR/MX/NS/SOA lookups, internal authoritative responses, recursive external answers, SERVFAIL/REFUSED, and high-volume TXT activity.
- TLS/X.509 behavior is mostly source-native. TLSv12 non-resumed sessions carry `cert_chain_fuids`; resumed sessions and TLSv13 sessions generally do not. `zeek-dmz/ssl.json:1` for `registry.npmjs.org` links cleanly to certificate files and `zeek-dmz/x509.json:1-2`.
- Proxy behavior is coherent: successful `CONNECT` records in `zeek-dmz/http.json` are followed by matching proxy-originated TLS/SNI records, while failures show 403/407/502/503/504 variation.
- Endpoint OS/source-port behavior looks thoughtful: Windows workstation IPs use ephemeral ports above 49152, while Linux-like hosts use 32768+ ranges.
- Internet-facing web noise looks real: `zeek-dmz/http.json:402-407` shows `116.181.114.1` probing `/phpmyadmin/`, `/wp-login.php`, and `/xmlrpc.php` against `ehr-portal.meridianhcs.com`.

## Detailed Analysis
The network corpus spans roughly six hours on 2024-03-18, with 4,641 core connections and 6,356 DMZ connections. The service mix is believable: core traffic is dominated by Kerberos, DNS, SMB, LDAP, HTTP proxying, SSH, and some RDP/database traffic; DMZ traffic includes proxy `CONNECT`, TLS, web portal traffic, public DNS, inbound scans, and server egress.

The strongest flaw is DNS timing. For one UDP DNS request and one response, the connection start, duration, DNS timestamp, and DNS RTT should describe the same two packets. Here, same-UID records often set `conn.duration == dns.rtt` but place `dns.ts` after `conn.ts`, causing the DNS transaction to extend beyond the visible conn window. That is a concrete source-native contradiction, not merely “too complete” correlation.

TLS and HTTP are much stronger. Certificate chains, validity windows, OCSP file references, proxy failures, inbound scanner paths, and SNI/domain alignment are all convincing. The dataset also includes good environmental artifacts: WPAD/ISATAP noise, stale-looking DNS failures, DHCP renewals, SMB file transfers, public resolver use from DMZ systems, and realistic source-port ranges.

Behaviorally, the dataset feels modeled but not crude. The external scan distribution and some repeated tool/user-agent/domain combinations feel selected from curated pools, yet they do not by themselves prove synthesis. The DNS timing issue does.

## Realism Score by Category
- **Field format accuracy:** 7/10 — Most Zeek fields are shaped correctly, but DNS/conn timing semantics are wrong at scale.
- **Temporal patterns:** 5/10 — General activity timing is varied, but same-UID DNS timing has impossible ordering.
- **Cross-source correlation:** 7/10 — Correlation is rich and mostly coherent; DNS timing breaks source-native consistency.
- **Behavioral realism:** 8/10 — Proxy use, scans, DNS noise, TLS, and enterprise service mix are believable.
- **Environmental consistency:** 8/10 — Host roles, internal domains, source ports, certificates, and traffic zones mostly agree.

## Recommendations
- Fix Zeek DNS timestamp semantics first: for single-query UDP DNS, align `dns.ts` with the query/connection start and keep `dns.rtt` within `conn.duration`.
- Add validation that recomputes same-UID DNS transaction windows from `conn.json` and fails on impossible ordering.
- Make scan campaigns less pool-uniform: vary port preference, scanner cadence, target selection, and success/failure patterns by source.
- Preserve the current TLS/X.509, proxy, OS ephemeral-port, and enterprise DNS artifact modeling; those are strong realism anchors.

