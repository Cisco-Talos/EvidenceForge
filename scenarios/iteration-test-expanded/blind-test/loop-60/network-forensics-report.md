# Network Forensics Analyst - Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 72
**Synthetic-Confidence Score:** 24

## Executive Summary

The network telemetry is mostly production-like: Zeek protocol fan-out, proxy behavior, ASA NAT/teardown semantics, Snort alerts, web access logs, DNS, TLS/X.509, DHCP, and NTP are mutually consistent. I found no hard contradiction or source-native contract gap; the only synthetic-leaning observations are weak collection-profile questions, not decisive defects.

## Evidence For Synthetic

- **weak_signal / environment_or_collection_plausibility:** OCSP volume is light relative to TLS/X.509 volume: `zeek-core/ocsp.json` has 2 rows and `zeek-dmz/ocsp.json` has 51 rows versus 1,878 combined SSL rows and 738 combined X.509 rows. This is weak only, because OCSP HTTP/file companions are present, e.g. `zeek-dmz/http.json` at `2024-03-18T12:05:45.956Z` has `tags:["ocsp"]` and `resp_mime_types:["application/ocsp-response"]`.
- **weak_signal / distribution_texture:** DMZ NTP visibility is very thin: only two `zeek-dmz/ntp.json` rows over the six-hour window, both to `129.6.15.28` with `poll:2048.0` and `ref_id:".NIST."`. This is not a contradiction because only response-bearing UDP/123 flows appear in `zeek-dmz/conn.json`.

## Evidence For Real

- Zeek protocol contracts are intact: all DNS, SSL, HTTP, SMTP, NTP, and file records I checked have matching `conn.json` UIDs and tuples in the same sensor directory.
- The two Zeek vantage points behave like independent sensors: no cross-sensor duplicate UIDs, file IDs, certificate IDs, or OCSP IDs across `zeek-core` and `zeek-dmz`.
- DNS has realistic variety: `NOERROR`, `NXDOMAIN`, `SERVFAIL`, and `REFUSED`; A, AAAA, PTR, TXT, SRV, NS, SOA, and MX; varied TTLs; and internal AD-style SRV/PTR traffic.
- Perimeter correlation is credible: all 34 Snort alerts have nearby Zeek-DMZ flows, with deltas between about `-0.698s` and `+0.661s`.
- Web access logs correlate with network telemetry: all 758 `WEB-EXT-01.../web_access.log` rows have nearby Zeek-DMZ connections from the same client IP to the web host.

## Detailed Analysis

Zeek connection coverage spans `2024-03-18T12:00:23Z` to `18:00:22Z` in `zeek-core/conn.json` and `12:01:39Z` to `18:00:25Z` in `zeek-dmz/conn.json`. Service mix is plausible: core shows DNS, Kerberos, HTTP proxy, SMB, LDAP, SSH, DHCP, SMTP, and RDP; DMZ shows DNS, SSL, HTTP, MySQL, SSH, scans, and NTP.

DNS is source-native consistent. For example, `zeek-core/dns.json` at `2024-03-18T12:00:44.983Z` resolves `FILE-SRV-01.meridianhcs.local` A to `10.10.2.20`, matching `uid:CdnDE6N5xpIKMHnHw` in `zeek-core/conn.json`. Across DNS rows, I found zero missing conn UIDs and zero tuple mismatches.

TLS/X.509 looks realistic. `zeek-dmz/ssl.json` mixes TLS 1.2 and TLS 1.3, resumed and non-resumed sessions, with certificate chains where expected and no missing X.509 IDs. Certificate files in `zeek-dmz/files.json` use `source:"SSL"`, `mime_type:"application/pkix-cert"`, hashes, chain depths, and matching `conn_uids`.

Proxy behavior is coherent. `PROXY-01.../proxy_access.log` shows explicit proxy CONNECTs and forwarded GET/POSTs; Zeek core sees client-to-proxy HTTP/CONNECT on `10.10.3.20:8080`, while Zeek DMZ also sees proxy-to-origin activity such as the Duo MSI download at `2024-03-18T12:04:41Z` from `10.10.3.20` to `52.84.140.36`.

ASA/Snort alignment is strong. `fw-perimeter/cisco_asa.log` at `Mar 18 12:01:39` builds inbound TCP `156.32.3.55:43920 -> 10.10.3.10:3389`; `zeek-dmz/conn.json` has the corresponding S0 SYN-only flow at `2024-03-18T12:01:39.035Z`. Snort ICMP/HTTPS scan alerts similarly land on matching Zeek flows.

## Synthetic Indicator Summary

| Category | Source Family | Scope | Impact |
|---|---|---:|---|
| weak_signal | OCSP/TLS | Dataset-wide ratio | Low |
| weak_signal | NTP | DMZ only | Low |
| hard_contradiction | Network | None found | None |
| contract_gap | Zeek/proxy/ASA/Snort | None found | None |
| schema_or_format | Network logs | None found | None |

## Realism Score by Category

- **Field format accuracy:** 90 - Zeek, ASA, Snort, proxy, web, SMTP, DHCP, NTP fields are source-native and internally consistent.
- **Temporal patterns:** 86 - Six-hour volume has jitter, varied durations, scan bursts, and plausible app timing.
- **Cross-source correlation:** 92 - UIDs, tuples, web access, Snort, ASA, proxy, files, SSL, and DNS align without impossible reuse.
- **Behavioral realism:** 84 - Traffic mix includes enterprise baseline, proxy browsing, mail, AD, lateral protocols, DMZ scans, and web activity.
- **Environmental consistency:** 85 - Addressing, host roles, local/remote flags, NAT presentation, and service placement are coherent.

## Recommendations

- Increase OCSP/cache diversity if this is synthetic: add more varied revocation-check visibility, including absent checks, cached checks, and issuer-specific patterns.
- Add more DMZ time-sync texture if appropriate: internal NTP, host-specific poll schedules, and occasional non-response UDP/123 connections would make NTP less sparse.
