# Network Forensics Analyst - Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 72
**Synthetic-Confidence Score:** 24

## Executive Summary

The network telemetry looks mostly production-like: Zeek UID relationships are coherent, protocol timing is plausible, ASA/Snort perimeter activity aligns with Zeek DMZ observations, and DNS/TLS/HTTP behavior has realistic variety. I found weak texture concerns, but no hard contradictions, impossible ordering, generator leaks, or source-native network impossibilities.

## Evidence For Synthetic

- `weak_signal` / `distribution_texture`: Some proxy/web activity uses finite repeated pools, e.g. repeated exact CONNECT transactions such as `ctldl.windowsupdate.com:443` in `zeek-core/http.json` and `zeek-dmz/http.json`. This is explainable for proxy logs and update traffic, so low impact.
- `environment_or_collection_plausibility`: NTP visibility is sparse: only 2 rows in `zeek-dmz/ntp.json` and no core NTP rows, despite many hosts. This is plausible if hosts use domain time or NTP is outside sensor visibility.
- `weak_signal`: Certificate extraction is very complete where SSL files are present, while `ssl.json` lacks some common Zeek policy fields such as cert-chain FUIDs/validation fields. This can be a Zeek policy/export choice, not a contradiction.

## Evidence For Real

- Zeek protocol logs consistently reference parent connections: DNS/HTTP/SSL/SMTP/file rows join cleanly to `conn.json`; no missing parent UIDs for those families.
- Timing is source-native plausible: HTTP and SSL rows occur after TCP connection starts; DNS/NTP UDP rows align with request-response connection durations.
- DNS behavior has production texture: A/AAAA/PTR/TXT/SRV mix, NXDOMAIN/SERVFAIL/REFUSED responses, WPAD/ISATAP noise, varied TTLs, and internal authoritative answers.
- TLS is not one-note: TLS 1.2 and 1.3 both appear, multiple cipher suites occur, resumption is partial, SNI values vary, and X.509 issuer/subject chains are diverse.
- Perimeter traffic looks credible: ASA built/teardown/NAT/deny/ICMP messages are mixed, Snort alerts correspond to observed scan-like DMZ traffic, and external scanner intervals are jittered rather than fixed.
- File extraction stays within parent flow byte budgets, with some SMB missing-byte texture and no impossible file/conn byte contradictions.

## Detailed Analysis

I reviewed only `/private/tmp/research-data-A0rZCu/dataset`. The collection window is `2024-03-18T12:00:00Z` to `2024-03-18T18:00:00Z`.

`zeek-core` contains 7,455 conn rows, 3,341 DNS rows, 1,121 HTTP rows, 97 SSL rows, 53 SMTP rows, 319 file rows, 73 DHCP rows, and 71 X.509 rows. `zeek-dmz` contains 6,606 conn rows, 2,006 DNS rows, 1,323 HTTP rows, 1,791 SSL rows, 725 file rows, 51 OCSP rows, 2 NTP rows, and 667 X.509 rows.

UID integrity is strong. DNS, HTTP, SSL, SMTP, NTP, and file records join back to visible parent `conn.json` rows. HTTP timing offsets are positive, with core HTTP offsets from about 0.0017s to 4.18s after connection start; SSL offsets are similarly positive. DNS rows have zero offset from UDP conn start, which is normal for Zeek request timestamps.

DNS is realistic enough to support a real-data verdict. `zeek-core/dns.json` includes A, AAAA, PTR, TXT, SRV, NS, SOA, and MX queries, with 2,919 NOERROR, 408 NXDOMAIN, 12 SERVFAIL, and 2 REFUSED responses. Queries such as `wpad`, `isatap`, `_ldap._tcp.meridianhcs.local`, internal hostnames, Microsoft/Ubuntu/package domains, and reverse lookups all fit enterprise traffic.

TLS also looks credible. `zeek-dmz/ssl.json` has 1,258 TLSv13 and 533 TLSv12 rows, with several ciphers and mixed resumed/non-resumed sessions. High-volume `ehr-portal.meridianhcs.com` traffic from external clients aligns with `WEB-EXT-01.meridianhcs.local/web_access.log`, which has mixed 200/301/302/403/404/429/500 statuses and normal web asset/cache behavior.

Perimeter records are plausible. `fw-perimeter/cisco_asa.log` has paired built/teardown activity, dynamic NAT translations, deny records, and ICMP lifecycle records. `snort-perimeter/snort_alert.log` has 34 alerts, including repeated rapid HTTP/HTTPS scan alerts from `185.70.41.45`, which also appears as a high-volume Zeek DMZ source to port 443.

## Synthetic Indicator Summary

| Category | Affected Source Family | Scope | Score Impact |
|---|---|---:|---:|
| `weak_signal` / `distribution_texture` | Zeek HTTP / proxy | Repeated exact proxy CONNECT shapes | Low |
| `environment_or_collection_plausibility` | Zeek NTP | Very sparse NTP visibility | Low |
| `weak_signal` | Zeek SSL/X.509 | Complete cert extraction with limited SSL policy fields | Low |

## Realism Score by Category

- **Field format accuracy:** 88 - Zeek JSON, ASA, Snort, proxy, and web formats are source-native enough, with normal quirks like `304 -`.
- **Temporal patterns:** 84 - Connection/protocol ordering is coherent and scan/DHCP timing is jittered.
- **Cross-source correlation:** 86 - Zeek, ASA, Snort, proxy, web, and endpoint flow tuples agree without impossible ordering.
- **Behavioral realism:** 82 - DNS, TLS, proxy, scan, web, DHCP, SMTP, and file-transfer behavior are diverse and plausible.
- **Environmental consistency:** 78 - Network roles are mostly consistent; sparse NTP is the main mild plausibility question.

## Recommendations

- Add or preserve source-policy context for Zeek SSL/X.509 optional fields so complete certificate extraction is not mistaken for synthetic uniformity.
- If this were being tuned for production-likeness, include a slightly broader NTP/time-sync visibility profile or document why only DMZ NTP is visible.
- Keep the current jittered DHCP, scan, and proxy-origin timing patterns; they are among the stronger realism signals.
