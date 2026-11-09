# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Real  
**Verdict Confidence:** 67  
**Synthetic-Confidence Score:** 27

## Executive Summary

Zeek records show varied and internally consistent network activity across core, DMZ, and DB sensors, with coherent DNS, HTTP, TLS, and connection pivots. A dense internal scan is conspicuous but corroborated by endpoint FLOWs from `nmap` on WEB-EXT-01.

## Evidence For Synthetic

- [weak_signal] At 14:39–14:40 UTC, 10.10.3.10 probes roughly 253–254 addresses in 10.10.2.0/24 across TCP 22, 80, 443, 445, 3306 and ICMP. Endpoint evidence identifies nmap and corroborates the scan.

## Evidence For Real

- `zeek-core` has 12,891 connections with completed, unanswered, reset, rejected, and partial states; DMZ also varies.
- DNS A/AAAA/PTR/SRV/TXT and NXDOMAIN activity is plausible. DNS/HTTP/TLS companion UIDs map to matching connection endpoints.
- HTTP includes proxy CONNECT, ordinary methods, and varied status codes. TLS includes 1.2/1.3, multiple suites/SNI, and incomplete handshakes.
- WEB-EXT-01 eCAR records `nmap -sn 10.10.2.0/24` and `nmap -Pn -sT -p 22,80,443,445,3306 10.10.2.0/24` under PIDs 2705081 and 2705106 with matching outbound flows.

## Detailed Analysis

Reviewed `conn.json`, `dns.json`, `http.json`, and `ssl.json` in zeek-core, zeek-db, and zeek-dmz. Core spans 13:00–18:59 UTC with 12,891 connections, 3,318 DNS, 2,521 HTTP, and 398 TLS rows; DMZ has 10,334 connections, 1,138 DNS, 2,776 HTTP, 3,098 TLS. Core DNS includes 2,427 A, 291 AAAA, 171 PTR, and 102 SRV; 241 NXDOMAIN. HTTP is mainly proxy TCP/8080 CONNECT. The scan has mostly S0 TCP and OTH ICMP outcomes and a visible process owner.

## Synthetic Indicator Summary

- `weak_signal` — network connection volume — a short multi-port subnet scan — small upward pressure, limited by endpoint corroboration.
- No hard contradiction or broken sampled Zeek UID/tuple relationship observed.

## Realism Score by Category

- **Field format accuracy:** 9/10 — Zeek fields/protocol rows are well formed.
- **Temporal patterns:** 8/10 — Varied timing; scan has a visible process owner.
- **Cross-source correlation:** 9/10 — DNS/HTTP/TLS UIDs match conn records.
- **Behavioral realism:** 8/10 — Service mix, outcomes, and probes are plausible.
- **Environmental consistency:** 8/10 — Core/DMZ/DB paths fit roles.

## Recommendations

No concrete network-log correction indicated.
