# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Confidence:** 88

## Executive Summary

The dataset is highly realistic at the connection/protocol level, with coherent Zeek schemas, plausible enterprise proxy traffic, AD/DNS/Kerberos/SMB activity, and credible internet background noise. However, multiple intra-Zeek timing contradictions in SSL certificate/file analysis are not consistent with real packet-derived Zeek output, and the DNS/certificate behavior has several overly templated distributions.

## Evidence For Synthetic

- `zeek-dmz/files.json`: 52 of 372 adjacent SSL certificate-chain file pairs have impossible depth ordering, where `depth: 1` appears before `depth: 0` for the same TLS connection.
- Example: `zeek-dmz/ssl.json` UID `C33JjSJEp0AWt1ptY1O` lists `cert_chain_fuids` as leaf `FH6g94gJoUZ5eapErt` then intermediate `F2RV8BHnQkBOLepna2D`, but `zeek-dmz/files.json` records depth 1 at `2024-03-18T12:07:57.067261Z` before depth 0 at `2024-03-18T12:07:57.095222Z`.
- `zeek-core/files.json` has the same class of issue for UID `CBkUqxfFvebfbvDvFC`: depth 1 `F8DgB2QIpRO56bv7m5` at `14:29:38.314910Z` precedes depth 0 `FKWNyINo2ZYspa0wH4` at `14:29:38.321878Z`.
- `zeek-dmz/x509.json`: 8 X.509 records occur before the corresponding `files.json` certificate object with the same `fuid`; for `FKDMZEzHzprqNF4xDk`, X.509 timestamp is `14:48:05.907142Z`, while the file object begins at `14:48:05.980185Z`.
- SSL certificate timing is overly regular: `zeek-dmz/files.json` has 272 of 372 adjacent SSL cert-depth pairs exactly `0.001` seconds apart; `zeek-core/files.json` has 7 of 9 exactly `0.001` seconds apart.
- DNS responses are simplified: in `zeek-dmz/dns.json`, all 757 successful A responses and all 68 successful AAAA responses contain only literal IP answers, with no visible CNAME/mixed answer chains despite heavy CDN/SaaS traffic.
- Internet scan noise repeats a small template-like port menu across several external origins.

## Evidence For Real

- Zeek UID integrity is strong: every `dns.json`, `http.json`, and `ssl.json` UID in both sensors has a matching `conn.json` row.
- Protocol timestamps are generally coherent with connection timing: DNS, HTTP, and SSL records do not precede their `conn.json` start times or exceed connection duration in checked rows.
- `conn_state`/`history` combinations look source-native: `S0/S`, `SF/Dd` for UDP, `REJ/Sr`, and TCP histories such as `ShADadfF` align with Zeek semantics.
- Sensor placement is believable: `zeek-core` sees internal AD/Kerberos/DNS/SMB/proxy traffic; `zeek-dmz` sees proxy egress, inbound EHR portal traffic, internet scanning, and external TLS.
- TLS modeling includes a realistic distinction where many TLS 1.3 sessions lack exposed cert chains while TLS 1.2 sessions carry `cert_chain_fuids`.
- DHCP leases in `zeek-core/dhcp.json` maintain stable host/IP/MAC mappings with jittered renewals rather than perfectly fixed intervals.

## Detailed Analysis

The strongest authenticity break is inside Zeek's SSL file-analysis timeline. For a TLS certificate chain, `cert_chain_fuids` and file `depth` should reflect visible stream order: the leaf certificate is depth 0, followed by intermediate certificates. Multiple records invert that ordering inside the same connection, which is an impossible visible ordering rather than a missing-precondition problem.

The X.509/file ordering issue is even more direct. An `x509.json` record is derived from the certificate file object, so it should not timestamp before the matching `files.json` object with the same `fuid`. `FKDMZEzHzprqNF4xDk` violates this by about 73 ms, and there are 8 such cases in `zeek-dmz`.

The DNS layer is plausible but compressed. Real enterprise recursive DNS for CDN-heavy browsing typically exposes some CNAME chains, mixed answer sections, NODATA/negative AAAA behavior, and messier TTL distributions.

## Realism Score by Category

- **Field format accuracy:** 7/10 — Zeek fields are mostly accurate, but SSL/X509 timestamp ordering breaks source semantics.
- **Temporal patterns:** 5/10 — Broad timing looks plausible, but certificate-chain ordering and exact 1 ms gaps are synthetic tells.
- **Cross-source correlation:** 8/10 — Core/DMZ relationships are coherent without relying on completeness as evidence.
- **Behavioral realism:** 7/10 — Enterprise proxy, AD, scan, and DNS activity are believable, with some templated scan/DNS patterns.
- **Environmental consistency:** 8/10 — Internal topology and host roles are consistent; DNS and certificate modeling are the weaker areas.

## Recommendations

Fix SSL/X509 generation so `files.json` depth order, `ssl.cert_chain_fuids`, and `x509.json` timestamps are derived from one ordered packet/stream timeline. Add validation invariants for "x509 cannot precede file" and "cert depth N+1 cannot precede depth N" within a connection.

Improve DNS realism with CNAME chains, multi-RR answer sections, NODATA/negative AAAA cases, resolver cache effects, and less flattened CDN resolution. Vary internet scan actors by tool family, retry behavior, port selection, and TCP option/header profiles rather than reusing the same small scan menu.
