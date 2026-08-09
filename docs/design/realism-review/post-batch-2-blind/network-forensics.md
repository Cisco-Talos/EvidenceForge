# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 96
**Synthetic-Confidence Score:** 94

## Executive Summary

The dataset is unusually sophisticated and preserves many realistic Zeek, TLS, DNS, firewall, and endpoint correlations. However, a decisive HTTP accounting contradiction—nonzero bodies on every HEAD response, often copied exactly into the TCP response-byte counter with no room for HTTP headers—plus highly generator-like DHCP and timing distributions makes synthetic origin substantially more likely than sanitized production data.

## Evidence For Synthetic

- **[hard_contradiction] HEAD responses contain impossible bodies and TCP accounting.** All 10 `method:"HEAD"` records in `ZEEK-BO-CORE/http.json` have nonzero `response_body_len` values from 136 to 478. A HEAD response has no message body. For 9 of the 10 UIDs, `conn.json` has `resp_bytes == response_body_len`, leaving zero TCP payload bytes for the HTTP status line and headers.
  - UID `Ciocp6L1Ok38JBVHZvt`, `185.199.110.42:58096 -> 10.44.30.10:80`: at `1715691340.183806`, HEAD `/cgi-bin/test-cgi`, status 301, `response_body_len=437`; the connection has `resp_bytes=437`, `missed_bytes=0`.
  - UID `ClgoQT14wXDG0mNwg8`: HEAD `/phpinfo.php?debug=622`, body 229, connection response bytes 229.
  - UID `Ckb3RxoqpnVxBLdlQ`: HEAD `/sitemap.xml`, body 478, connection response bytes 478.
  - UID `CwDPpWX0MDEFEegYGo`: HEAD `/cgi-bin/test-cgi`, body 437, connection response bytes 437.
  - The same values also appear in `WEB-BO-01.northstar-branch.local/web_access.log`, indicating a body/response-size value was copied across renderings rather than derived from a realizable HTTP exchange.

- **[distribution_texture] DHCP renewals resemble independent uniform sampling, not stable client packets and T1 timers.** The 47 rows in `dhcp.json` are all `REQUEST,ACK` with `lease_time=3600`, but per-client intervals range from 1,623.9 to 1,978.4 seconds, approximately a broad ±10% band around 1,800 seconds. Their one-request/one-ACK LAN durations span 0.012025–0.496072 seconds with a mean of 0.24245 seconds, while request payloads vary from 292–357 bytes and ACKs from 304–374 bytes despite stable client, MAC, server, address, and message types.
  - `WS-NKAPOOR-01` renews at `1715688111.488239`, `1715689853.437352`, and `1715691794.519494`, producing successive gaps of 1,741.9 and 1,941.1 seconds. Its corresponding request/response byte pairs change from 336/331 to 336/317 to 356/351.
  - Real renewals from the same DHCP stack normally retain a much more stable option layout and packet length; broad independent variation across timing, packet size, and response delay is characteristic of sampled synthetic fields.

- **[distribution_texture] Per-event cross-sensor timestamp offsets fluctuate around both sides of zero.** All 38 IDS alerts have exact Zeek tuple matches, but the apparent clock offset is independently variable. For three consecutive ICMP packets from `45.33.74.51 -> 10.44.30.10`, IDS-minus-Zeek offsets are −11.718 ms (`C5cujXijrNrK2QWAeq`), −20.182 ms (`CtrvfjapZ2y1KnYzZb`), then +26.705 ms (`C2XY7XXVYJ73eSJm7rm`) within 0.2 seconds. Across the 21 ICMP alerts, offsets span roughly −117 to +113 ms. Separate sensors can have clock skew, but the skew for the same packet path should be comparatively stable rather than changing sign and tens of milliseconds almost immediately.

- **[distribution_texture] Identical OCSP requests receive strongly varying synthesized sizes while parsed response state remains identical.** Four `ocsp.digicert.com` requests for serial `067735243AC718F49CE5D3F13F724D62` use the same encoded request, issuer hashes, `thisUpdate=1715687609`, and `nextUpdate=1716037070`, but the corresponding complete HTTP files have sizes 2060, 902, 1793, and 2277 bytes:
  - `FcWo0UfSYp8ecXCANN` / UID `CL9OEU7zCq1hIJzNNF`
  - `F5b3IALWzpeYfD1aiio` / UID `CMVZT61ltf5ri5wW5A`
  - `FX69v59zOA5kHCLzNb` / UID `CSsEhnzWm6gCSp2yxA`
  - `FXm1Xj8pjOIL102bu` / UID `C3Ok8BR9ua1U1uDn4k`

  OCSP responses can change, but this much size variation for the same request, responder, parsed validity interval, and status is implausibly random.

- **[weak_signal] One inbound RDP attempt uses TEST-NET source `198.51.100.77`.** UID `C3Z7aGASex0KKJ8h9u` and ASA connection `1226110` show this address reaching `10.44.10.25:3389`. Because production data may have had addresses sanitized, this was explicitly given little weight.

## Evidence For Real

- TLS behavior is impressively coherent. All 251 two-certificate chains have exact leaf-issuer to intermediate-subject matches, every observed leaf SAN covers its SNI, and repeated certificates preserve fingerprint, serial, validity, hash, and file size.
  - The 123 full TLS 1.2 handshakes for `portal.northstarclaims.net` all use the same leaf fingerprint `ce24478522ba9d9a6f533c378239570c32ff30f9`.
  - Public client IPs preserve stable TLS fingerprints: all 46 connections from `103.197.57.73` use TLS 1.3/AES-256-GCM; all 19 from `186.244.203.224` use TLS 1.2/ECDHE-RSA-AES-128-GCM.
  - Repeated proxy-origin hostnames likewise retain one version/cipher combination per hostname.

- DNS has realistic protocol texture: 645 A, 187 AAAA, 124 PTR, and 51 SRV queries; 91 NXDOMAIN, 7 SERVFAIL, and 1 REFUSED response. Internal forward and SRV responses correctly set `AA=true`, while recursive external and PTR traffic generally has `AA=false`. Search-suffix failures, WPAD/ISATAP noise, decreasing cached TTLs, reverse lookups, and occasional randomized-looking failed domains all resemble production resolver behavior.

- TCP state and scan texture are plausible: 4,731 SF, 1,141 S0, plus smaller RSTO, RSTR, REJ, S1/S2/S3, and OTH populations. Unanswered SYNs preserve source-specific TCP option lengths—for example, scanner `37.75.195.175` generally produces 48-byte SYNs, `38.186.148.245` 60-byte SYNs, and `175.29.181.188` 40-byte SYNs—consistent with different TCP stacks or raw scanners.

- UID and tuple correlation is strong without being unrealistically complete. All 1,007 DNS, 700 HTTP, and 1,030 SSL records resolve to a unique `conn.json` UID with matching tuple; child protocol timestamps fall inside their connection intervals. All 768 file records link to existing connection UIDs, and all 537 X.509 records link to file IDs with SHA-1 equal to the certificate fingerprint.

- Firewall behavior includes realistic source-specific gaps. There are 2,469 paired ASA TCP build/teardown records with coherent duration and tuple semantics, but 293 builds lack an exact Zeek tuple/second match. Connection IDs span `1206840`–`1254707` with large gaps, as expected when only selected traffic is in the slice. NAT mappings avoid overlapping collisions, and some ASA byte counters exactly match Zeek IP-byte totals while others differ modestly, consistent with capture-point differences.

## Detailed Analysis

The network slice covers approximately 12:00–18:00 UTC and contains 6,115 Zeek connections, 1,007 DNS transactions, 700 HTTP records, 1,030 TLS sessions, 47 DHCP renewals, 28 OCSP responses, 537 X.509 records, 768 file records, 6,700 ASA messages, and 38 IDS alerts.

The environment is coherent: `10.44.20.10` behaves as the AD DNS/Kerberos/LDAP server, `10.44.20.20` as a file server, `10.44.20.30:8080` as an explicit proxy, and `10.44.30.10` as the public web/DMZ host. Internal traffic includes Kerberos, LDAP, SMB, DNS, DHCP, SSH, RDP, and server-to-proxy activity. Public traffic combines ordinary web browsing, broad background scans, ICMP probes, and a concentrated Nikto run.

The HTTP HEAD failure is decisive because it survives three correlated views. At 12:55:40 UTC, UID `Ciocp6L1Ok38JBVHZvt` begins at `1715691339.887169`; `http.json` records a HEAD request at `1715691340.183806` with a 437-byte body, `web_access.log` also reports 437 bytes, and `conn.json` reports exactly 437 response payload bytes. Even if the web-server access field were total transmitted bytes rather than body bytes, the Zeek `response_body_len` remains impossible, and equality with the entire TCP response excludes any status line or response headers. The same construction repeats across nine separate HEAD UIDs.

The DHCP population further suggests a generator using uniform ranges. Every successful renewal consists of exactly one request packet and one ACK packet, yet both payload lengths independently change on almost every renewal. Each host has 11–12 renewals, all around 30 minutes but with standard deviations of 104–115 seconds. LAN ACK latency is likewise spread almost uniformly across half a second. These three simultaneous forms of randomization lack a common network or client-state explanation.

The data otherwise shows unusually careful correlation. TLS 1.3 sessions correctly omit visible certificate chains, resumed TLS 1.2 sessions omit chains, full TLS 1.2 sessions contain one or two certificates, repeated certs preserve all hashes, and all OCSP serials match observed certificates. This strongly argues for a high-quality synthetic generator rather than simple templates.

The reserved RDP source was not treated as decisive because sanitization could intentionally map a real address into TEST-NET space. Likewise, complete UIDs, broad coverage, and concise attack sequences were not treated as synthetic indicators.

## Synthetic Indicator Summary

| Category | Source/scope | Impact |
|---|---|---|
| `hard_contradiction` | 10 HEAD rows in `http.json`; 9 matching `conn.json` records with body bytes equal to all response bytes | Decisive |
| `distribution_texture` | 47 DHCP renewals across four workstations | High |
| `distribution_texture` | 21 exact ICMP IDS/Zeek matches and thousands of endpoint-flow correlations | Moderate |
| `distribution_texture` | Four identical OCSP certificate requests with 902–2277-byte responses | Moderate |
| `weak_signal` | TEST-NET source on one inbound RDP tuple | Low; discounted for possible sanitization |

## Realism Score by Category

- **Field format accuracy:** 7/10 — Zeek, ASA, IDS, TLS, X.509, and OCSP schemas are strong, but the HEAD/body accounting violates HTTP semantics.
- **Temporal patterns:** 5/10 — Most causal ordering is valid, but DHCP timing and per-event cross-sensor jitter are conspicuously sampled.
- **Cross-source correlation:** 8/10 — UID, tuple, certificate, firewall, IDS, and endpoint relationships are extensive; the invalid copied HTTP byte values reduce the score.
- **Behavioral realism:** 7/10 — Traffic mix, scan states, DNS noise, caching, and TLS client fingerprints are convincing; renewal and OCSP texture is less organic.
- **Environmental consistency:** 8/10 — Host roles, routing, proxy use, AD traffic, DMZ traffic, and collection gaps are coherent.

## Recommendations

- Enforce HTTP protocol invariants before rendering: HEAD, 1xx, 204, and 304 responses must have zero body length. TCP application bytes must include status lines and headers in addition to any body.
- Do not copy a web access-log size directly into both Zeek `response_body_len` and `conn.resp_bytes`; derive each counter from a single serialized HTTP exchange.
- Generate DHCP packets from stable per-client option sets so repeated request and ACK sizes remain stable unless a specific option changes. Anchor renewal timing to lease T1 and reserve jitter for actual retries or client scheduling behavior.
- Model clock behavior with a stable per-sensor offset and slow drift, plus source-native processing delay, rather than independent symmetric jitter per record.
- Reuse or cache identical OCSP response objects unless produced time, included responder certificates, or parsed validity fields actually change; keep size changes tied to those structural changes.
- Preserve the existing DNS authority flags, TLS client/server fingerprint stability, certificate-chain integrity, and ASA/Zeek tuple correlation as regression requirements.
