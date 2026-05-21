# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Confidence:** 74

## Executive Summary

The dataset is unusually strong at the network-evidence layer: Zeek field formats, conn/http/ssl/files/x509 joins, proxy behavior, DHCP renewals, and scan noise are mostly coherent. My synthetic verdict rests mainly on DNS source-native contradictions: the same resolver returns different TXT/DMARC answers for the same name well inside the prior TTL window, which is difficult to reconcile with real recursive-cache behavior.

## Evidence For Synthetic

- `zeek-core/dns.json`: `github.com` TXT via resolver `10.10.2.10` changes inside cache lifetime. At `2024-03-18T16:43:50.928446Z`, client `10.10.1.22` gets `v=spf1 include:_spf.google.com include:spf.protection.outlook.com ~all` with TTL `300`; at `2024-03-18T16:45:19.597510Z`, client `10.10.1.31` gets `v=spf1 include:servers.mcsv.net include:mail.zendesk.com ~all` from the same resolver, only 89 seconds later.
- `zeek-core/dns.json`: `_dmarc.meridianhcs.com` TXT changes from `p=none` with TTL `1800` at `2024-03-18T16:47:40.616369Z` to `p=quarantine` at `2024-03-18T16:56:45.366483Z`, also through `10.10.2.10`, before the earlier TTL should expire.
- `zeek-core/dns.json`: `atlassian.net` TXT changes from `include:spf.protection.outlook.com -all` at `2024-03-18T17:01:25.709969Z` to `include:sendgrid.net include:_spf.google.com ~all` at `2024-03-18T17:03:53.364802Z`, same resolver and same 1800-second TTL class.
- `zeek-dmz/http.json`: external browsing to `ehr-portal.meridianhcs.com` has a pattern-library feel: many one-off public clients retrieve the same small set of paths with repeated exact body sizes, such as `/` returning `75951` bytes for multiple unrelated origins and `/api/v1/status` returning `111` bytes.
- DNS latency looks bounded rather than messy: `zeek-core/dns.json` has 860 records with RTT max about `0.349413` seconds, and `zeek-dmz/dns.json` has 1057 records with RTT max about `0.348933` seconds. That is not impossible, but the ceiling is conspicuously clean.

## Evidence For Real

- `zeek-core/conn.json`: connection states are plausible for an enterprise slice: `3994 SF`, `230 S0`, `219 RSTO`, `142 RSTR`; `zeek-dmz/conn.json` similarly has `4880 SF`, `1398 S0`, `106 RSTO`, `50 RSTR`, matching a mix of normal traffic plus exposed-service scan noise.
- `zeek-dmz/ssl.json`: TLS distribution is believable for a mixed modern environment: `1401 TLSv13` and `617 TLSv12`, with common ciphers including `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, and ECDHE RSA/ECDSA suites.
- `zeek-core/dns.json` and `zeek-dmz/dns.json`: DNS includes realistic A/AAAA/PTR/TXT mix, WPAD/ISATAP suffix-search failures, NXDOMAINs, internal host lookups, and external resolver use from the proxy.
- `zeek-core/dhcp.json`: DHCP renewals are credible slice-of-time artifacts. Examples include REQUEST/ACK renewals to `10.10.2.10` with 3600/7200/14400-second lease classes and stable MAC/hostname pairings.
- `zeek-dmz/files.json`, `ssl.json`, and `x509.json`: certificate file IDs, SSL `cert_chain_fuids`, and X.509 records line up cleanly, and SNI-to-certificate SAN matching appears source-native.

## Detailed Analysis

Connection behavior is broadly convincing. The DMZ view shows expected internet-facing pressure against `10.10.3.10`, including S0 scans to `22`, `23`, `25`, `80`, `443`, `445`, `8080`, and `3389`, while normal HTTPS dominates successful sessions. Internal core traffic shows Kerberos, SMB, LDAP, SSH, HTTP proxying, DHCP, and database-port probes, all fitting a segmented enterprise network.

DNS is the weakest area. The dataset has good realism elements: `wpad`, `wpad.local`, `isatap`, `printer01.meridianhcs.local`, and random NXDOMAINs appear naturally, and the TXT burst from `10.10.2.30` to `*.ns1.westbridge-services.net` from `2024-03-18T16:45:04.820568Z` to `2024-03-18T17:44:55.179947Z` looks like a plausible DNS-tunnel/C2 pattern. However, recursive-cache semantics break on repeated TXT/DMARC answers through `10.10.2.10`. That is a concrete protocol-level inconsistency, not merely "too well correlated."

HTTP and proxy behavior are mostly plausible. `zeek-core/http.json` is dominated by `CONNECT` (`960`) with GET (`127`) and POST (`5`), and status codes include `200`, `403`, `407`, `502`, `504`, `304`, and `206`. Examples like `Windows-Update-Agent`, `Google Update`, `Zscaler Client Connector`, `Dell Command Update`, and browser UAs through `10.10.3.20` fit an explicit proxy environment. The external web traffic, though, reuses a narrow set of page paths, response sizes, and browser versions in a way that feels generated.

TLS is one of the stronger parts of the dataset. SNI values match certificate subjects/SANs, resumed sessions generally omit cert chains, OCSP and X.509 artifacts are present, and the TLS 1.2/TLS 1.3 split is reasonable. I did not find an impossible visible ordering in SSL/files/x509 references.

## Realism Score by Category

- **Field format accuracy:** 9 — Zeek JSON shape, UID usage, byte fields, TLS, files, and X.509 records are mostly source-native.
- **Temporal patterns:** 7 — Business-hour flow and bursts are good, but DNS RTT bounds and some templated web sequences reduce confidence.
- **Cross-source correlation:** 8 — Network-layer joins are strong; DNS recursive-cache contradictions are the main exception.
- **Behavioral realism:** 7 — Proxy, TLS, scans, DHCP, and lateral traffic are plausible, but some web/DNS content feels assembled.
- **Environmental consistency:** 7 — Host/IP/service topology is coherent, but repeated DNS answer changes inside TTL windows are hard to accept as production behavior.

## Recommendations

If this were synthetic, improve realism by making DNS resolver behavior cache-aware: repeated positive answers for the same resolver/name/type should remain stable until TTL expiry unless an explicit resolver restart, split-horizon change, or cache-bypass condition is represented. Add more long-tail HTTP/client behavior, broader user-agent entropy, occasional DNS non-response/retry artifacts, and less visibly bounded DNS RTT distributions.
