# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Confidence:** 64

## Executive Summary

The Zeek data is substantially realistic: protocol logs are internally consistent, cross-sensor timing is plausible, and the proxy/file/DNS/TLS relationships hold together without obvious impossible ordering. I would still call it synthetic because several behavioral surfaces feel authored: DNS-tunnel payload vocabulary, HTTP paths/content lengths, and user-agent/application pools are cleaner and more semantically tidy than I expect from production traffic.

## Evidence For Synthetic

- `zeek-core/dns.json` has 285 TXT lookups from `10.10.2.30` to `*.ns1.westbridge-services.net` between `2024-03-18T16:44:51Z` and `16:59:46Z`; TXT answers such as `xid:V7RMETVJ4BLIZ7Y:path-c24:n1` and `srv-x23-4:aee0045ac2` look like deliberately readable protocol markers rather than messy encoded payloads.
- `zeek-dmz/http.json` shows tidy repeated web content patterns: `ehr-portal.meridianhcs.com` `/api/v1/status` repeatedly returns body length `111` as `text/html`, `/api/v2/data` returns `42320`, and `/` returns `75951`.
- User-agent diversity is present but pool-like: exact strings such as `Windows-Update-Agent/10.0.10011.16384...` occur 189 times, alongside repeated `curl/7.88.1`, `Wget/1.21.3`, `python-requests/2.31.0`, and `Apache-HttpClient/4.5.14`.
- Some proxy DNS behavior is slightly too convenient. `zeek-dmz/dns.json` resolves `api.westbridge-services.net` with very low TTLs, but later TLS sessions to `45.33.32.30` occur outside those TTL windows, for example the `17:24:38Z` large upload in `zeek-dmz/ssl.json`.
- The external web and scan traffic has believable variety, but many paths, domains, and service names read like a curated enterprise-security scenario rather than the noisier vocabulary of a random production edge.

## Evidence For Real

- Zeek source-native references are strong: DNS, HTTP, SSL, files, X509, and OCSP records all have parent connection/file references where expected.
- Core and DMZ sensors observe the same internal-to-proxy flows with independent UIDs and small timestamp offsets, which is realistic for multiple Zeek vantage points.
- The large SMB-to-proxy-to-TLS sequence is coherent: `zeek-core/files.json` shows `\\FILE-SRV-01\C$\ProgramData\Microsoft\cache_7f3a.zip` at `314685609` bytes, followed by proxy CONNECT and outbound TLS with matching upload scale.
- DNS includes normal enterprise messiness: `wpad`, `isatap`, reverse lookups, `NXDOMAIN`, `REFUSED`, and `SERVFAIL` appear alongside normal AD-style host resolution.
- TLS/X509 looks credible: mixed TLS 1.2/1.3, resumed and non-resumed sessions, cert chains, OCSP entries, public CAs, internal CA certificates, and repeated leaf fingerprints across repeated sessions.

## Detailed Analysis

**Topology and Flow Shape:**
`zeek-core/conn.json` is mostly internal traffic: AD/Kerberos to `10.10.2.10`, SMB to `10.10.2.20`, proxy traffic to `10.10.3.20:8080`, and internal app/web traffic. `zeek-dmz/conn.json` adds Internet-facing traffic: proxy egress, public web ingress to `10.10.3.10`, and scan/noise traffic to ports `23`, `3389`, `445`, `25`, `22`, `80`, and `443`.

**Cross-Sensor Proxy Correlation:**
At `2024-03-18T12:00:16Z`, core UID `C2APg9pRr5YEsW4JOm` and DMZ UID `C8OplfD4H6wtWaj4Ia` both show `10.10.1.22:39309 -> 10.10.3.20:8080` with HTTP CONNECT to `registry.npmjs.org`. The UIDs differ, as expected across independent Zeek sensors, while timing and byte counts line up.

**Exfil-Like Sequence:**
At `17:22:17Z`, `zeek-core/conn.json` UID `CBHKK7Vr5cvXvetv40` shows SMB from `10.10.1.35` to `10.10.2.20:445`, with `resp_bytes=314685609`. `zeek-core/files.json` ties that UID to `cache_7f3a.zip` with the same byte count. At `17:24:36Z`, `10.10.1.35` opens HTTP CONNECT to `api.westbridge-services.net`, and `zeek-dmz/ssl.json` follows with outbound TLS from proxy `10.10.3.20` to `45.33.32.30:443`, `orig_bytes=315302218`, SNI `api.westbridge-services.net`. This is very convincing network storytelling.

**DNS Realism:**
Internal DNS has normal AD flavor: `DC-01.meridianhcs.local`, `FILE-SRV-01`, PTR records, `wpad`, `isatap`, and mixed response codes. The westbridge TXT tunnel is technically plausible but too legible: payload markers like `path-b15:n3` and repeated low TTLs are the strongest synthetic fingerprint.

**HTTP/TLS Realism:**
The CONNECT proxy pattern is well rendered, and TLS cert extraction behaves properly: resumed sessions often omit cert chains, while non-resumed sessions include X509/file records. The public web traffic has reasonable browser UAs and asset waterfalls, but the content paths and sizes feel curated.

## Realism Score by Category

- **Field format accuracy:** 8 — Zeek fields, UIDs, histories, byte counters, and X509/file references are mostly source-native.
- **Temporal patterns:** 7 — Workday activity, bursts, scans, and proxy flows are plausible, but some DNS/proxy timing feels staged.
- **Cross-source correlation:** 9 — Core/DMZ/HTTP/SSL/files relationships are highly coherent with no hard impossible ordering found.
- **Behavioral realism:** 7 — Attack and baseline behaviors make sense, but vocabulary pools and payload strings feel authored.
- **Environmental consistency:** 8 — AD, proxy, DMZ, DHCP, internal CA, and public TLS all fit one environment.

## Recommendations

If this is synthetic, improve realism by making DNS-tunnel payloads less semantically transparent, adding more varied application/browser long-tail traffic, and loosening repeated HTTP response bodies for dynamic endpoints. I would also model proxy DNS caching more explicitly so low-TTL resolutions and later TLS reuse are explainable, and add more incidental production artifacts such as oddball UAs, partial failures, retries, and inconsistent web response metadata.
