# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Confidence:** 76

## Executive Summary

The dataset is high-quality and contains many realistic Zeek/proxy/TLS correlations, but several source-native and distribution-level artifacts push me toward synthetic. The strongest issue is visible OCSP causality: OCSP analyzer records occur seconds after the referenced HTTP connection has already ended, despite sharing the same file ID and connection UID.

## Evidence For Synthetic

- `zeek-dmz/ocsp.json:1` has OCSP `ts=1710764576.722447` for `id=F8x4dwbDScRHvCF1tz`, but the linked HTTP response file is `zeek-dmz/files.json:71` at `ts=1710764571.962935` with `duration=0.016703`, and the parent connection is `zeek-dmz/conn.json:443` at `ts=1710764571.698447` with `duration=0.466529`. The OCSP record appears about 4.56 seconds after the TCP flow ended.
- Same pattern in `zeek-core`: `conn.json:1369` for `uid=C0OwI0qDwKMxeURwH3` ends around `1710770783.951647`, while `ocsp.json:1` logs `id=FVMds5ZHyQ34tnueAZN` at `1710770785.190478`, after the linked `files.json:81` OCSP response duration of only `0.010259`.
- AD discovery DNS looks too modeled. `zeek-core/dns.json` has 860 DNS records with qtypes `A=514`, `TXT=286`, `AAAA=30`, `PTR=16`, `MX=9`, `NS=4`, `SOA=1`, but zero `SRV` queries despite `zeek-core/conn.json` containing 1,082 Kerberos and 317 LDAP connections to `10.10.2.10`.
- DC lookup behavior is repetitive: 245 `A` queries for `DC-01.meridianhcs.local`, usually returning the same `10.10.2.10` / `TTL=300.0`. In a Windows AD-heavy slice, I would expect at least some `_ldap._tcp`, `_kerberos._tcp`, or `_msdcs` SRV discovery mixed into the DNS stream.
- Kerberos traffic is entirely `tcp/88` in `zeek-core/conn.json` (`service=krb`, 1,082 records). TCP-only Kerberos is not impossible, but combined with the absence of SRV DNS, it feels like a simplified renderer model of domain activity.

## Evidence For Real

- Cross-source proxy behavior is convincing. For `ctldl.windowsupdate.com`, core/DMZ HTTP CONNECT records to `10.10.3.20:8080` are followed by DMZ TLS from proxy `10.10.3.20` to `52.114.132.73:443` with the same SNI pattern and realistic delay.
- Zeek byte and packet accounting is internally consistent: TCP `orig_ip_bytes`/`resp_ip_bytes` reflect payload plus plausible IP/TCP overhead, and ICMP records use type/code-style ports such as `id.orig_p=8`, `id.resp_p=0`.
- TLS/x509 data is richer than a naive synthetic set: `zeek-dmz/ssl.json` has TLS 1.2 and 1.3, session resumption, multiple cipher families, cert-chain file IDs, and `zeek-dmz/x509.json` certificates that are valid during the March 18, 2024 window.
- Network background noise is plausible: inbound S0 scans against `WEB-EXT-01`, web portal sessions to `ehr-portal.meridianhcs.com`, WPAD/isatap NXDOMAIN noise, proxy 403/407/502/504 failures, and mixed Windows/Linux user agents.
- DHCP renewal records in `zeek-core/dhcp.json` show repeated REQUEST/ACK renewals with stable MAC/IP/hostname mappings and varied lease times.

## Detailed Analysis

The Zeek corpus spans roughly 2024-03-18 12:00:12 to 18:01:10 UTC. `zeek-core` has 4,659 conn, 860 DNS, 1,092 HTTP, 52 SSL, 205 files, 12 x509, 1 OCSP, and 25 DHCP records. `zeek-dmz` has 6,476 conn, 1,057 DNS, 1,455 HTTP, 2,018 SSL, 887 files, 789 x509, and 68 OCSP records.

The proxy model is one of the strongest realism points. Core sees internal clients connecting to `PROXY-01` on `8080`; DMZ sees both that CONNECT leg and the proxy's outbound TLS. Example: `zeek-core/http.json` records `10.10.1.36 -> 10.10.3.20:8080` CONNECT to `ctldl.windowsupdate.com` at `1710763665.644940`; `zeek-dmz/ssl.json` then records `10.10.3.20 -> 52.114.132.73:443` with SNI `ctldl.windowsupdate.com` at `1710763667.689318`.

The main hard flaw is OCSP timing. In `zeek-dmz`, all 68 OCSP records occur after their associated HTTP connection end by more than 0.5 seconds. The first is representative: `conn.json:443` starts `1710764571.698447`, duration `0.466529`; HTTP/file records carry fuid `F8x4dwbDScRHvCF1tz` at `1710764571.961935` / `1710764571.962935`; OCSP logs that same fuid at `1710764576.722447`. That ordering is not a bounded-window issue because all records are visible and share the same identifier chain.

The AD network shape is also weaker than the rest. Heavy Kerberos/LDAP traffic to `10.10.2.10` is present throughout the core sensor, but DNS discovery is mostly direct `DC-01.meridianhcs.local` A/AAAA lookups and PTRs. The absence of SRV query types across 860 DNS records is a behavioral gap for a domain environment this active.

The malicious/network narrative itself is plausible: TXT lookups from `10.10.2.30` to `ns1.westbridge-services.net` with low TTLs and varying answers look like DNS tunneling; later proxy CONNECT/TLS activity to `api.westbridge-services.net` appears in both core and DMZ. I do not treat that attack storyline as synthetic by itself.

## Realism Score by Category

- **Field format accuracy:** 78 — Zeek JSON fields mostly look source-native, but OCSP timestamps break source-native causal ordering.
- **Temporal patterns:** 70 — Broad timing is plausible, but OCSP-after-connection-end and simplified AD discovery timing are notable.
- **Cross-source correlation:** 88 — Proxy, TLS, files, x509, and eCAR flow direction line up well without obvious tuple contradictions.
- **Behavioral realism:** 72 — Web/proxy/background traffic is strong; AD DNS/Kerberos behavior is too simplified.
- **Environmental consistency:** 82 — Host/IP/service roles are coherent, with realistic DMZ/core separation and endpoint mappings.

## Recommendations

Fix OCSP timestamp ownership first: OCSP records should timestamp within the HTTP response/file transfer and before the parent connection end. Add AD DNS realism by generating SRV lookups for Kerberos/LDAP/DC discovery, not only hostname A records. Consider adding UDP Kerberos or documenting/configuring TCP-only Kerberos as an environment trait when that distribution is intentional.
