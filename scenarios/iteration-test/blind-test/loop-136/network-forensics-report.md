# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Confidence:** 68

## Executive Summary

The network data is technically coherent and often source-native: Zeek UID references line up, TCP state fields are mostly believable, and proxy/TLS/DNS relationships tell a plausible intrusion story. I would still call it synthetic because several high-volume patterns look generated rather than organically captured, especially resolver selection, DNS-tunnel vocabulary/timing, Kerberos transport mix, and repeated short TLS sessions.

## Evidence For Synthetic

- `zeek-dmz/dns.json`: `10.10.3.20` distributes DNS almost evenly across `1.1.1.1` (314), `8.8.8.8` (292), and `9.9.9.9` (239). Corporate hosts usually have stable resolver preference/failover behavior, not near-balanced public-resolver rotation.
- `zeek-core/dns.json`: 245 `*.westbridge-services.net` queries from `10.10.2.30` are almost all TXT records, from `12:45:23` to `13:45:00`; responses use templated-looking payloads such as `id=...`, `rx=...`, and `s=232;d=...`.
- `zeek-dmz/conn.json` and `ssl.json`: source `185.70.41.45` makes 381 port-443 connections to `10.10.3.10` between `08:30:28` and `08:51:07`, with median duration `2.57s`, median client bytes `717`, and median server bytes `4268`. That many tiny TLS sessions to one portal feels algorithmic.
- `zeek-core/conn.json`: Kerberos is represented as 1120 TCP/88 connections and no visible UDP/88 Kerberos. TCP Kerberos is valid, but an all-TCP mix over a six-hour AD window is unusual.
- `zeek-core/http.json` / `zeek-dmz/http.json`: almost every HTTP transaction has `trans_depth: 1`; only three records per sensor reach `trans_depth: 2`. Real proxy and web traffic usually has more persistent connection reuse somewhere in the long tail.

## Evidence For Real

- All `http.json`, `ssl.json`, `files.json`, `x509.json`, `ocsp.json`, and `dhcp.json` UID references I checked resolve to local `conn.json` records inside the same sensor.
- TCP state fields are mostly source-native: `S0` records have no server bytes, `REJ` records use `Sr`, UDP/DNS uses `Dd`, and ICMP uses type/code fields like `id.orig_p: 8`, `id.resp_p: 0`.
- TLS behavior is plausible: `zeek-dmz/ssl.json` is mostly TLS 1.3 (`1376`) and TLS 1.2 (`644`), with modern cipher suites and realistic resumed-session coverage.
- TLS 1.3 records often lack certificate chains while TLS 1.2 records include `cert_chain_fuids` linked to `files.json` and `x509.json`, which matches what Zeek can observe without decryption.
- DNS includes realistic enterprise noise: `wpad`, `isatap`, DNS suffix-search failures, PTR lookups, DKIM/SPF TXT records, OCSP, Windows Update, Ubuntu, Adobe, and Google update traffic.

## Detailed Analysis

**Connection Patterns**

`zeek-core/conn.json` contains 4699 records from `08:00:09` to `14:00:03`; `zeek-dmz/conn.json` contains 6531 records from `08:00:01` to `13:59:13`. State distribution is believable overall: core is mostly `SF` (`3987`) with some `S0`, `RSTO`, and `RSTR`; DMZ has heavier `S0` (`1443`) from inbound scanning. The DMZ exposure pattern is plausible, with repeated probes to `10.10.3.10` on 443, 80, 445, 3389, 23, 25, and 22.

**DNS Behavior**

Internal DNS is mostly clients to `10.10.2.10`, while the proxy uses public resolvers. The query mix is credible in places: core has `A`, `AAAA`, `PTR`, `MX`, `NS`, and a large TXT spike; DMZ has public A/AAAA/PTR/NS/SOA. The strongest synthetic tell is not the presence of tunneling, but the generated feel of the `westbridge-services.net` TXT run: 244 TXT queries, small discrete TTLs, and repeated payload prefixes.

**HTTP and Proxy Flow**

Proxy modeling is good. Example: at `13:45:26`, `10.10.1.35:52188 -> 10.10.3.20:8080` issues `CONNECT api.westbridge-services.net:443`, followed at `13:45:27` by `10.10.3.20 -> 45.33.32.30:443` with SNI `api.westbridge-services.net`. That is exactly the kind of split-path evidence I expect from explicit proxy logs. The weak point is that nearly all HTTP sessions are single-transaction, which flattens the long tail.

**TLS and Certificates**

Certificate handling is one of the stronger realism areas. `x509.json` chains reference plausible issuers including GlobalSign, DigiCert, Let's Encrypt, Google Trust Services, and internal Meridianhcs CAs; I found no certificates invalid at observation time. TLS versions and ciphers are modern without being perfectly uniform.

**Traffic Volume and Timing**

Business-hour activity has natural-ish bursts, including a core DNS spike around `12:45` and DMZ 443 spikes around `08:30`. The exfil-like chain around `13:45` is coherent: a large SMB transfer from `10.10.2.20` to `10.10.1.35`, then a large CONNECT/TLS upload to `api.westbridge-services.net`. The story works, but the sizes and timing are almost narratively tidy.

## Realism Score by Category

- **Field format accuracy:** 8 — Zeek fields, UIDs, TCP states, TLS/X509/file references are mostly source-native.
- **Temporal patterns:** 7 — Business-hour bursts are good, but some bursts look scripted.
- **Cross-source correlation:** 8 — Proxy, TLS, DNS, files, and cert references align without obvious impossible ordering.
- **Behavioral realism:** 6 — DNS resolver rotation, all-TCP Kerberos, and repetitive TLS sessions reduce believability.
- **Environmental consistency:** 7 — Internal roles, proxying, AD, DHCP, update traffic, and scanning are coherent.

## Recommendations

If this were synthetic, I would improve realism by making resolver behavior host-specific and sticky, adding more HTTP keep-alive/multi-transaction depth, mixing UDP and TCP Kerberos according to realistic AD client behavior, and making DNS-tunnel responses less visibly templated. I would also vary TLS client behavior for repeated portal access so one source does not produce hundreds of similarly small, short-lived sessions.
