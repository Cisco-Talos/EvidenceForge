# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 66
**Synthetic-Confidence Score:** 64

## Executive Summary

The network telemetry is unusually well-correlated and mostly source-native: Zeek parent/child UIDs line up, DNS generally precedes external connections, and Snort/firewall/NAT views match Zeek DMZ flows. The deciding synthetic tell is a repeated Zeek TLS inconsistency: many TLSv1.2 sessions are marked `resumed:true` while carrying full-handshake-style `ssl_history` values but no certificate/file/x509 artifacts.

## Evidence For Synthetic

- **[schema_or_format]** `zeek-dmz/ssl.json` has 85 TLSv1.2 rows with `resumed:true` and `ssl_history` of `CSXKNGIFIFD` or `CSXKNGIFIFT`, but no `cert_chain_fuids` and no matching SSL certificate files/x509 rows. Examples: UID `CfkOQtwcdi1LSa0S76` at `2024-03-18 12:13:40.983Z`, `www.bing.com`; UID `CQOQjEFPaC4hlezd7P` at `12:26:28.487Z`, `security.ubuntu.com`; UID `Cfltt6PQk4LQTFtwFy` at `13:03:21.598Z`, inbound `ehr-portal.meridianhcs.com`.
- **[schema_or_format]** The same pattern appears once in `zeek-core/ssl.json`: UID `CCAEuEQQby1D4HoPp`, `mail-clinical.meridianhcs.com`, `resumed:true`, `TLSv12`, `ssl_history:"CSXKNGIFIFT"`, no cert artifacts, parent conn has `missed_bytes:0`.
- **[distribution_texture]** A few HTTP/1.1 keep-alive sequences advance exactly ~1 ms after sizeable responses on the same UID. Example: `zeek-core/http.json` UID `CFb1eCOI4mxjrMYp6J` has trans_depth 2 `/assets/img/content/399fa2bf.webp` with `response_body_len:115034`, then trans_depth 3 one millisecond later for another 288795-byte image. This is weak by itself but has generated-timing flavor.

## Evidence For Real

- Zeek analyzer rows are strongly coherent with `conn.json`: core DNS `3341/3341`, HTTP `1121/1121`, SSL `97/97`, SMTP `53/53`, DHCP `73/73`; DMZ DNS `2006/2006`, HTTP `1323/1323`, SSL `1791/1791`, NTP `2/2` all have matching parent connection references.
- DNS-to-connection behavior is plausible. Example: `zeek-dmz/dns.json` UID `CQQgog6drEPBYhj2sy` queries `media.licdn.com` at `12:02:48.754Z` and returns `13.107.45.52`; `zeek-dmz/ssl.json` UID `CLcOXhp7Gfly6kHJ8v` connects to `13.107.45.52:443` with SNI `media.licdn.com` at `12:02:52.267Z`.
- Snort/perimeter correlation is good: all 34 parsed Snort alerts had a matching Zeek DMZ flow within 2 seconds. Example: Snort ICMP alert `156.32.3.55 -> 203.14.220.10` at `12:21:45.789` matches Zeek UID `CoSCcLTGbWMdmqm4Hj`, `156.32.3.55 -> 10.10.3.10`, `proto:"icmp"`, `conn_state:"SF"` at `12:21:45.801`.
- Proxy/origin behavior is often realistic. The Duo MSI download appears as client-to-proxy HTTP UID `CwJeow4O5p99yJ1XES` and proxy-to-origin HTTP UID `CxXAFFwcoSRMkCNDHx6`, both carrying ~33.98 MB and matching file SHA1/size behavior.

## Detailed Analysis

The dataset spans `2024-03-18T12:00:00Z` to `18:00:00Z` per `COLLECTION_PROFILE.json`. Network volume is plausible for a compact enterprise slice: `zeek-core/conn.json` has 7,455 rows and `zeek-dmz/conn.json` has 6,606 rows; DMZ has heavier SSL and inbound scan texture, while core has DNS, Kerberos, SMB, LDAP, DHCP, and internal HTTP/proxy traffic.

The strongest defect is in TLS state semantics. In `zeek-dmz/ssl.json`, UID `CfkOQtwcdi1LSa0S76` is `10.10.3.20:58646 -> 13.107.21.200:443`, `version:"TLSv12"`, `cipher:"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"`, `server_name:"www.bing.com"`, `resumed:true`, `established:true`, `ssl_history:"CSXKNGIFIFD"`. Its parent `conn` has `missed_bytes:0`, yet there are no `cert_chain_fuids` and no SSL certificate `files`/`x509` rows for that UID. The same pattern repeats broadly enough to look like a generator contract bug, not a sensor blind spot.

By contrast, non-resumed TLSv1.2 rows with similar histories do emit cert artifacts. For example, `zeek-dmz/ssl.json` UID `CAiIWPzv2tm0PwYhX` at `12:13:04.674Z` for `www.bing.com` is `resumed:false`, has `ssl_history:"CSXKNGIFIFD"`, and includes `cert_chain_fuids`. That contrast is why the resumed rows stand out.

The perimeter story is otherwise credible. Snort alert `185.70.41.45:61074 -> 203.14.220.10:443` at `12:32:24.358` maps to Zeek DMZ UID `CYLsw5PEHxYjpEAtF`, `185.70.41.45:61074 -> 10.10.3.10:443`, `service:"ssl"`, `conn_state:"SF"`, `missed_bytes:0`, at `12:32:24.248`. NAT-visible public IP and internal DMZ IP are consistent with the firewall records.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected score |
|---|---|---:|---|
| schema_or_format | Zeek ssl/files/x509 | 86 TLSv1.2 rows across core+DMZ | `resumed:true` conflicts with full-handshake-style history and missing cert artifacts under `missed_bytes:0`. |
| distribution_texture | Zeek HTTP | 3 duplicated core/DMZ events | Same-UID HTTP requests occur ~1 ms after sizeable prior responses; weak but synthetic-looking. |
| weak_signal | Network timing | dataset-wide | Some timings are very clean, but most have enough jitter and source-native consistency to keep this from being decisive. |

## Realism Score by Category

- **Field format accuracy:** 72 — Mostly native Zeek/ASA/Snort shapes, with a notable TLS resumed/history/cert defect.
- **Temporal patterns:** 70 — Good jitter overall; a few HTTP keep-alive timings look too mechanical.
- **Cross-source correlation:** 88 — Zeek, Snort, firewall, proxy, and files correlate well without obvious impossible ordering.
- **Behavioral realism:** 78 — DNS, proxy, scans, SMB/LDAP/Kerberos, SSH/RDP, and web browsing distributions are plausible.
- **Environmental consistency:** 84 — Host roles, subnets, NAT, and collection-window behavior are internally consistent.

## Recommendations

If synthetic, fix the Zeek TLS contract first: TLSv1.2 resumed sessions should use abbreviated-session semantics, while full-handshake histories should be `resumed:false` and emit consistent `cert_chain_fuids`, `files`, and `x509` rows.

Add browser/proxy HTTP timing constraints so same-connection `trans_depth` advances only after a plausible response interval unless intentionally modeling pipelining. Keep the existing DNS-before-egress, UID parenting, NAT, and Snort correlation patterns; those are the parts making the dataset hard to dismiss.
