# Network Forensics Analyst - Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Confidence:** 72

## Executive Summary

The dataset is high quality and often behaves like a real enterprise slice: Zeek UIDs are coherent, DNS/proxy/TLS/firewall relationships line up, and there is convincing background noise from Windows update, package managers, web browsing, scans, DHCP, and proxy errors. I still assess it as synthetic because a few source-native contradictions and distributional regularities stand out, especially IDS alerts that do not agree with Zeek protocol state.

## Evidence For Synthetic

- `snort-perimeter/snort_alert.log` reports `ET INFO TLS Handshake Failure` at `03/18-15:31:34.870` for `145.78.103.167:58172 -> 203.14.220.10:443`, but Zeek shows the same flow in `zeek-dmz/conn.json` at `2024-03-18T15:31:34.277294Z` as `service:"ssl"`, `conn_state:"SF"`, and `zeek-dmz/ssl.json` logs `established:true`, `resumed:true`, and a negotiated cipher.
- `snort-perimeter/snort_alert.log` has `ET SCAN Rapid POP3 Connection - Possible Brute Force Attack` at `15:25:31.415` and `17:00:33.430`, but `zeek-dmz/conn.json` shows only one POP3 connection from each source to port `110` during the window: `45.33.74.51:59303` and `185.249.5.220:52066`.
- Browser-like HTTPS proxy traffic to `api.westbridge-services.net` repeatedly uses a slightly malformed Chrome UA missing the normal `KHTML, like Gecko` token, e.g. `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/121.0.0.0 Safari/537.36`.
- The `api.westbridge-services.net` TLS flows in `zeek-dmz/ssl.json` use the same TLSv1.2 cipher repeatedly: `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`. That can be malware, but across many check-ins it feels more templated than captured.
- HTTP keep-alive behavior is thin: in `zeek-dmz/http.json`, `1441/1449` records have `trans_depth:1`; only 8 are depth 2. Real browser traffic, even over HTTP/1.1, often shows more connection reuse for clustered assets.
- The exfil-like upload at `17:25:06` is coherent but aggressive: `proxy_access.log` shows `314782725` client bytes, and `zeek-dmz/conn.json` shows `315397859` origin bytes over `5.294631` seconds. That is not impossible, but it is a conspicuously clean, high-rate transfer to suspicious infrastructure.

## Evidence For Real

- Zeek correlation is mostly excellent without being source-native impossible: `dns`, `http`, `ssl`, and `files` UIDs map back to `conn.json`, and sub-log timestamps fall within the owning connection windows.
- The DMZ proxy path is convincing. At `16:30:21`, `zeek-dmz/dns.json` resolves `api.westbridge-services.net` to `45.33.32.30`; `proxy_access.log` records a `CONNECT` and `GET /api/v2/checkin`; `zeek-dmz/ssl.json` shows proxy egress from `10.10.3.20` to `45.33.32.30`; ASA logs the matching NAT path.
- `zeek-core/dhcp.json` has realistic renewal behavior: same MAC/IP pairs renew around T/2 with jitter, and lease times vary (`3600`, `7200`, `14400` seconds).
- DNS has believable enterprise noise: `wpad`, `isatap`, PTR lookups, internal host A records, `NXDOMAIN`, `SERVFAIL`, mixed `A`/`AAAA`/`TXT`/`PTR`, and varied TTLs.
- Inbound internet noise looks organic: `WEB-EXT-01` sees `/phpmyadmin/`, `/backup.sql`, ICMP probes, TLS scans, and repeated HTTPS sessions from scanner-like sources.
- Firewall/NAT records align well with Zeek byte counts and timing, including the large `17:25:07` outbound connection where ASA reports `330380194` bytes and Zeek reports comparable payload plus IP overhead.

## Detailed Analysis

The Zeek corpus spans `2024-03-18T12:00Z` to about `18:00Z` across `zeek-core` and `zeek-dmz`. `zeek-core/conn.json` contains `4440` records, while `zeek-dmz/conn.json` contains `6325`. The protocol mix is credible: core traffic is dominated by Kerberos, DNS, SMB, LDAP, HTTP proxying, SSH, and DHCP; DMZ traffic includes TLS, HTTP, DNS, inbound scans, proxy egress, and server-side web traffic.

Cross-source flow construction is one of the strongest realism points. For example, the `api.westbridge-services.net` sequence has DNS resolution in `zeek-dmz/dns.json` at `16:30:21.250747Z`, proxy access at `16:30:21`, TLS egress in `zeek-dmz/ssl.json` at `16:30:22.691732Z`, and firewall NAT/teardown records for the same path. The large upload at `17:25:06` also lines up: `proxy_access.log` records a POST to `/upload/telemetry/7f3a2b19`, Zeek records UID `Cp5DmZxp3LTVb2M2Re4` from `10.10.3.20:40671` to `45.33.32.30:443`, and ASA tears down the translated connection after five seconds with `330380194` bytes.

DNS behavior is generally strong. Internal DNS queries to `DC-01.meridianhcs.local`, `FILE-SRV-01.meridianhcs.local`, `wpad.local`, `isatap`, and reverse zones look like normal enterprise background. DMZ DNS shows public resolver use to `1.1.1.1`, `8.8.8.8`, and `9.9.9.9`, with plausible response timing and mixed TTLs. The one caveat is that some suspicious domains all resolve to `45.33.32.30` with highly varied TTLs, which is plausible for attacker infrastructure but has a generated feel.

TLS and certificate data is mostly source-native. `zeek-dmz/ssl.json` includes TLSv1.2 and TLSv1.3, resumed and non-resumed sessions, certificate chains in `files.json`/`x509.json`, and OCSP responses. The certificate corpus avoids obvious impossible validity periods. The strongest defect is not TLS formatting but IDS disagreement: Snort says a TLS handshake failed for `145.78.103.167:58172`, while Zeek says it completed and negotiated a cipher.

HTTP and web behavior is mixed. The web server logs show credible asset fetches, referrers, 304s, scanners, mobile and desktop UAs, and internal users browsing `WEB-EXT-01`. Proxy logs include normal enterprise outcomes: `200`, `403`, `407`, `502`, `503`, `504`, `DENIED`, `AUTH_REQUIRED`, and `GATEWAY_ERROR`. The weaker point is low transaction depth and repeated templated CONNECT/check-in pairs for the suspicious infrastructure.

Firewall and IDS artifacts are good but not flawless. ASA NAT syntax and byte accounting are convincing, including dynamic translation pairs and inbound/outbound directionality. Snort contains realistic Emerging Threats style alerts, but the POP3 "rapid" alerts are under-supported by Zeek-visible POP3 volume, and the TLS handshake failure contradiction is the clearest authenticity problem.

## Realism Score by Category

- **Field format accuracy:** 8 - Zeek, ASA, proxy, and web fields are mostly convincing; IDS/TLS semantic mismatch lowers the score.
- **Temporal patterns:** 7 - Good jitter and burstiness, but some check-in/proxy patterns and the very fast upload feel over-shaped.
- **Cross-source correlation:** 8 - Strong DNS/proxy/TLS/firewall alignment, with one important Snort-versus-Zeek contradiction.
- **Behavioral realism:** 7 - Rich enterprise and scan background, but some UA/TLS/check-in patterns feel templated.
- **Environmental consistency:** 8 - Topology, NAT, DHCP, internal DNS, and proxy placement are coherent.

## Recommendations

- **P0:** Fix IDS/protocol contradictions. A Snort TLS handshake failure should not coincide with Zeek `ssl.established:true` and a negotiated cipher for the same 5-tuple.
- **P1:** Ensure threshold-style IDS alerts are backed by visible supporting flow volume, especially the "Rapid POP3" alerts.
- **P2:** Broaden TLS/client fingerprint diversity for repeated suspicious infrastructure, including ciphers, resumed-session behavior, and user-agent realism.
- **P2:** Stretch large exfiltration over more realistic WAN/proxy timing, or add congestion/segmentation artifacts that explain the throughput.
- **P3:** Increase HTTP keep-alive reuse and `trans_depth` variety for browser asset clusters.
- **P4:** Keep OCSP/certificate oddities, but make revoked/unknown statuses consistent with client behavior and downstream session outcomes.
