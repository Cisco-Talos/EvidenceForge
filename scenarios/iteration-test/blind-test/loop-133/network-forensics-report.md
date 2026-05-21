# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Confidence:** 68

## Executive Summary

This is high-quality, internally consistent network telemetry with convincing Zeek, proxy, firewall, web, TLS, and IDS correlations. My synthetic verdict is driven less by contradictions and more by repeated evidence of authored generation grammars: DGA-like DNS, web-scan paths, response sizes, and traffic roles look curated in ways real environments rarely sustain this cleanly.

## Evidence For Synthetic

- `zeek-dmz/dns.json` contains 38 suspicious domains matching a tight grammar: prefix + 8 random chars + small TLD set, e.g. `assets-391won4y.to`, `cdn-e3j21qu9.to`, `update-hntatlyk.tk`, `metrics-0s888zha.top`.
- Those suspicious DNS queries use a small set of nonstandard resolver IPs that also appear as scanner infrastructure, including `37.75.195.175`, `145.78.103.167`, `38.186.148.245`, and `74.172.69.175`.
- The suspicious DNS answers often resolve to generic CDN/cloud-looking IPs, but I did not see follow-on connections from the querying host to those returned IPs within five minutes. That makes the DNS look more like planted noise than operational malware resolution.
- `WEB-EXT-01.meridianhcs.local/web_access.log` has a very regular Nikto-style scan from `185.70.41.45` from `12:31:12` to `12:51:08`, with repeated fixed response sizes: `/wp-login.php` → `404 902`, `/xmlrpc.php` → `404 952`, `/config.php` → `404 919`, `/server-status` → `403 1230`.
- The environment is unusually clean at the sensor level: Zeek file records consistently show `missing_bytes:0`, `overflow_bytes:0`, and `timedout:false`. This is not impossible, but combined with the templated behavior it feels generated.

## Evidence For Real

- Cross-source flow reconstruction is strong. The `12:00:19` proxy CONNECT to `pypi.org` appears in `zeek-core/http.json`, `zeek-dmz/http.json`, `PROXY-01.../proxy_access.log`, and ASA logs with coherent timing and byte counts.
- TLS behavior is source-native. TLS 1.2 sessions carry visible certificate chains and matching `x509.json`/`files.json` entries; TLS 1.3 sessions usually lack visible cert chains, which matches passive network collection behavior.
- The inbound web scan from `185.70.41.45` is represented coherently across `zeek-dmz/conn.json`, `zeek-dmz/ssl.json`, `WEB-EXT-01.../web_access.log`, and `snort-perimeter/snort_alert.log`.
- Realistic browser/server sequences exist. For example, `118.59.66.215` at `12:04:43-12:05:16` fetched `/`, CSS, vendor JS, logo, app bundle, hero image, favicon, `/blog`, and blog images with plausible `200`/`304` statuses and referrers.
- Internal DNS, DHCP, Kerberos, SMB, proxy, and DMZ traffic show believable role separation: workstations in `10.10.1.0/24`, servers in `10.10.2.0/24`, DMZ systems in `10.10.3.0/24`, and DB traffic toward `10.10.4.10`.

## Detailed Analysis

The Zeek corpus shows a coherent two-sensor view. `zeek-core/conn.json` has 4,699 connections across roughly `2024-03-18T12:00:09Z` to `18:00:03Z`; `zeek-dmz/conn.json` has 6,531 connections from `12:00:01Z` to `17:59:13Z`. Service mixes are plausible: core is heavy in Kerberos, DNS, SMB, LDAP, proxy HTTP, and SSH; DMZ is heavier in SSL, HTTP proxying, inbound scanning, and external DNS.

The strongest realness signal is proxy path consistency. At `12:00:19`, `10.10.2.30:53535` connects to `10.10.3.20:8080` for `CONNECT pypi.org:443`; ASA logs build/teardown connection `1218008`, while the DMZ side shows `10.10.3.20:44957 -> 151.101.0.223:443` and ASA NAT translation to `203.14.220.1/53216`. That is exactly the kind of multi-hop shape I expect from a real proxy deployment.

TLS/X.509 handling is also convincing. `zeek-dmz/ssl.json` has TLS 1.2 certificate-bearing sessions with `cert_chain_fuids`, matching `zeek-dmz/files.json` and `zeek-dmz/x509.json`. A no-SNI connection from `185.70.41.45` at `12:30:28` presents a self-signed `CN=203.14.220.10`, while later SNI-bearing traffic to `ehr-portal.meridianhcs.com` uses the portal certificate. That is nuanced.

The public web traffic is mixed. Normal browser sessions have believable referrers, asset cascades, mobile and desktop UAs, and status-code variation. But the scanner and malicious-looking DNS are where the authored feel emerges. The Nikto sequence is almost textbook, with highly repeatable endpoint/status/size combinations. The suspicious DNS names are all from a compact generator-like vocabulary: `assets`, `cdn`, `storage`, `update`, `metrics`, `lookup`, `telemetry`, `status`, `sync`, `resolver`, `node`, and `cdn-check`.

I did not find a hard impossible ordering, broken UID relationship, or source-native field contradiction. The dataset’s realism is therefore high. My verdict is synthetic because the behavioral entropy feels bounded by reusable pools rather than by the messier long tail of a live network.

## Realism Score by Category

- **Field format accuracy:** 8 — Zeek, ASA, proxy, Snort, TLS, and web fields are mostly source-native and coherent.
- **Temporal patterns:** 7 — Traffic has spikes and jitter, but the six-hour slice and generated-looking scan/DNS timing feel controlled.
- **Cross-source correlation:** 9 — Proxy, firewall, Zeek, web, TLS, and IDS evidence lines up very well without obvious contradictions.
- **Behavioral realism:** 7 — Browser sessions and proxy flows are good; DGA and scanner behavior feel templated.
- **Environmental consistency:** 8 — Topology, DNS, DHCP, proxying, and DMZ placement are consistent and believable.

## Recommendations

If this is synthetic, improve realism by expanding the suspicious DNS grammar, separating scanner IPs from recursive/DGA resolver roles, and adding selective follow-on connections or beacon semantics for resolved malicious domains. Add more low-level sensor imperfections, such as occasional Zeek parser gaps, partial transfers, retransmission artifacts, and noisier server-side response variance. For web traffic, broaden endpoint behavior so repeated scanner paths and normal asset sizes do not map as cleanly to fixed status/body-length pairs.
