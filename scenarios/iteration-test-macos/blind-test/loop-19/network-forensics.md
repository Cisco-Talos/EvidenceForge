# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 88
**Synthetic-Confidence Score:** 82

## Executive Summary

The network records are structurally coherent across three Zeek vantage points, proxy access records, perimeter firewall logs and IDS alerts, with sensible connection-state, DNS, HTTP and TLS fields. The strongest authenticity concern is the unusually repetitive suspicious traffic from 10.10.3.10: long runs of algorithmically shaped `.top` DNS labels at a steady cadence, plus a compact sweep across three sensitive ports and nearly an entire internal /24. These could describe real compromise behavior, but the repeated, highly regular texture across unrelated-looking probes makes a synthetic source more likely.

## Evidence For Synthetic

- [distribution_texture] `zeek-dmz/dns.json` shows 10.10.3.10 issuing a continuous stream of unique random-looking labels under `.top` from 18:00:34 through at least 18:45 UTC. Examples include `ewnjsaqf1rasgez5.top` at 18:00:34, `30rgw6r7503.top` at 18:01:23, `ipeq1qmxjn.top` at 18:06:25, and `6nnvbsmiacq5.top` at 18:43:25. The intervening requests recur every roughly 20–45 seconds, predominantly NXDOMAIN, with several sinkhole-like answers of `45.33.32.30`. This is a sustained and unusually uniform DGA-style pattern. `snort-perimeter/snort_alert.log` independently flags this source's `.top` queries at 18:01:23, 18:06:26, 18:11:34, 18:21:58, 18:27:05, 18:32:32, 18:38:00 and 18:43:26.
- [distribution_texture] `zeek-core/conn.json` records about 760 attempts from 10.10.3.10 to 10.10.2.0/24 on TCP 22, 445 and 3306 in a roughly five-second span, 14:40:45–14:40:50 UTC. There are 255 attempts to port 445, 255 to 22 and 254 to 3306; 743 of 766 combined attempts are `S0` with zero bytes and no completed handshake. For example, at 14:40:45 the same source probes 10.10.2.103:445, 10.10.2.97:3306, 10.10.2.92:445 and 10.10.2.71:22. A high-speed sweep is technically possible, but the near-equal service counts, subnet-wide reach, zero-response texture and narrow timing cluster look like a generated scan burst.
- [environment_or_collection_plausibility] The same 10.10.3.10 address appears as an internal initiator for DNS, web/proxy traffic and the above broad internal administrative-port sweep. The apparent DMZ web host therefore produces both persistent random-label DNS and wide internal discovery behavior. This is possible after compromise, but the combination is unusually concentrated in this one address across the visible window.
- [weak_signal] `zeek-core/conn.json` contains 1,889 TCP/8080 connections, nearly all to 10.10.3.20, while `zeek-core/http.json` contains 1,825 CONNECT requests. The destination is consistent with a proxy and proxy logs corroborate this traffic, so the volume alone is not a contradiction; the marked concentration is a weak texture signal only.

## Evidence For Real

- Zeek's network records have plausible source-native shapes and values. Across `zeek-core/conn.json` (11,956 records), `zeek-db/conn.json` (513) and `zeek-dmz/conn.json` (8,943), completed (`SF`) sessions dominate, while failed or partial states (`S0`, `RSTO`, `RSTR`, `REJ`, `S1`–`S3`, `OTH`) are also present. There are varied durations, byte counts, packet counts and history strings rather than a single uniform connection template.
- DNS has a believable mix of A, AAAA, PTR, SRV, TXT, MX, SOA and NS queries, with NOERROR, NXDOMAIN, SERVFAIL and REFUSED outcomes. For example, `zeek-core/dns.json` contains 2,227 A, 273 AAAA, 167 PTR and 101 SRV queries among 3,041 records; the SRV responses include an LDAP service record at 13:02:57 UTC with both domain controllers.
- HTTP and TLS activity includes both enterprise services and varied ordinary destinations. `zeek-dmz/http.json` contains CONNECT, GET and POST requests and a range of response codes; `zeek-dmz/ssl.json` contains both TLS 1.2 and 1.3 with contemporary cipher suites. The proxy log has distinct CONNECT tunnel metadata, user agents, status codes and tunnel byte/duration fields.
- Cross-log protocol references are internally consistent in the sampled Zeek data: every DNS, HTTP and SSL UID examined has a corresponding connection UID in its sensor's `conn.json`; HTTP/TLS timestamps fall within their matching connection interval. This alignment is valid positive evidence and is not treated as a synthetic clue by itself.
- Network alerts and observed traffic agree on concrete events. For example, the perimeter Snort SSH-scan alert at 15:15:02.826 UTC for `10.10.3.10:47058 -> 10.10.2.30:22` is close to the successful Zeek connection beginning at 15:15:02.524 UTC; DNS alert source, destination and query timing also align in the Zeek records.

## Detailed Analysis

### Connection patterns and services

The three Zeek sensors cover 13:00–19:00 UTC on 2026-11-02. Core traffic includes high DNS and Kerberos/LDAP volumes, proxy-bound TCP/8080, SMB, SSH, HTTP(S) and database connections. The DB sensor is strongly centered on 10.10.3.10 to 10.10.4.10 over TCP/3306 (320 records), which is a coherent application-to-database pattern. `zeek-core/conn.json` has 9,660 `SF` records and a nontrivial tail of incomplete/rejected/reset states. Many longer sessions are SSH or RDP-like, such as a successful SSH flow from 10.10.1.35 to 10.10.2.40 at 13:05:00 UTC with a 3,335-second duration, which is plausible for an interactive session.

The main exception is the subnet sweep from 10.10.3.10 at 14:40:45–14:40:50 UTC. Its 22/445/3306 attempts each cover nearly the same-sized population and mostly receive no response. That is technically possible as a fast scan, but the large, tightly bunched, count-matched probe set is a strong generator-like distribution feature.

### DNS and protocol behavior

Normal-looking internal resolution and service discovery coexist with suspicious domains. At 13:02:57 UTC, a DNS SRV lookup for `_ldap._tcp.dc._msdcs.meridianhcs.local` returns both domain controllers. By contrast, 10.10.3.10 repeatedly asks for fresh alphanumeric `.top` names for roughly 45 minutes, with results mostly NXDOMAIN and occasional `45.33.32.30` sinkhole answers. The recurring interval and naming texture, plus matching IDS alerts, support a real malicious-DNS interpretation but also make this family unusually regular for a live network sample. Other odd TLD queries are sparse and spread among clients, so the sustained `.top` stream is the notable concentration.

HTTP through the proxy is supported by matching Zeek CONNECT records on port 8080 and `PROXY-01.meridianhcs.local/proxy_access.log`; the proxy's extended tunnel byte and duration fields vary. TLS has a mix of TLSv1.2 and TLSv1.3 and cipher suites such as `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` and `TLS_AES_128_GCM_SHA256`. The dataset therefore does not exhibit a simple protocol-format or crypto-version defect.

### IDS, perimeter and collection-path correlation

`snort-perimeter/snort_alert.log` contains incoming scan/ping indicators and suspicious outbound DNS, SSH, and TLS alerts. Its alert for 10.10.3.10's SSH attempt to 10.10.2.30 at 15:15:02.826 UTC corresponds to the matching `zeek-dmz/conn.json` flow at 15:15:02.524 UTC, which ends successfully after about 13,316 seconds. The alert itself labels it a scan; a single alert does not establish a malformed flow. `fw-perimeter/cisco_asa.log` has plausible ASA build/teardown and translation records, including inbound SYN-timeout cases and outbound NAT construction. These records support a multi-vantage network view and do not show a broad source-native parsing flaw.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the score |
|---|---|---|---|
| `distribution_texture` | Zeek DNS and perimeter Snort | 10.10.3.10; recurring `.top` requests from 18:00–18:45 UTC | Many unique random-looking labels recur every 20–45 seconds, mostly NXDOMAIN, with repeated IDS hits over the same period. |
| `distribution_texture` | Zeek connection logs | 10.10.3.10 to internal 10.10.2.0/24; 14:40:45–14:40:50 UTC | Roughly 255 probes apiece to TCP 22 and 445 and 254 to 3306, mostly `S0`/zero-byte, concentrated in seconds. |
| `environment_or_collection_plausibility` | Zeek DNS/connection logs | One apparent DMZ web host | The same address carries persistent DGA-like traffic and broad internal administrative-port discovery, an unusual concentration though possible under compromise. |

## Realism Score by Category

- **Field format accuracy:** 9 — Zeek, proxy, ASA and Snort records use credible source-native fields and varied values.
- **Temporal patterns:** 6 — General traffic spans six hours with diverse durations; the `.top` cadence and five-second subnet scan are unusually regular/concentrated.
- **Cross-source correlation:** 9 — Sampled Zeek UID and protocol-time relationships are coherent, and IDS alerts line up with matching flows.
- **Behavioral realism:** 6 — Normal enterprise protocols coexist with plausible suspicious activity, but the repeated random-label DNS and broad service sweep are strongly patterned.
- **Environmental consistency:** 6 — Proxy, DMZ, DB and internal service roles mostly form coherent paths; the DMZ-origin internal scan and sustained suspicious DNS remain unusual.

## Recommendations

If this were synthetic, make the suspicious DNS family less uniform in duration, spacing, query outcomes and endpoint participation, or give the repeated queries a stronger visible reason in other network records. Vary or split the scan's target ports and timing so that the near-equal 22/445/3306 counts do not appear as one tightly bunched subnet sweep. Retain the realistic DNS, proxy, TLS, connection-state and multi-sensor correlation texture, which is strong in the reviewed logs.
