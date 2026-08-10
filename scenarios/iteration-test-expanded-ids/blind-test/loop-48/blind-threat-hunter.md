# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 76
**Synthetic-Confidence Score:** 39

## Executive Summary

This six-hour collection is operationally convincing and generally production-like: suspicious activity can be hunted across web, endpoint, Zeek, firewall, proxy, Windows, and Linux evidence without visible impossible ordering. The main doubts come from repeated broad SSH administration patterns and a few collection/distribution choices that feel modeled, but they are moderate indicators rather than decisive contradictions.

## Evidence For Synthetic

- `[environment_or_collection_plausibility]` SSH administration is unusually broad for a six-hour window. Syslog shows `aisha.johnson` accepted on APP-INT-01 (2), DB-PROD-01 (8), MAIL-CLIN-01 (8), MAIL-EDGE-01 (10), PROXY-01 (8), and WEB-EXT-01 (9); `marcus.chen` is similarly accepted on all six server roles (5, 7, 7, 6, 4, and 7 respectively). Centralized identities can explain this, but 81 accepted sessions for just these two named users across application, database, mail, proxy, and public-web roles in six hours is an unusually dense and role-insensitive administration texture.
- `[distribution_texture]` Several exact fleet command lines recur across otherwise different Windows roles, including `powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Scripts\service-health.ps1` on DC-01, FILE-SRV-01, MAIL-FIN-01, and multiple workstations, plus `backup-check.ps1` on workstations. Fleet automation is plausible, but the small shared vocabulary is more repetitive than the long tail normally produced by independently maintained endpoints.
- `[environment_or_collection_plausibility]` Windows Security volume is heavily concentrated in filtering-platform events: 4,374 of 7,566 Security events on DC-01 and 1,007 of 2,026 on FILE-SRV-01 are Event 5156. This can result from intentional audit policy, but the similarly narrow mix across the sampled workstations makes the collection look highly curated rather than like a broad native channel export.
- `[weak_signal]` DC-01 records `wevtutil cl Security` and Event 1102 at about 17:41:49, while the supplied Security XML retains both earlier records and new records through 17:59:59. Forwarded or continuously collected telemetry makes this possible; absent explicit collector metadata, it is only a collection-plausibility question and not a contradiction.

## Evidence For Real

- The source-family scale is believable for a small enterprise slice: 18 eCAR host files with 24,639 records; 13,861 Security and 4,016 Sysmon events on nine Windows hosts; 11,404 Zeek connections; 3,009 DNS, 2,051 HTTP, and 1,714 TLS records; 11,670 ASA lines; 4,292 Linux syslog lines; 1,668 proxy requests; and 187 IDS alerts. Suspicious records remain a minority inside substantial baseline activity.
- Internet background noise is convincing. The DMZ sensor has 5,230 connections, including 1,240 `S0`, 118 `RSTO`, 62 `RSTR`, and 20 `REJ` records, while WEB-EXT-01 carries 1,021 kernel/UFW messages and the ASA shows short SYN timeouts against varied exposed ports. This resembles ordinary scanning pressure rather than a pristine attack-only feed.
- The initial compromise pivot is technically coherent. At 13:19:36, `185.70.41.45` posts to `/ehr/admin/upload.php`; at 13:19:38.580 an Apache-owned `/bin/bash` process runs as `www-data`; at 13:19:38.794 Zeek sees `10.10.3.10:51084 -> 45.33.32.30:8443` with `SF`; at 13:19:38 the ASA builds the matching NAT and outbound connection; and at 13:19:40.210 eCAR reports that same tuple and process identity. The small sensor/endpoint timestamp differences look like collection latency, not copied timestamps.
- Later pivots remain huntable across roles: DC-01 creates and elevates `svc_mhsync` around 16:15, installs an hourly `DeviceSync` task around 16:19, FILE-SRV-01 runs `Compress-Archive` as that account at 17:01, and WS-AJOHNSON-01 copies the resulting `cache_7f3a.zip` at 17:20. These records preserve host, account, process, path, and timing continuity.
- Baseline activity has useful heterogeneity. Core Zeek traffic is dominated by DNS/Kerberos/SMB/proxy services, whereas DMZ traffic is dominated by HTTPS/proxy/DNS/MySQL and hostile probes. TLS is split between TLS 1.2 and 1.3, DNS includes A/AAAA/PTR/SRV/TXT, proxy clients have different browsers and destinations, and Linux program mixes vary by host role (Postfix on mail hosts, multipath on the database, Apache/UFW on the public web server).
- Bounded beginning/middle/end samples did not reveal dependent activity whose same-identifier initiator appears later in the visible window. Login/logout and process create/terminate count differences are consistent with a slice-of-time collection and were not treated as synthetic evidence.

## Detailed Analysis

### Orientation and bounded review method

The visible window is approximately 2024-03-18 12:00:00Z through 17:59:59Z. I reviewed source inventories and aggregate counts, then bounded beginning/middle/end records for each major family, plus narrow windows around 13:18-13:21, 15:58-16:21, 17:00-17:22, and 17:40-17:51. The environment contains nine Windows-instrumented hosts, nine Linux/syslog hosts (with some overlap only through eCAR naming), core and DMZ Zeek sensors, perimeter ASA and Snort sources, a proxy, and a public web server.

### Operational lifecycle and tradecraft

The strongest suspicious chain begins with the 13:19:36 upload POST from `185.70.41.45`. The Apache parent, `www-data` principal, decoded `/dev/tcp/45.33.32.30/8443` behavior, Zeek tuple, and ASA NAT evidence form a usable initial-access-to-command-and-control pivot. It is followed by plausible discovery and movement: `nmap -sn 10.10.2.0/24` at 13:53:30 and `nmap -sT -p 22,80,443,445,3306` at 13:58:06 on WEB-EXT-01, later Windows identity manipulation and scheduled-task persistence, archive collection, remote file retrieval, encoded PowerShell, Security-log clearing, and eventual `svc_mhsync` deletion at 17:49:46.

The commands are syntactically usable and run under principals consistent with the shown host state (`www-data` after web execution, `root` on Linux, `SYSTEM` on DC-01, and `svc_mhsync` for collection). I found no visible network/authentication inversion in the sampled pivots. In particular, the reverse-shell Zeek connection begins about 216 ms after process creation and the endpoint FLOW arrives later, a reasonable source-latency relationship.

### Signal-to-noise and source-family mix

The attack is discoverable but not isolated. Core Zeek has 6,174 connections, of which 5,975 are `SF`; DMZ Zeek has 5,230 with a much noisier state distribution, including 1,240 `S0`. Core DNS has 2,258 queries with A (1,367), TXT (365), AAAA (296), PTR (151), and SRV (68); DMZ DNS adds 751. Proxy traffic is user-skewed but plausible: 10.10.1.21 generates 477 of 1,668 requests across 65 hosts, while other workstations range from 71 to 208 and servers contribute much smaller update/service volumes.

Host telemetry also supplies a workable haystack. DC-01 alone contains 7,566 Security and 578 Sysmon events; FILE-SRV-01 has 2,026 and 430. Windows endpoint process-create counts range from 63 to 153 per host in six hours, with matched but not perfectly identical terminate counts. Linux sources include cron, package/update, DHCP, NetworkManager, Postfix, multipath, irqbalance, snapd, SSH/PAM, and UFW noise rather than only shell commands.

### Pivot feasibility

IP and host roles remain stable in the sampled evidence: DC-01 is 10.10.2.10, FILE-SRV-01 is 10.10.2.20, APP-INT-01 is 10.10.2.30, WEB-EXT-01 is 10.10.3.10, and PROXY-01 is 10.10.3.20. eCAR source/destination tuples agree with Zeek for the initial reverse shell and with the ASA translation. Authentication, process, and file pivots expose durable identifiers and principal names, while protocol logs preserve Zeek UIDs across relevant companion records. I did not penalize this completeness; it materially helps hunting and did not reveal a concrete contradiction.

### Environment and collection texture

The main realism weakness is identity placement. Repeated interactive SSH by the same named accounts across public web, mail edge, clinical mail, proxy, application, and database systems would normally imply a clearly privileged operations team, a jump host, or centralized automation. The raw logs do not make that role boundary obvious, and direct accepts appear on each target. This is possible, but it reduces confidence more than the attack sequence itself.

The Windows event mix also looks deliberately selected, with 5156 representing roughly half or more of Security events on major hosts and relatively compact process vocabularies. A tuned collector can produce exactly this, so it should not be confused with missing-source evidence. The Security-log clear caveat is similarly conditional: a forwarder can retain pre-clear events, but a local after-the-fact export ordinarily cannot.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `environment_or_collection_plausibility` | Linux SSH/syslog | Repeated across six server roles | Broad, high-frequency use of the same named identities weakens host-role realism, but remains operationally possible. |
| `distribution_texture` | Windows process/eCAR/Security/Sysmon | Repeated across several host roles | Small exact shared PowerShell maintenance vocabulary suggests modeled fleet noise; centralized scripts are an adequate alternative explanation. |
| `environment_or_collection_plausibility` | Windows Security | Dataset-wide collection choice | Event 5156 dominates major host Security volumes, giving the available channel a curated texture rather than a broad export. |
| `weak_signal` | DC-01 Security/process | One cleanup sequence | Pre-clear and post-clear records coexist; plausible with forwarding, questionable for a local export, and therefore low weight. |

## Realism Score by Category

- **Field format accuracy:** 9 — Sampled Zeek, ASA, proxy, syslog, Windows, and eCAR values are source-shaped and operationally usable.
- **Temporal patterns:** 8 — Baseline activity is jittered and the sampled attack pivots preserve causal ordering; repeated fleet jobs remain somewhat templated.
- **Cross-source correlation:** 9 — Web, endpoint, Zeek, firewall, authentication, and file pivots align without a sampled hard contradiction.
- **Behavioral realism:** 7 — Tradecraft is technically coherent, but repeated direct SSH activity by the same users across many sensitive roles is unusual.
- **Environmental consistency:** 7 — Segmentation and service placement are strong; identity authorization texture and the narrow Windows audit mix are less convincing.

## Recommendations

- If this were synthetic, vary routine SSH administration by role and authorization boundary: concentrate direct access on appropriate operators or jump hosts, reduce repeated cross-role accepts, and retain occasional justified exceptions with source-host evidence.
- Expand the long tail of fleet maintenance commands and software-specific tasks while preserving centrally managed scripts where appropriate. Differentiate workstation, domain-controller, mail, file, and database maintenance vocabularies instead of reusing the same small set everywhere.
- Make the Windows collection profile explicit in log-visible metadata or broaden the Security event-volume mix so the high proportion of 5156 events reads as an intentional sensor policy rather than a generated selection.
- When modeling log clearing, provide a visible forwarding/collector context if both pre-clear history and post-clear host events are retained; otherwise constrain the local export to what would remain after the clear.
