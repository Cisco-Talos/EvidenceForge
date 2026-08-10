# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 53

## Executive Summary

This is a strong, huntable collection whose suspicious lifecycle is operationally coherent across web, endpoint, proxy, Zeek, firewall, and authentication evidence. The main reason I cannot call it real is a repeated baseline pattern in which Linux systems launch similarly shaped root-owned proxy checks and wget probes against a constantly changing pool of unrelated public services; that distribution looks constructed, while the attack pivots and source volumes otherwise look production-like.

## Evidence For Synthetic

- `[distribution_texture]` A common outbound-probe family appears across four Linux hosts: 30 `/opt/meridian/bin/proxy_healthcheck.py` executions on `APP-INT-01`, eight on `MAIL-CLIN-01`, 22 proxy-configured root `wget` executions on `DB-PROD-01`, and 21 on `WEB-EXT-01`. Across the six-hour window these 81 executions rotate through 62 distinct public targets, including advertising, analytics, package, font, monitoring, and CDN names. Examples include `tracking.pollfish.io` at 12:29:35, `analytics.segment.com` at 12:30:40, `widget.uptime.co` at 12:50:01, `api.snapcraft.io` at 15:05:59 and 17:30:47, and `proxy.mixpanel.com` at 17:39:41. A real health check normally exercises one or a small stable set of configured destinations; this broad target churn looks like a data-generation pool.
- `[environment_or_collection_plausibility]` Windows users `aisha.johnson` and `marcus.chen` repeatedly initiate SSH to nearly every modeled Linux service from their workstations. The endpoint records contain 48 Aisha SSH client process launches and 40 Marcus launches in six hours, spanning `WEB-EXT-01`, `MAIL-EDGE-01`, `MAIL-CLIN-01`, `APP-INT-01`, `DB-PROD-01`, and `PROXY-01`. This could fit two infrastructure administrators, but the breadth and frequency, combined with RDP and file-server activity, is unusually dense for a 15-host healthcare environment and resembles generalized lateral-movement background texture.
- `[distribution_texture]` The same two Linux operational motifs recur on unrelated systems with limited host-specificity: root-owned PID-1 children perform proxy-aware `wget`, while a shared `/opt/meridian/bin/proxy_healthcheck.py` probes an ever-changing external hostname. The hostnames and timing are varied, but the behavioral grammar remains strikingly uniform across application, database, clinical-mail, and internet-facing web roles.
- `[weak_signal]` The collection is unusually favorable to investigation: endpoint objects, Security/Sysmon, proxy, dual Zeek views, firewall translations, and IDS records frequently expose the same pivots. Completeness alone is not an authenticity indicator, and I did not score it as one; it only makes the repeated baseline families easier to recognize.

## Evidence For Real

- The visible intrusion lifecycle is technically plausible. `185.70.41.45` performs Nikto-style enumeration from 12:31 through 12:59, then SQL injection attempts appear at 12:59:49 and an upload to `/ehr/admin/upload.php` succeeds at 13:20:30. `WEB-EXT-01` creates a `www-data` bash process at 13:20:33 and opens a reverse-shell connection to `45.33.32.30:8443` at 13:20:36; Zeek records the corresponding 15.166-second `SF` flow and the ASA records its build and teardown.
- Cross-source pivots retain source-native differences rather than collapsing to identical records. The two Zeek sensors use different UIDs and slightly different observation timestamps for the same client-to-proxy transaction, while ASA records NAT state and endpoint eCAR records the owning process. That is consistent with independent observation points.
- The data-staging and exfiltration path is coherent. `svc_mhsync` creates `C:\ProgramData\Microsoft\cache_7f3a.zip` on `FILE-SRV-01` at 17:00:37; Aisha's workstation copies it to her local Temp directory at 17:22:34, Chrome reads it at 17:22:35, and a proxy transaction begins at 17:25:11. Zeek observes 314,782,997 client-origin bytes to the proxy and 315,244,670 proxy-origin bytes to `45.33.32.30:443`; ASA teardown totals are appropriately larger because they include both directions and transport overhead.
- Proxy semantics are convincing. The exfiltration has a CONNECT control record followed by a POST to `/upload/telemetry/7f3a2b19`; the proxy reports 314,782,706 client bytes and a matching 11.644-second tunnel. Denied CONNECTs terminate without origin traffic, while inspected/tunneled requests carry separate control and payload byte scopes.
- The collection has believable noise and imperfect outcomes: internet scans against the DMZ, `S0`, `REJ`, reset and partial connection states, failed SSH attempts, denied proxy requests, NXDOMAIN/SERVFAIL DNS responses, DHCP, Kerberos, LDAP, SMB, NTP, software-update traffic, cron/systemd noise, and routine user browsing. Malicious activity is not the majority of records.
- Temporal behavior is not mechanically uniform. User browsing arrives in bursts with dependent assets, infrastructure traffic continues throughout the window, phpsession cleanup has jitter around a roughly half-hour cadence, TCP durations vary widely, and failed inbound scans time out differently from successful sessions.

## Detailed Analysis

### Scope and collection profile

The visible interval is approximately 12:00:00 through 17:59:58 UTC on 18 March 2024. There are 15 named endpoint/server hosts: seven Linux systems (including application, database, mail, proxy, public web, and two Linux workstations) and eight Windows systems (a domain controller, file server, finance mail server, and user workstations). Available families include Security and Sysmon XML, eCAR endpoint JSON, Linux syslog and bash history, proxy and web access logs, core and DMZ Zeek protocol logs, ASA firewall records, and core/perimeter Snort alerts.

Volume is believable for a deliberately rich six-hour capture rather than a tiny narrative extract. I counted 7,652 Security records on `DC-01`, 1,825 on `FILE-SRV-01`, 492-874 on individual Windows endpoints, 11,730 Zeek connections across the two sensors, 2,146 proxy lines, and 12,184 ASA lines. Connection-state texture includes 10,072 `SF`, 1,261 `S0`, 176 `RSTO`, 119 `RSTR`, 33 `REJ`, and smaller tails of `S1`/`S2`/`S3`/`OTH`.

### External access and execution

The web intrusion can be followed without relying on a single source. `WEB-EXT-01/web_access.log` shows sustained reconnaissance from `185.70.41.45`, including `/info.php`, `/phpMyAdmin`, `/admin`, and XML-RPC probes. At 12:59:49 the same source sends `admin' OR '1'='1` and a `UNION SELECT username,password FROM users` request, both returning 500. At 13:20:30 it receives HTTP 200 from `/ehr/admin/upload.php`. Three seconds later eCAR records Apache PID 23965 spawning PID 581497 as `www-data` with a base64-decoded bash reverse shell, followed at 13:20:36 by outbound `10.10.3.10:33230 -> 45.33.32.30:8443`.

That transport has no impossible visible ordering. `zeek-dmz/conn.json` begins the flow at 13:20:34.536, reports `SF`, 620 origin bytes, 1,840 response bytes, and 15.166 seconds duration. The perimeter ASA builds the outbound connection at 13:20:34 and tears it down at 13:20:49 with 3,000 bytes and TCP FINs. Differences between endpoint creation, sensor observation, and firewall accounting are small and source-plausible.

### Internal movement and privilege use

Subsequent evidence shows broad administrative access through SSH, RDP, SMB, and remote-service mechanisms. The most consequential Windows path creates domain account `svc_mhsync`, adds it to Domain Admins, creates `DeviceSyncSvc`, and schedules `\Microsoft\Windows\Maintenance\DeviceSync`; later that account runs the file-server archive operation. The commands, principals, network paths, and service-account use align well enough to support hunting pivots. Cleanup later clears the Security log and deletes `svc_mhsync`, which is also operationally plausible.

The collection-window caveat matters here: some session starts or ends fall outside the slice, and I did not treat unmatched lifecycle edges as contradictions. Likewise, several local or SSH administrative sessions could explain otherwise surprising root and sudo activity. The concern is distributional rather than causal: Aisha and Marcus generate 88 SSH client processes across six Linux targets in only six hours, and the same remote-access style appears across many destinations. Without organization context I cannot prove that this is impossible, so I weighted it below the repeated external-probe family.

### Collection and baseline realism

Most background traffic is strong. The Windows estate produces machine-account, user, service, anonymous, and local-service logons; the network shows Kerberos, LDAP, SMB, DNS, HTTP/S, SSH, database, DHCP, NTP, and internet scanning; Linux syslog includes cron, package maintenance, systemd, resolver, SSH, kernel firewall, rsyslog, and sudo activity. Browser sessions have dependent assets and plausible referers rather than only one isolated request per site.

The weakest baseline behavior is the public-target churn. `APP-INT-01` repeatedly launches the same root-owned health-check script while changing targets from one unrelated SaaS or ad-tech hostname to another. `MAIL-CLIN-01` uses the same script and path. `DB-PROD-01` and `WEB-EXT-01` exhibit a sibling pattern with root-owned proxy-configured `wget` commands to another changing destination pool. The timing is jittered and the names look plausible individually, but the combined fleet behavior lacks the stable target configuration expected of actual service checks. This is the single largest driver of the synthetic-confidence score.

### Exfiltration pivot

The final high-volume pivot is particularly well constructed. On `FILE-SRV-01`, PID 5772 runs `Compress-Archive` as `svc_mhsync` at 17:00:37 and creates `cache_7f3a.zip`. At 17:22:34, Aisha's workstation uses PowerShell `Copy-Item` to copy the archive from the administrative share, then Chrome PID 8416 reads the local copy. At 17:25:11 the same Chrome process opens `10.10.1.35:62915 -> 10.10.3.20:8080`; Squid opens `10.10.3.20:48838 -> 45.33.32.30:443`. The proxy logs a POST upload, both Zeek perspectives capture the tunnel with independent UIDs, and ASA captures both legs and the dynamic translation. Packet counts and byte totals are not bit-identical but are directionally and numerically consistent.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the synthetic-confidence score |
|---|---|---|---|
| `distribution_texture` | Linux eCAR, proxy/network | Repeated across four hosts; 81 executions and 62 distinct targets | A shared probe grammar rotates through unrelated public destinations far more broadly than stable production health checks normally would. |
| `environment_or_collection_plausibility` | Windows eCAR, SSH/network, Linux sessions | Repeated across two users and six destinations | Eighty-eight SSH launches from two workstations in six hours create unusually dense cross-role administrative access, though an IT-admin explanation remains possible. |
| `distribution_texture` | Linux process baseline | Cross-host family | Application, database, mail, and public-web roles share the same root-owned outbound-check motifs with limited role-specific specialization. |
| `weak_signal` | Whole collection | Dataset-wide | Rich collection makes repeated patterns conspicuous, but completeness itself was not scored as synthetic evidence. |

## Realism Score by Category

- **Field format accuracy:** 9 — The reviewed eCAR, Zeek, proxy, web, syslog, and ASA fields are internally usable and source-appropriate, with no obvious impossible values in the key pivots.
- **Temporal patterns:** 8 — Attack ordering, transport timing, browsing bursts, failures, and infrastructure cadence are credible; only the repeated probe family feels generated.
- **Cross-source correlation:** 9 — Web execution, reverse shell, service-account activity, staging, and exfiltration pivot cleanly while preserving realistic sensor-specific timestamps, UIDs, and byte accounting.
- **Behavioral realism:** 6 — The intrusion tradecraft works, but the rotating health-check/wget destinations and very broad SSH use weaken the lived-in feel.
- **Environmental consistency:** 7 — Host roles and source volumes mostly fit a small enterprise, though shared outbound-probe behavior crosses roles too uniformly.

## Recommendations

- If this were synthetic, make operational probes configuration-stable: assign each health-check process one or a small host-role-specific target set and reuse those targets over time. Reserve broad destination diversity for browser activity, package managers, telemetry agents, or explicit egress-testing jobs whose command names and cadence explain it.
- If this were synthetic, separate Linux role behavior more sharply. Database hosts should emphasize repository mirrors, backup targets, monitoring, and database dependencies; public web hosts should emphasize application upstreams and update repositories; mail hosts should emphasize mail relays, reputation services, and vendor endpoints.
- If this were synthetic, reduce or better contextualize the 88 SSH launches from Aisha and Marcus. Concentrate remote administration on designated jump hosts or a smaller administrator/destination matrix, or add stable job/tool context that explains why two desktop users repeatedly touch nearly every Linux role.
- Preserve the current multi-source attack contracts. The reverse-shell, proxy, dual-sensor, NAT, staging, and high-volume exfiltration relationships are strong and should remain source-native rather than being simplified.
