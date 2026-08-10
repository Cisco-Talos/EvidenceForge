# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 68
**Synthetic-Confidence Score:** 36

## Executive Summary

This looks more like sanitized production telemetry than a generated facsimile: the six-hour collection has believable source diversity, background contention, imperfect visibility, and an intrusion that remains technically coherent when pivoted across web, endpoint, Zeek, proxy, firewall, and Linux authentication evidence. The strongest concern is not a contradiction but an unusually dense, repetitive pattern of human SSH administration by a very small set of users, which gives part of the baseline a modeled feel.

## Evidence For Synthetic

- `[distribution_texture]` SSH administration is unusually dense for the visible six-hour window. Across the Linux syslogs I counted roughly 120 successful SSH authentications, heavily concentrated in three source identities: for example, `lina.nguyen` authenticated to `WEB-EXT-01` 16 times from `10.10.1.21`; `aisha.johnson` authenticated there 12 times from `10.10.1.35`; and `marcus.chen` authenticated to `MAIL-EDGE-01` 10 times from `10.10.1.31`. The same users repeatedly rotate through WEB, APP, DB, mail, and proxy hosts, often in short sessions.
- `[environment_or_collection_plausibility]` Direct interactive administration of the Internet-facing `WEB-EXT-01` is broader than I would expect in a mature environment. Between 12:00 and 18:00 UTC it accepts public-key SSH from at least `lina.nguyen`, `aisha.johnson`, `marcus.chen`, and `root`; at 13:39:26 it accepts root directly from workstation `10.10.1.22`. This is possible, but the number of broadly authorized users and direct-root access weakens the host-role realism.
- `[distribution_texture]` Several baseline command families recur with little variation across unrelated Linux hosts. The eCAR records contain 88 executions each of `debian-sa1 1 1` and its identical `/bin/sh -c 'command -v debian-sa1 ...'` wrapper, while common operator checks such as `ss -ltnp`, `systemctl is-active ...`, `grep ... /var/log`, and `cat /etc/passwd` recur across users and machines. Cron-driven `sysstat` explains the first pattern, but in aggregate the command vocabulary feels narrower and more reusable than a lived-in fleet.
- `[weak_signal]` The Windows Security mix is highly dominated by Event ID 5156 on every instrumented Windows host (for example 4,394 of 7,578 events on `DC-01`, 933 of 1,825 on `FILE-SRV-01`, and 513 of 869 on `WS-AJOHNSON-01`). A WFP-heavy audit policy can explain this, so I did not treat it as a contradiction, but the consistently similar source-family shape across roles is somewhat curated.

## Evidence For Real

- The collection covers about 18 named endpoints over 2024-03-18 12:00–18:00 UTC, with role-appropriate source families: Windows Security/Sysmon on Windows systems, syslog and shell history on Linux systems, eCAR across endpoints, two Zeek observation points, proxy, ASA firewall, Snort, SMTP, and web access telemetry. Volumes vary substantially by role rather than being equalized.
- The initial compromise is causally coherent. `WEB-EXT-01/web_access.log` records `185.70.41.45` posting to `/ehr/admin/upload.php` at 13:20:30; eCAR sees the inbound flow at 13:20:31.951, Apache-owned PID 581497 creating a base64-decoding reverse-shell command at 13:20:33.917, and that same PID connecting from `10.10.3.10:33230` to `45.33.32.30:8443` at 13:20:36.333. Zeek DMZ UID `CLfHpnmrjGNXZmSuRMR` observes a 15.166-second SF flow, and the ASA builds and tears down the same NATed connection at 13:20:34/13:20:49.
- Discovery pivots cleanly. In `WEB-EXT-01/ecar.json`, root PID 584875 launches `nmap -sT -p 22,80,443,445,3306 10.10.2.0/24` at 13:43:55.788; its child-attributed eCAR flows begin tens of milliseconds later and Zeek reports realistic mixed results (`SF`, `REJ`, `RSTO`, `S0`) against the requested ports.
- Lateral movement has the expected transport/auth/session sequence. `APP-INT-01/syslog.log` records connection from `10.10.3.10:44261` at 14:15:09, successful password authentication for root at 14:15:11, PAM open at 14:15:11.923, and logind session creation at 14:15:12.359. The matching Zeek SSH connection lasts 13,312 seconds and carries nontrivial bidirectional bytes, consistent with the later `cat /etc/passwd`, `cat /etc/shadow`, and cleanup commands tied to that session.
- The later data-staging/upload sequence is exceptionally well supported without a visible contradiction. `FILE-SRV-01` records `svc_mhsync` using PowerShell `Compress-Archive` at 16:20:37.693 to create `C:\ProgramData\Microsoft\cache_7f3a.zip`. On `WS-AJOHNSON-01`, PowerShell copies that archive from the administrative share into the user's Temp directory at 16:42:34.824; Chrome PID 8416 reads it at 16:42:35.371 and connects through `PROXY-01` at 17:25:11.458. The proxy records a POST to `/upload/telemetry/7f3a2b19` with `cs_bytes=314782706`; both Zeek observation points, the proxy-origin TLS leg, and ASA teardown volumes agree at the appropriate layer.
- Network baseline is not one-state or one-protocol. `zeek-core/conn.json` contains 6,087 `SF` along with `RSTO`, `RSTR`, `S0`, `REJ`, `OTH`, `S2`, and `S3`; the DMZ sensor has 1,241 `S0` connections consistent with Internet scanning. DNS includes A, AAAA, PTR, SRV, TXT, NXDOMAIN, SERVFAIL, and REFUSED behavior. Web traffic includes normal browsing, cache hits, redirects, authentication failures, bot traffic, proxy denies, and server-side application/database chatter.
- Collection is not implausibly pristine. The two Zeek sensors see some routed flows with slightly different timestamps and distinct UIDs, endpoint FLOW events sometimes omit process identity, proxy denies coexist with successful tunnels, and process/session starts and ends are not universally paired inside the bounded window. Those are normal consequences of vantage point and collection timing.

## Detailed Analysis

### Orientation and source mix

The visible window is approximately 12:00:00–17:59:57 UTC on 18 March 2024. Endpoint names imply user workstations (`WS-*`, `LT-*`), core Windows services (`DC-01`, `FILE-SRV-01`, `MAIL-FIN-01`), Linux application/database/mail systems, an external web server, and an explicit proxy. The main network segments appear to be user `10.10.1.0/24`, server `10.10.2.0/24`, DMZ `10.10.3.0/24`, and database `10.10.4.0/24`. This topology is internally stable across endpoint and network records.

The source mix is broad but role-shaped. The two Zeek sensors contain 11,730 connection records total, with core traffic dominated by DNS, Kerberos, SMB, proxy, and LDAP, while the DMZ includes 1,862 port-443 flows, Internet scan failures, proxy traffic, and web/database activity. The perimeter ASA has 12,184 records and the proxy has 2,146 requests. `WEB-EXT-01` has 804 access records and substantial unsolicited scan noise. This is enough background that the malicious activity must be found through pivots rather than simply selecting the only unusual row.

### Initial access and execution

At 13:20:30, `185.70.41.45` posts to `/ehr/admin/upload.php` and receives HTTP 200. The inbound TLS connection (`185.70.41.45:55812 -> 10.10.3.10:443`) is visible in eCAR, Zeek DMZ UID `CXkly27XMEUk6y2oHja`, and the ASA. Apache logs a SQL syntax/UNION message at 13:20:35.702. Meanwhile Apache worker PID 23965 creates PID 581497 running a base64-decode-to-bash command; decoding is not required to see that its literal command embeds `/dev/tcp/45.33.32.30/8443`. The associated endpoint FLOW starts at 13:20:36.333, Zeek sees the same tuple from 13:20:34.536 for 15.166 seconds, and the ASA reports 3,000 total bytes before normal FIN teardown. The small sub-second differences are consistent with sensor and endpoint reporting delays, not inverted causality.

### Privilege, discovery, and lateral movement

At 13:39:23–13:39:26, `WEB-EXT-01` accepts direct root SSH from `10.10.1.22`. That session then performs host/network discovery (`ip addr show`, `/etc/hosts`, `/etc/resolv.conf`), searches `/opt/ehr` for credential material, and launches both ping and TCP nmap scans. The nmap flows are attributed to the correct PID in eCAR and appear twice only where the core and DMZ Zeek sensors both have visibility, with distinct UIDs and a consistent ~49 ms sensor offset.

At 14:15, the web host establishes SSH to `APP-INT-01` as root. The transport precedes accepted-password and PAM/logind evidence. Commands tied to the same long-lived session later read `/etc/passwd` at 14:34:47 and `/etc/shadow` at 14:35:03. At 16:34:22, that APP session launches `ssh root@DB-PROD-01`; eCAR observes the flow at 16:34:39 and Zeek observes a 2,204-second SSH connection from `10.10.2.30` to `10.10.4.10`. I found no visible dependent event preceding its initiating transport or authentication.

### Staging, covert traffic, and exfiltration

Core DNS shows a dense sequence of randomized TXT queries from `10.10.2.30` under `ns1.westbridge-services.cloud` beginning around 16:05 UTC. The host concentration, high-entropy labels, varied subdomain shapes, and TXT answers form a plausible DNS-tunneling signal distinct from ordinary SPF/DKIM/DMARC lookups elsewhere in the file.

At 16:20:37, `FILE-SRV-01` service account `svc_mhsync` stages finance and patient export data into `cache_7f3a.zip`. At 16:42:34, `WS-AJOHNSON-01` copies that file locally, and Chrome reads the exact object 547 ms later. At 17:25:11, the client-to-proxy connection carries 314,782,997 origin bytes in both Zeek views; the proxy log reports 314,782,706 tunneled/upload bytes; the proxy-to-origin Zeek leg carries 315,244,670 bytes; and ASA teardowns report 326,219,817 and 332,949,663 bytes for the two legs. The size differences are directionally sensible for TCP/IP, proxy, and TLS overhead rather than suspicious equality.

### Signal-to-noise and collection realism

The malicious sequence is identifiable but not isolated. Web scanning from several recurring external addresses generates many `S0` connections and UFW blocks. Windows endpoints show ordinary application starts, scheduled health/backup scripts, Windows filtering events, Kerberos/LDAP/SMB traffic, update traffic, and interactive logon churn. Linux systems include cron/sysstat, systemd, journald/log rotation, sudo/PAM, package/update, rsyslog queue, and service-health noise. Proxy browsing uses multiple browser generations and Linux/Windows user agents, with `200`, `301`, `304`, `403`, `407`, `502`, `503`, and `504` outcomes.

The most artificial-looking element is the density and breadth of interactive SSH. The three most active administrators repeatedly open sessions to several sensitive roles throughout the entire six-hour period. That could reflect an operations-heavy organization or automation driving interactive-looking sessions, but it is a meaningful texture concern because it affects visible source volume and host-role behavior rather than merely making the intrusion easy to narrate.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `distribution_texture` | Linux syslog, eCAR, Zeek SSH | Dataset-wide across Linux servers | Approximately 120 successful SSH authentications, concentrated in a few users repeatedly traversing many hosts, is the clearest modeled-looking baseline pattern. |
| `environment_or_collection_plausibility` | WEB-EXT syslog/eCAR/Zeek | Repeated on one sensitive host | Broad direct SSH and direct-root access to the Internet-facing web host is possible but operationally unusual. |
| `distribution_texture` | Linux eCAR/process telemetry | Repeated across hosts | Identical cron commands are explainable, but the broader recurring administrative command pool is comparatively narrow. |
| `weak_signal` | Windows Security | Dataset-wide on instrumented Windows hosts | Event 5156 consistently dominates the channel; plausible policy choice, but the uniform family shape appears curated. |

## Realism Score by Category

- **Field format accuracy:** 9 — The inspected web, syslog, eCAR, Zeek, proxy, ASA, and Windows fields are source-appropriate and carry plausible identifiers, values, and precision.
- **Temporal patterns:** 8 — Attack prerequisites and effects are correctly ordered across the visible window, with believable sensor delays and mixed background timing; repetitive SSH activity is the main deduction.
- **Cross-source correlation:** 9 — Tuples, UIDs within each Zeek sensor, PIDs, users, host addresses, proxy legs, and byte volumes support reliable pivots without a concrete contradiction.
- **Behavioral realism:** 7 — Tradecraft and background actions are technically convincing, but the small set of users repeatedly administering many servers creates a somewhat modeled operational rhythm.
- **Environmental consistency:** 7 — Network zones and host roles are coherent, though direct-root SSH to the external web host and similarly shaped Windows audit mixes are weaker points.

## Recommendations

- If this were synthetic, reduce or better differentiate interactive SSH churn. Give each administrator a smaller, role-appropriate host set; mix long-lived multiplexed sessions, noninteractive automation, bastion-mediated access, and days with no direct login instead of repeatedly opening short sessions to many servers.
- If this were synthetic, harden the external web host's normal administrative path: route routine access through a bastion or management subnet, make direct root rare or disabled, and reserve any direct-root event for activity that has clear preceding credential/key acquisition evidence.
- If this were synthetic, expand per-user Linux command vocabularies and workflows so repeated operational checks reflect stable specialties (database, mail, application, network) rather than a shared pool of `systemctl`, `grep`, `ss`, and file-inspection commands.
- If this were synthetic, vary Windows collection profiles by role where operationally justified—for example, a DC, file server, and user workstation should not all present nearly the same WFP-dominant Security-channel texture unless a documented central audit policy intentionally creates it.
