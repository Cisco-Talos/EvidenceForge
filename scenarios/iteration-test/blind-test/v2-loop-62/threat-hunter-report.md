# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 82  
**Synthetic-Confidence Score:** 68

## Executive Summary

The dataset is highly realistic in format, traffic diversity, host-role behavior, and attack-chain correlation. However, four SSH sessions exhibit the same concrete identity defect: eCAR records and near-simultaneous `systemd-logind` removals assign different session IDs to what is visibly the same session. That repeated contradiction, reinforced by smaller cross-host distribution fingerprints, makes synthetic the more likely verdict.

## Evidence For Synthetic

- `[hard_contradiction]` Four Linux SSH sessions have contradictory session identities across endpoint sources:

  - APP-INT-01: eCAR logs session `378754` out at `17:16:39.458`, while syslog removes session `376301` at `17:16:39.434`.
  - DB-PROD-01: eCAR session `278296` logs out at `16:00:24.682`, while syslog removes `276613` at `16:00:25.324`.
  - WEB-EXT-01: eCAR session `351238` logs out at `14:58:49.449`, while syslog removes `350485` at `14:58:50.526`.
  - LOG-MON-01: eCAR session `39130` logs out at `13:09:44.915`, while syslog removes `38934` at `13:09:46.671`.

  These are not separate identifier namespaces: other sessions match exactly between these sources—for example, APP-INT-01 session `377123` appears in both [eCAR](/Users/dabianco/projects/SURGe/EvidenceForge/scenarios/iteration-test/blind-test/v2-loop-62/review-data/data/APP-INT-01.meridianhcs.local/ecar.json:223) and [systemd-logind](/Users/dabianco/projects/SURGe/EvidenceForge/scenarios/iteration-test/blind-test/v2-loop-62/review-data/data/APP-INT-01.meridianhcs.local/syslog.log:137).

- `[contract_gap]` The four affected SSH sessions begin visibly inside the collection window in eCAR/network telemetry, but their syslog records contain only the closing `pam_unix` message and mismatched `Removed session` message. For example, APP-INT-01 has the inbound flow, `sshd` process creation, login, file creation, and logout in [eCAR lines 661–666](/Users/dabianco/projects/SURGe/EvidenceForge/scenarios/iteration-test/blind-test/v2-loop-62/review-data/data/APP-INT-01.meridianhcs.local/ecar.json:661), but [syslog lines 208–209](/Users/dabianco/projects/SURGe/EvidenceForge/scenarios/iteration-test/blind-test/v2-loop-62/review-data/data/APP-INT-01.meridianhcs.local/syslog.log:208) omit the connection/authentication/open sequence and close a different session ID.

- `[distribution_texture]` Linux daemon record counts repeat unusually exact templates across dissimilar servers and workstations: `anacron=5` on 10 of 11 Linux hosts, `dbus-daemon=8` on 10 of 11, and `systemd-resolved=4` on 9 of 11. Individual daemon lifecycles can naturally have fixed message counts, but the repeated combination across mail, file, proxy, application, web, monitoring, and workstation roles produces a generator-like cross-host signature.

- `[weak_signal]` On WS-AJOHNSON-01, the staging PowerShell process runs as `MERIDIANHCS\aisha.johnson` at Medium integrity but is a direct child of `svchost.exe` running as `NETWORK SERVICE`; the exfiltration `curl.exe` is likewise a Medium-integrity Aisha process directly parented by `services.exe` as SYSTEM. Token impersonation or specially configured services could explain this, but the ancestry is atypical for the apparent remote-execution activity.

## Evidence For Real

- The six-hour window contains a believable source mix and volume for 21 hosts across workstation, domain-controller, mail, file, application, database, proxy, monitoring, and DMZ roles. Examples include 11,553 core Zeek connections, 8,663 DMZ connections, 20,448 ASA records, 3,013 core DNS records, and 2,887 proxy transactions.

- Network telemetry has substantial entropy. Core Zeek connections include `SF`, `S0`, `RSTO`, `RSTR`, `REJ`, `OTH`, `S1`, `S2`, and `S3` states; numerous TCP history strings; durations from sub-millisecond to several hours; and varied packet loss or `missed_bytes`.

- DNS includes A, AAAA, TXT, PTR, SRV, MX, NS, and SOA traffic, with `NOERROR`, `NXDOMAIN`, `SERVFAIL`, and `REFUSED` outcomes. HTTP includes CONNECT, GET, and POST; authentication failures and 3xx/4xx/5xx responses; and diverse browser, OS, update, and programmatic user agents.

- Host telemetry is role-sensitive rather than generically duplicated. FILE-LNX-01 contains `smbd` and `smbd_audit`; mail hosts contain Postfix and Dovecot; DB-PROD-01 has multipath activity; and Linux workstations show NetworkManager, DHCP, GNOME, PackageKit, and desktop-service traffic.

- The suspicious activity is technically coherent. Transport precedes authentication, child processes follow session creation, files exist before transfer, and transfer tuples and sizes agree across endpoint and network sources.

- Sensor observations are not bit-identical clones. The 17:24 exfiltration flow appears at `17:24:43.952` in DMZ Zeek with `18,783,413` origin bytes and no missed bytes, but at `17:24:44.067` in core Zeek with `18,750,831` visible bytes and `32,582` missed bytes—an internally meaningful difference.

- No dataset-wide visible eCAR lifecycle inversion was found: process terminations do not precede their visible creates, dependent activity does not precede its visible actor creation, and session logout does not precede login for the same object.

## Detailed Analysis

### Scope and collection profile

The logs span approximately `2024-03-18 12:00–18:00 UTC`. The environment contains 21 named hosts over four apparent network zones: user systems in `10.10.1.0/24`, internal servers in `10.10.2.0/24`, DMZ systems in `10.10.3.0/24`, and a database segment in `10.10.4.0/24`.

Available sources include Windows Security and Sysmon XML, Linux RFC 5424-style syslog, bash history, eCAR endpoint telemetry, three Zeek sensors, Cisco ASA, two Snort sensors, proxy access logs, and web access logs. Source volume is uneven in role-appropriate ways: the domain controllers are dominated by Windows Filtering Platform and Kerberos records, while FILE-LNX-01 contains dense SMB server activity.

### Threat-hunting trail

At `13:39:17`, root on LT-MRIVERA-02 executes SSH to WEB-EXT-01. The endpoint flow is followed by WEB-EXT-01 syslog connection, accepted-public-key, PAM-open, and logind-session events. At `13:40:17`, WEB-EXT-01 executes:

`nmap -sT -p 22,80,443,445,3306 10.10.2.0/24`

The resulting network evidence includes both successful and unsuccessful scan outcomes, principally `S0` and `REJ`, rather than fabricated successful services on every target.

At `15:45:00`, WS-AJOHNSON-01 runs:

`ms-index-service.exe "privilege::debug" "sekurlsa::logonpasswords" exit`

The process is High integrity, and subsequent Sysmon ProcessAccess events target `winlogon.exe` and `lsass.exe`, including `GrantedAccess=0x1FFFFF` in [Sysmon](/Users/dabianco/projects/SURGe/EvidenceForge/scenarios/iteration-test/blind-test/v2-loop-62/review-data/data/WS-AJOHNSON-01.meridianhcs.local/windows_event_sysmon.xml:12115). That is technically compatible with credential dumping.

At `16:14`, WMI-spawned processes on DC-01 create `svc_dirsync`, reset its password, and add it to Domain Admins. At `16:20`, the same host creates `DeviceSyncSvc` and an hourly scheduled task. The Security log contains corresponding account-management, group-membership, service-installation, and scheduled-task event types. At `17:42:26`, `wevtutil cl Security` is followed by Security Event 1102 and a reset of `EventRecordID` to 1, a source-native and coherent clearing sequence.

The data-access path is also operationally plausible:

- DB-PROD-01 receives root SSH access at approximately `17:15:13`.
- `mysqldump` creates `/tmp/rpt_0318.sql`, which is compressed.
- At `17:16:10.812`, Zeek records a successful 27.09-second SCP connection from `10.10.4.10:43731` to APP-INT-01 `10.10.2.30:22`, carrying approximately 1.1 MB in [conn.json](/Users/dabianco/projects/SURGe/EvidenceForge/scenarios/iteration-test/blind-test/v2-loop-62/review-data/data/zeek-core/conn.json:10294).
- APP-INT-01 records `/tmp/.cache/rpt_0318.sql.gz` being created by the receiver-side `sshd`.
- At `17:19`, `smbclient` uploads it to FILE-LNX-01 using `svc_mhsync`. Zeek records `SMB::FILE_OPEN` and `SMB::FILE_WRITE` for `Integration\DB-Staging\rpt_0318.sql.gz`, with size `1,063,533`, and FILE-LNX-01 records the matching authenticated write.

At `17:24`, WS-AJOHNSON-01 reads `cache_7f3a.zip` and connects from `10.10.1.35:61811` to proxy `10.10.3.20:8080`. Zeek, Sysmon, Security 5156, eCAR, and the proxy agree on the client tuple. The [proxy log](/Users/dabianco/projects/SURGe/EvidenceForge/scenarios/iteration-test/blind-test/v2-loop-62/review-data/data/PROXY-01.meridianhcs.local/proxy_access.log:2652) records the CONNECT and an `18,782,996`-byte POST to `/upload/telemetry/7f3a2b19`.

### Cross-source and lifecycle coherence

Most pivots work unusually well but without impossible ordering. SSH transports precede authentication, file reads precede transfers, and service/process events use compatible identities. The exfiltration flow also demonstrates realistic sensor effects: a roughly 115 ms core/DMZ timestamp offset and exactly explainable capture loss, rather than copied timestamps and byte counters.

The exception is the repeated SSH session-ID substitution. On APP-INT-01, eCAR creates session `378754` at `17:16:18.992`, writes the transferred file, and logs out that session at `17:16:39.458`. Syslog closes the same receiver `sshd` PID at `17:16:38.475`, then removes session `376301` 0.96 seconds later. Session `376301` appears nowhere in APP-INT-01 eCAR, while `378754` appears nowhere in syslog.

The same pattern occurs on DB-PROD-01, WEB-EXT-01, and LOG-MON-01. The temporal proximity and matching user/`sshd` closure indicate these are intended to represent the corresponding eCAR sessions, not unrelated background sessions. Because adjacent sessions elsewhere share the same numeric identity across eCAR and logind, this resembles a systematic continuation or identity-allocation defect.

### Baseline and distribution realism

The baseline is substantially better than a simplistic noise generator. Zeek core traffic includes 2,415 Kerberos, 1,179 LDAP, 414 SMB, 370 TLS, 251 syslog, 54 SSH, 48 DHCP, and 22 RDP connections. DNS failure codes, proxy authorization failures, HTTP server errors, stale-account authentication noise, scan failures, TLS resumption, and nonzero packet-loss tails create useful hunting background.

User activity is also differentiated. Developer-oriented Linux histories contain Git, Docker, Kubernetes, and build commands; administrators use journal and service tooling; database activity includes MySQL/PostgreSQL administration; and workstations show desktop processes and browser traffic.

The weaker area is long-tail variation in routine Linux service messages. The same exact `anacron`, `dbus-daemon`, and resolver counts recur across most hosts despite different system roles and overall event volumes. This does not create an impossible event, but it is a distributional fingerprint that would be unlikely to survive unchanged across so many independently operating systems.

### Authenticity weighing

The source formats, benign background, attack mechanics, and most cross-source timing are close to production telemetry. A real collection or ETL pipeline can certainly introduce missing events and identifier-normalization errors.

What pushes the assessment to synthetic is the shape of the error: the same selective SSH lifecycle defect appears on four hosts, with valid-looking but incorrect session numbers placed at precisely the expected close times, while neighboring sessions correlate correctly. Combined with repeated host-baseline count templates, this is more consistent with a generator defect than random packet loss or ordinary collection gaps.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the score |
|---|---|---|---|
| `hard_contradiction` | Linux eCAR and systemd-logind | Four SSH sessions on four hosts | The same visible session is assigned different numeric identities at near-identical close times. |
| `contract_gap` | SSH syslog lifecycle | Same four sessions | Visible in-window transports and eCAR logins have only closing syslog artifacts, unlike neighboring complete sessions. |
| `distribution_texture` | Linux syslog baseline | 10–11 Linux hosts | Exact daemon-record-count signatures repeat across unrelated system roles. |
| `weak_signal` | Windows Sysmon/Security process ancestry | Two WS-AJOHNSON-01 processes | Medium-integrity domain-user processes are direct children of service-hosting SYSTEM/NETWORK SERVICE processes; possible, but atypical. |

## Realism Score by Category

- **Field format accuracy:** 9 — Zeek, Windows, ASA, proxy, Snort, eCAR, and syslog records are structurally rich and largely source-native.
- **Temporal patterns:** 8 — Timing, jitter, sensor delay, failures, and long-lived connections are convincing, with no broad visible-ordering failure.
- **Cross-source correlation:** 6 — Most pivots are excellent, but the repeated SSH identity contradiction is material.
- **Behavioral realism:** 8 — User baselines, host roles, attack commands, privileges, and data movements are technically plausible.
- **Environmental consistency:** 7 — Traffic and service placement fit the visible topology, but routine Linux daemon counts are too repeatable across hosts.

## Recommendations

If this were synthetic, the following changes would improve it:

- Make the SSH action lifecycle use one authoritative session identifier across eCAR, `sshd`, and `systemd-logind`. Validate login, process, file-transfer, logout, and session-removal records as a single lifecycle group.

- Apply source-observation decisions coherently. If Linux auth/session-start records are dropped, do not retain an unrelated logind removal as the apparent close for that session; either preserve the complete source-local lifecycle or omit the affected group consistently.

- Add automated cross-source assertions that compare eCAR SSH session IDs to logind `New session` and `Removed session` values when their user, host, PID, transport tuple, and close time identify the same session.

- Vary routine daemon activity by host uptime, package state, timer configuration, role, and maintenance history so that `anacron`, D-Bus, and resolver records do not produce identical count signatures across most systems.

- For remotely or service-launched Windows activity, model the actual execution mechanism’s parent process and token transition—such as `WmiPrvSE.exe`, Task Scheduler components, or a named service binary—so the child’s parent principal, user token, and integrity level have an explicit source-native explanation.
