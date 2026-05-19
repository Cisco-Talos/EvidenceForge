# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Confidence:** 66

## Executive Summary

The logs are highly coherent and source-native enough that I would not call this an obvious fake. My synthetic verdict comes from the incident story feeling unusually curated: the attack chain is textbook, artifact names are narratively convenient, and several high-value pivots appear with very clean timing and little attacker mess.

## Evidence For Synthetic

- The kill chain is almost training-lab clean: `nmap`, domain recon, PsExec, `svc_mhsync` creation, Domain Admins membership, scheduled persistence, database dump, exfil, encoded PowerShell, `wevtutil cl Security`, and account deletion all land in a neat sequence.
- DB root history is unusually surgical: `DB-PROD-01.../bash_history/root.bash_history` contains only timestamped dump/compress/scp commands for `/tmp/rpt_0318.sql`, with no unrelated root history.
- Artifact names feel selected to tell the story: `svc_mhsync`, `DeviceSyncSvc`, `cache_7f3a.zip`, `rpt_0318.sql`, and `api.westbridge-services.net`.
- High-signal process events repeatedly show clean Security/Sysmon/eCAR ordering within fractions of a second, e.g. `whoami /all` at 15:20:32 on `WS-AJOHNSON-01` and `net user svc_mhsync ...` at 16:14:57 on `DC-01`.
- The attacker path has few visible mistakes after compromise. There is scanning noise, but little credential churn, tooling staging, operator typo/retry behavior, or partial cleanup failure.

## Evidence For Real

- Source formats are strong: Windows Security/Sysmon fields, Zeek `conn/dns/http/ssl`, ASA build/teardown/deny messages, proxy access logs, and Snort alerts all look source-native.
- Cross-source pivots are technically plausible. WEB-EXT nmap events match Zeek/ASA flow evidence; DB `scp` matches Zeek SSH; DC PowerShell matches proxy and Zeek HTTP; File Server access matches Kerberos and 4624 records.
- Baseline noise is not sterile: Windows Update, APT/Snap/GitLab/Grafana traffic, external web scans, account-disabled failures, Kerberos volume, DNS lookups, and proxy 200/407/502 outcomes are present.
- The attack is embedded in enough normal activity that it requires hunting rather than simple string matching.

## Detailed Analysis

Scope: I observed 73 files across host, network, firewall, proxy, web, Snort, bash history, and eCAR-style endpoint records. The visible window is roughly 2024-03-18 12:00:00Z through 19:18:38Z. Host/IP mapping is internally consistent: `DC-01=10.10.2.10`, `FILE-SRV-01=10.10.2.20`, `APP-INT-01=10.10.2.30`, `WEB-EXT-01=10.10.3.10`, `PROXY-01=10.10.3.20`, `DB-PROD-01=10.10.4.10`, and workstations in `10.10.1.0/24`.

Attack storyline: At 14:10:29Z and 14:13:29Z, `WEB-EXT-01` root runs `nmap -sn 10.10.2.0/24` and `nmap -sT -p 22,80,443,445,3306 10.10.2.0/24`. Zeek and ASA show matching probes from `10.10.3.10` to `10.10.2.10/.20/.30`, including SMB, SSH, HTTP, HTTPS, and MySQL-like ports with mixed `SF`, `S0`, and `REJ`.

Workstation recon: At 15:20:31Z, `WS-AJOHNSON-01` has an RDP-style login from `10.10.1.99`, then PowerShell from Explorer, then `whoami /all`, `net user /domain`, `net group "Domain Admins" /domain`, and `net view /domain` within about four seconds. That is realistic command choice, but very compact and narratively obvious.

DC compromise and persistence: `DC-01` shows Security 4697 for `PSEXESVC` by `aisha.johnson` at 16:00:12Z, then `cmd.exe /c whoami && hostname`. At 16:14:57Z, `net user svc_mhsync MhsSvc!2024 /add /domain` creates the account; at 16:15:03Z, Security 4728 adds it to Domain Admins. At 16:20Z, `DeviceSyncSvc` is created and scheduled under `\Microsoft\Windows\Maintenance\DeviceSync`.

Lateral access and exfil: At 17:01:07Z, `svc_mhsync` gets Kerberos TGT/TGS activity from `10.10.1.35` and logs onto `FILE-SRV-01`; eCAR shows `net view \\FILE-SRV-01` and `Compress-Archive ... cache_7f3a.zip`. At 17:25:26Z, proxy logs show `10.10.1.35` POSTing 314,782,795 bytes to `api.westbridge-services.net/upload/telemetry/7f3a2b19`.

Database activity: At 17:14:29Z, `DB-PROD-01` records root SSH from `10.10.2.30`; at 17:14:43Z `mysqldump --single-transaction ehr patients insurance_claims`; at 17:15:05Z `gzip -9 /tmp/rpt_0318.sql`; at 17:20:35Z `scp /tmp/rpt_0318.sql.gz root@10.10.2.30:/tmp/.cache/rpt_0318.sql.gz`. Zeek core confirms SSH from `10.10.4.10:39761` to `10.10.2.30:22` at 17:20:36Z.

Cleanup/C2: At 17:41:39Z, `DC-01` runs encoded PowerShell under `PSEXESVC`; decoded, it invokes `Net.WebClient` to download `https://api.westbridge-services.net/v2/manifest`. Proxy logs show the matching PowerShell/5.1 GET at 17:41:40Z. At 17:41:42Z, `wevtutil cl Security` runs and Security 1102 follows. At 17:49:58Z, `net user svc_mhsync /delete /domain` cleans up the account.

Overall, the technical pivots work. My concern is not impossibility; it is that the case reads as a deliberately authored incident with unusually tidy breadcrumbs.

## Realism Score by Category

- **Field format accuracy:** 9 — Windows, Zeek, ASA, proxy, and Snort fields are mostly source-native and plausible.
- **Temporal patterns:** 7 — Background timing has jitter, but attack stages are compact and cleanly sequenced.
- **Cross-source correlation:** 9 — Pivots between endpoint, auth, Zeek, firewall, and proxy are strong.
- **Behavioral realism:** 7 — TTPs are realistic, but operator behavior is too scripted and low-mess.
- **Environmental consistency:** 8 — Host/IP/user/service context is coherent with believable enterprise noise.

## Recommendations

If this were synthetic, I would add more attacker imperfection: failed credential use, alternate tooling, retries, typos, abandoned pivots, and partial cleanup. I would also make bash histories less curated, vary cross-source event latency/order more, and add a longer pre-compromise trail for credential acquisition and tool staging.
