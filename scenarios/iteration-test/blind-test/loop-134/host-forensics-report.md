# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Confidence:** 74

## Executive Summary

The Windows, eCAR, and Zeek evidence is unusually coherent and often source-native correct, especially around the PsExec/DC compromise and later file movement. The strongest synthetic indicators are in Linux syslog baseline noise, where repeated `polkitd` records combine authorization actions with caller binaries that do not normally request those actions.

## Evidence For Synthetic

- `APP-INT-01.meridianhcs.local/syslog.log:13` at `2024-03-18T12:04:11.353504Z` shows `/usr/bin/timedatectl` requesting `org.freedesktop.login1.reboot`; `timedatectl` should not be the caller for reboot authorization.
- `APP-INT-01.meridianhcs.local/syslog.log:87` at `2024-03-18T12:30:40.949814Z` shows `/usr/bin/nmcli` requesting `org.freedesktop.timedate1.set-timezone`; that action belongs to timedate tooling, not NetworkManager.
- `WEB-EXT-01.meridianhcs.local/syslog.log:1` at `2024-03-18T12:00:00.694762Z` shows `/usr/bin/timedatectl` requesting `org.freedesktop.packagekit.system-update`, another source-native mismatch.
- Similar mismatched `polkitd` action/program pairs recur across APP, DB, PROXY, WEB, and WS-OHADDAD hosts, suggesting template-driven noise rather than captured Linux authorization telemetry.
- Bash history has a mild command-pool feel: exact administrative commands recur repeatedly across users and hosts, such as `systemctl status systemd-resolved --no-pager`, `resolvectl status 2>/dev/null | head -40`, and `file /usr/bin/ls`.

## Evidence For Real

- Windows event record IDs are not naively reset at file start. For example, `DC-01` Security starts at `EventRecordID=11606382`, reaches `11621279`, then resets around the `1102` audit-clear event at `2024-03-18T17:41:42.8093377Z`.
- The DC compromise chain is source-native plausible: Sysmon file create for `C:\Windows\PSEXESVC.exe` at `16:00:12.535`, process start at `16:00:14.629`, child `cmd.exe` at `16:00:15.888`, then `net user` / `net group` activity at `16:14:57` and `16:15:00`.
- Hashes are stable by binary/version. On `DC-01`, repeated `C:\Windows\System32\net.exe` process creates reuse the same SHA256 `F006143155279ACA9A7169AFCF3D53C35DE337F9E008DF8BC03BC576E8079E37`.
- DB exfiltration has realistic shell/EDR separation: bash history records redirection for `mysqldump`, while eCAR process telemetry omits the shell redirection and separately records `/tmp/rpt_0318.sql` creation.
- Network correlation is credible: `DB-PROD-01` eCAR records `scp` from `10.10.4.10` to `10.10.2.30:22` at `17:20:35.818`, `APP-INT-01` records inbound file creation at `17:20:38.630`, and Zeek core records the SSH connection at `17:20:36.215`.
- File-server staging is coherent: `FILE-SRV-01` eCAR records `Compress-Archive` creating `C:\ProgramData\Microsoft\cache_7f3a.zip`, and Zeek core later records SMB transfer of that same ZIP to `10.10.1.35` with `314272438` bytes.

## Detailed Analysis

The Windows endpoint evidence is the strongest part of the dataset. Process trees, parent images, logon IDs, service creation, account creation, audit clearing, and Sysmon/Security sequencing largely fit how a real domain compromise would look. The `PSEXESVC` chain, `svc_mhsync` creation, Domain Admins addition, `DeviceSyncSvc` persistence, encoded PowerShell, and `wevtutil cl Security` all line up across eCAR, Sysmon, and Security logs without obvious impossible ordering.

The Linux endpoint baseline is weaker. The `polkitd` records repeatedly combine actions and requestor binaries that are semantically incompatible. One or two odd lines could be explained by unusual wrappers or sanitization, but the recurrence across several hosts and action classes looks generated.

Temporal behavior is mostly believable. The dataset avoids obvious fixed intervals in the attack path, includes short-lived processes with matching terminations, and keeps file/network timing plausible. The main temporal weakness is that ordinary admin noise feels selected from reusable pools, especially in bash histories.

Overall, I would classify the dataset as synthetic, but high quality. The Windows and network layers are strong enough that the verdict rests primarily on Linux source-native inconsistencies rather than on over-complete correlation.

## Realism Score by Category

- **Field format accuracy:** 7 — Windows/Sysmon/Zeek fields are strong, but Linux `polkitd` action/caller combinations are flawed.
- **Temporal patterns:** 8 — Attack timing and lifecycle ordering are plausible with only mild baseline regularity.
- **Cross-source correlation:** 9 — Endpoint, bash history, Zeek, and Windows logs correlate cleanly without obvious impossible ordering.
- **Behavioral realism:** 7 — The attacker workflow is realistic; benign Linux command histories feel somewhat pooled.
- **Environmental consistency:** 8 — Host roles, IP ranges, users, services, and OS-specific artifacts are mostly consistent.

## Recommendations

Fix Linux syslog generation by binding `polkitd` actions to compatible caller programs: `nmcli` with NetworkManager actions, `timedatectl` with timedate actions, `packagekitd` with PackageKit actions, and `systemctl` with systemd/logind actions. Add more user-specific shell history variation and reduce exact command reuse across unrelated hosts. Keep the Windows process, service, account, and file/network correlation patterns, as those are the dataset’s strongest realism features.
