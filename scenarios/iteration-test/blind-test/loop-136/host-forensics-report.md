# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Confidence:** 78

## Executive Summary

The endpoint telemetry is high quality and internally coherent, especially around Security/Sysmon/eCAR process correlation and the DC attack timeline. I still judge it synthetic because several source-native endpoint details are off in ways that feel generated: malformed UserAssist registry values, repeated polkit action/program mismatches, and unusually templated Windows core process identity patterns.

## Evidence For Synthetic

- `WS-AJOHNSON-01.../windows_event_sysmon.xml` has UserAssist writes like `...\Count\HRZR_EHACNGU28` at `2024-03-18T12:04:14.889Z` with `Details=00 00 00 00 8D73A8EC`. `HRZR_EHACNGU` is ROT13 for `UEME_RUNPATH`; real values normally include the encoded path, not numbered placeholders.
- The same UserAssist pattern repeats across workstations: `HRZR_EHACNGU8`, `HRZR_EHACNGU40`, `HRZR_EHACNGU73`, plus short 8-byte-looking values.
- Linux polkit messages repeatedly pair implausible actions and binaries, e.g. `APP-INT-01/syslog.log` at `12:04:11Z`: `/usr/bin/timedatectl` gaining `org.freedesktop.login1.reboot`; at `12:30:40Z`: `/usr/bin/nmcli` gaining `org.freedesktop.timedate1.set-timezone`.
- Windows boot-core process PIDs look generated more than lived-in. Examples include `WS-AJOHNSON-01` showing `services.exe` as PID `4284` and `lsass.exe` as PID `4292`, and several hosts with `services.exe`, `lsass.exe`, `smss.exe`, or `csrss.exe` in the 3k-6k range.
- Sysmon Event 10 call traces are compact and templated: 489 process-access events used only 64 call traces, all 1-3 frames long. Real Sysmon traces are often messier and deeper.

## Evidence For Real

- Security 4688, Sysmon Event 1, and eCAR PROCESS/CREATE line up well. Example: `WS-AJOHNSON-01` creates `AdobeARMservice.exe` PID `5204` at `12:05:25Z` in Security, Sysmon, and eCAR within sub-second deltas.
- The DC log-clear sequence is credible: `PSEXESVC.exe` spawns encoded PowerShell at `17:41:39Z`, then `wevtutil cl Security` at `17:41:41Z`, followed by Security Event `1102` at `17:41:42Z` and EventRecordID reset to `3`.
- Linux SSH sessions have realistic sequences: `APP-INT-01` at `12:06:15Z` shows connection, accepted publickey for root, PAM session open, and later session close at `12:19:56Z`.
- Bash histories include natural admin behavior and typos: `journactl`, `uilmit`, `sgat`, `exiy`, alongside role-specific commands like `npm run lint`, `mysql`, `mysqldump`, `journalctl`, and `systemctl`.
- User behavior differs by role: Aisha uses `mstsc.exe`, Dropbox, Firefox; Marcus uses VS Code, MMC, Postman; Priya uses Teams/Slack/Chrome; Linux users show DBA/dev/admin-flavored command histories.

## Detailed Analysis

### Windows Process And Sysmon Realism

The process tree is mostly plausible. Service children such as `svchost.exe`, `MpCmdRun.exe`, `spoolsv.exe`, and Adobe/Dropbox/Google updaters are parented to `services.exe`; interactive tools and user apps are parented to `explorer.exe`; `conhost.exe` under `csrss.exe` appears frequently. The attack chain on `DC-01` is also convincing: `PSEXESVC.exe` service creation, `cmd.exe`, `net user`, `net group`, `sc.exe`, `schtasks.exe`, encoded PowerShell, and `wevtutil`.

The weaker area is forensic artifact fidelity. UserAssist registry values are the clearest tell: `HRZR_PGYFRFFVBA` is recognizable, but numbered `HRZR_EHACNGU##` values are not credible as real `UEME_RUNPATH:<path>` artifacts. Some third-party file metadata is also thin, with `FileVersion`, `Product`, `Company`, and `OriginalFileName` set to `-` for binaries that usually carry metadata.

### Logon Session Lifecycle

The data includes a realistic mix of logon types: interactive `2`, network `3`, service `5`, unlock `7`, RDP `10`, and cached interactive `11`. Workstation lock/unlock evidence is present, e.g. `WS-DRAMIREZ-01` has `4800` at `14:41:35Z`, `4801` at `14:52:35Z`, then a type `7` logon with the same logon ID.

I did not find visible impossible ordering inside the collection window. Some unmatched starts/ends are acceptable for a slice-of-time capture.

### Endpoint Correlation

Cross-source correlation is a strength. On `WS-AJOHNSON-01`, `mstsc.exe /v:DC-01` PID `5268` appears as Security 4688, Sysmon Event 1, eCAR PROCESS/CREATE, then a 3389 FLOW/5156/Sysmon network connection. On `DB-PROD-01`, root bash history at `17:14:42Z`, `17:15:05Z`, and `17:20:35Z` aligns with eCAR `mysqldump`, `gzip`, file creation, and `scp`.

### Linux Evidence

The SSH and bash-history evidence is one of the better parts of the dataset. Sessions have normal connection/auth/open/close sequences, sudo records include TTY/PWD/USER/COMMAND, and the command history has believable human entropy.

The synthetic weakness is syslog background noise. Polkit messages repeatedly combine actions and owning processes in ways that do not make source-native sense, especially `timedatectl`, `nmcli`, `systemctl`, and `packagekitd` being mixed with unrelated policy actions.

## Realism Score by Category

- **Field format accuracy:** 7 — Mostly correct XML/JSON/syslog shapes, but UserAssist and polkit semantics are off.
- **Temporal patterns:** 8 — Good jitter and session timing; some background noise feels over-randomized.
- **Cross-source correlation:** 9 — Strong Security/Sysmon/eCAR/bash alignment without visible impossible ordering.
- **Behavioral realism:** 8 — Role-specific user behavior and admin workflows are convincing.
- **Environmental consistency:** 7 — Host roles and OS cohorts mostly hold together, but core process PID patterns and Linux policy noise weaken it.

## Recommendations

If this were synthetic, I would improve realism by generating true UserAssist value names and binary data, mapping polkit actions to plausible executables, seeding Windows boot-core processes with realistic low PIDs, and enriching Sysmon call traces/file metadata. I would also keep the strong cross-source correlation but add more source-native rough edges rather than generic randomized background noise.
