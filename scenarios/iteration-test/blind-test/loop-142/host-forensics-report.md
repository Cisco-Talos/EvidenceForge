# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Confidence:** 72

## Executive Summary

The dataset has strong endpoint realism in the Windows process trees, Kerberos/logon lifecycle, and Linux syslog noise, but several host/EDR details feel generated rather than observed. The most persuasive synthetic indicators are source-native Linux sudo formatting/template repetition and eCAR process/network behavior that does not match the stated command semantics.

## Evidence For Synthetic

- `WS-LNGUYEN-01.meridianhcs.local/ecar.json` shows `/usr/bin/docker` with `command_line="docker ps"` created at `2024-03-18T15:44:10.109Z`, immediately making an outbound TCP flow to proxy `10.10.3.20:8080` at `15:44:11.419Z`, then terminating at `17:51:19.425Z`. A local `docker ps` normally talks to a Unix socket and exits quickly; this looks like generic process-to-proxy generation.
- `WEB-EXT-01.meridianhcs.local/syslog.log` has 91 sudo “command not allowed” records, and `PROXY-01.../syslog.log` has 46. All 137 omit the usual `PWD=...` field while cycling a small pool of users (`nginx`, `www-data`, `apache`) and commands (`/bin/ls /root`, `cat /etc/shadow`, metadata curl, `id`).
- The denied sudo activity is very template-like across both hosts: same three service-account names, same restricted command set, same missing field pattern, spread throughout the day.
- Some eCAR process telemetry appears command-agnostic: benign or local commands receive network-flow behavior and long process lifetimes that fit an activity model more than actual process execution.

## Evidence For Real

- Windows endpoint chains are quite convincing: on `DC-01`, Sysmon Event 11 shows `services.exe` creating `C:\Windows\PSEXESVC.exe` at `15:59:57.878Z`, Security 4697 records `PSEXESVC` installation at `15:59:58.111Z`, then Sysmon/Security show `PSEXESVC.exe` and child commands.
- The DC log-clearing sequence is source-native: `wevtutil cl Security` at `17:42:23.933Z`, Security 1102 at `17:42:25.288Z`, then lower EventRecordIDs afterward.
- I found no visible logoff-before-logon or Sysmon terminate-before-create ordering contradictions for same identifiers inside the window.
- Linux syslog has good operational texture: DHCP request/ack/bound cycles, rsyslog queue/reload messages, unattended-upgrades, polkit, journald sizing, SSH accept/session open/close, and sudo activity.
- Bash histories include human-like entropy and typos (`jjournalctl`, `datte`, `lx`) plus mixed tooling (`vim`, `nano`, `emacs`, `code`, `make`, `npm`, `cargo`, `pytest`).

## Detailed Analysis

The Windows process evidence is the strongest part. `DC-01` has a coherent PsExec-style timeline: `PSEXESVC` service installation by `aisha.johnson`, execution as `SYSTEM`, child `cmd.exe /c whoami && hostname`, later `net user svc_mhsync ... /add /domain`, Domain Admin modification, persistence via `sc.exe` and `schtasks.exe`, encoded PowerShell, and log clearing. The parent/child PIDs and Sysmon ProcessGuids remain internally consistent.

The file-server staging also looks plausible. `FILE-SRV-01` records `svc_mhsync` launching PowerShell at `2024-03-18T17:01:31Z` to run `Compress-Archive` over finance/patient export paths, with Sysmon Event 11 creating `C:\ProgramData\Microsoft\cache_7f3a.zip`.

The Linux evidence is mixed. Normal SSH and systemd session handling looks believable, and I did not find impossible visible ordering. But the sudo-denial corpus on `WEB-EXT-01` and `PROXY-01` is too uniform: all denied records omit `PWD`, while successful sudo records elsewhere include `PWD=/...`. That is a source-native formatting smell, not just “too much correlation.”

The eCAR endpoint layer is generally useful but occasionally over-abstracted. The `docker ps` example on `WS-LNGUYEN-01` is the clearest issue: process lifetime and proxy flow do not fit that command’s native behavior. That kind of mismatch is exactly where synthetic telemetry tends to leak through.

## Realism Score by Category

- **Field format accuracy:** 7 — Windows XML is strong; sudo denial formatting and some eCAR semantics are weaker.
- **Temporal patterns:** 7 — Broad timing is varied, but some process durations/denial patterns feel model-driven.
- **Cross-source correlation:** 8 — Strong and no concrete impossible ordering found.
- **Behavioral realism:** 6 — Attack and admin behavior are plausible, but Linux/eCAR command semantics show tells.
- **Environmental consistency:** 7 — AD, Windows, and Linux roles fit, though service-user and sudo patterns feel templated.

## Recommendations

- Make eCAR process-to-network generation command-aware: `docker ps` should not emit proxy flows or multi-hour runtime unless explicitly modeled as a hung or malicious wrapper.
- Improve sudo failure templates to include source-native `PWD=` and distro/service-user realism; reduce repeated command-pool cycling across hosts.
- Add more source-local imperfections and host-specific variation in Linux service accounts, shell sessions, and denied privilege attempts.
- Keep the Windows Security/Sysmon lifecycle modeling; that portion is the most convincing.
