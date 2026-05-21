# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Confidence:** 70

## Executive Summary

The host evidence is unusually strong: Security 4688, Sysmon 1/3/5/11, and eCAR records frequently agree on PID, image, user, timing, and network activity. I still assess it as synthetic because a few endpoint-native details feel generated: several visible process creations lack corresponding Sysmon Event 1 despite adjacent Sysmon lifecycle evidence, and the Linux bash histories show repeated "realism garnish" patterns across unrelated systems.

## Evidence For Synthetic

- `WS-PPATEL-01` has Security 4688 at `2024-03-18T17:05:49.063Z` for `powershell.exe -WindowStyle Hidden ... Get-WinEvent ... Export-Csv`, PID `0x1dc8`/7624, and eCAR `PROCESS CREATE` at `17:05:49.551Z`, but Sysmon shows only Event 11 and Event 5 for ProcessGuid `{398565f9-746d-65f8-9ce6-50d5a0da63fa}` with no Sysmon Event 1.
- Across Windows logs, 861 of 867 Security 4688s match Sysmon Event 1 within two seconds; the few misses stand out because the dataset otherwise captures process creation very consistently.
- Bash histories repeatedly use generic diagnostic command pools across different Linux hosts: `nmcli device status`, `ip route get 8.8.8.8`, `journalctl ...`, `systemctl status ...`, `lpstat`, `bluetoothctl`, `~/.xsession-errors`.
- Human-typo artifacts appear broadly and neatly: `hostnaem`, `systtemctl`, `lastt`, `whhoami`, `umak`, `hitsory`, `ifle`. Real users mistype, but this distribution feels deliberately injected.
- Several server bash histories contain workstation-like checks such as `bluetoothctl devices`, `lsusb`, and `~/.xsession-errors` on hosts named `APP-INT-01`, `WEB-EXT-01`, and `DB-PROD-01`.

## Evidence For Real

- Security/Sysmon/eCAR process correlation is very good. Example: `WS-AJOHNSON-01` Security 4688 at `2024-03-18T12:04:55.651Z` creates `mstsc.exe /v:FILE-SRV-01`, PID `0x1468`; Sysmon 1 follows at `12:04:55.670Z` with PID `5224`; eCAR `PROCESS CREATE` follows at `12:04:56.036Z`.
- Sysmon Event 3 and eCAR FLOW align for that same RDP process: `10.10.1.35:56775 -> 10.10.2.20:3389` at about `12:04:59Z`.
- No visible impossible ordering in the parsed lifecycle checks: Sysmon process terminations had no create-after-terminate cases; Security 4624/4634 had no visible logoff-before-logon for the same LogonID.
- Logon mix is realistic: type 3 network logons dominate, with type 5 service, type 2 interactive, type 10 RDP, type 7 unlock, and type 11 cached interactive logons.
- Process trees are plausible: `explorer.exe -> mstsc.exe/vpnui.exe/ZSATray.exe`, `services.exe -> svchost.exe/AdobeARMservice.exe/MpCmdRun.exe`, `csrss.exe -> conhost.exe`, and `SearchIndexer.exe -> SearchFilterHost.exe`.
- The DC log clear sequence is source-native: `wevtutil cl Security` at `2024-03-18T17:42:02.700Z`, Sysmon 1 for `wevtutil.exe` at `17:42:02.742Z`, then Security 1102 at `17:42:15.517Z`.

## Detailed Analysis

The strongest realism is in endpoint correlation. The `WS-AJOHNSON-01` RDP example has Security, Sysmon, and eCAR agreeing on process image, PID, parent image, user, and later network tuple. That is exactly what I expect from a well-instrumented workstation.

The process tree generally feels lived-in. I saw updater/service noise such as `OneDriveStandaloneUpdater.exe`, `AdobeARMservice.exe`, `MpCmdRun.exe`, `TiWorker.exe`, `gpupdate.exe`, Zscaler, GlobalProtect, AnyConnect, Dropbox, Google Drive, Teams, Zoom, and Citrix. User-launched processes are mostly under `explorer.exe`; service processes mostly under `services.exe` or `svchost.exe`.

The logon lifecycle is credible. There are 834 Security 4624s and 493 4634s, with 486 visible prior-login pairs and no impossible visible ordering. Type 3 sessions are mostly short, while RDP/interactive sessions last hours. Lock/unlock events appear for Aisha and Marcus, with matching user/session context.

The main endpoint flaw is selective Sysmon process creation absence. The `WS-PPATEL-01` hidden PowerShell at `17:05:49Z` has Security 4688, eCAR process creation, Sysmon file creation, and Sysmon process termination, but no Sysmon Event 1 for the same ProcessGuid. In isolation this could be Sysmon filtering or event loss; in a dataset where nearly every other 4688 is matched, it reads like a generation/rendering gap.

Linux bash history has plausible timestamps and role-specific commands, especially `lina.nguyen` using `git`, `docker`, `pytest`, and editors. But the histories also reuse broad diagnostic checklists and typo artifacts across hosts. That feels more like a command-pool generator than organic long-lived admin behavior.

## Realism Score by Category

- **Field format accuracy:** 8 — Windows XML, Sysmon fields, ProcessGUIDs, and Security event data are mostly source-native.
- **Temporal patterns:** 8 — Timing has jitter and plausible lifecycles, though some attack steps are tightly storyboarded.
- **Cross-source correlation:** 9 — Security/Sysmon/eCAR alignment is strong and usually source-consistent.
- **Behavioral realism:** 7 — User and admin activity is plausible, but bash histories feel pooled and lightly templated.
- **Environmental consistency:** 7 — Enterprise tooling and host roles fit, but server-side desktop artifacts weaken realism.

## Recommendations

If this were synthetic, I would improve it by ensuring any process with Sysmon Event 11 or 5 and an in-window Security 4688 also has a source-consistent Sysmon Event 1 unless a clear Sysmon filtering policy explains the omission. I would also make Linux shell histories more host-specific: fewer repeated generic diagnostics, fewer evenly distributed intentional typos, and less desktop-oriented command noise on server-named systems.
