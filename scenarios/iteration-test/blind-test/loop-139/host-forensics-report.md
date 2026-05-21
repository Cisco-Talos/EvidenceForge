# Host/EDR Forensics Analyst - Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Confidence:** 72

## Executive Summary

This dataset is better than a toy generator: process trees, logon lifecycles, Sysmon/Security/eCAR timing, and several Linux session artifacts are internally plausible. I still assess it as synthetic because the endpoint evidence has a curated, training-scenario feel, with several source-native details that look templated rather than organically collected.

## Evidence For Synthetic

- Windows 5156 `Application` paths use `\device\harddiskvolume1\...` uniformly across all Windows hosts, including workstations and servers; real fleets often vary by install layout and volume mapping.
- Several Sysmon `SearchProtocolHost.exe` command lines contain SIDs with prefixes not observed anywhere in Security log account SIDs: e.g. `WS-MCHEN-01` at `2024-03-18T12:34:18.7007022Z` uses `S-1-5-21-732725513-806867832-691112306-2676`, while all observed domain Security SIDs use `S-1-5-21-1524654518-2022274387-1755902678-*`.
- The attack chain on `DC-01` is very clean and pedagogical: `PSEXESVC.exe`, `net user`, `net group "Domain Admins"`, `sc.exe create`, `schtasks.exe`, encoded PowerShell, `wevtutil cl Security`, and account deletion all appear in a tidy sequence.
- `DeviceSyncSvc.exe` is installed and executed, but I found no visible Sysmon file-create/drop event for `C:\Windows\System32\DeviceSyncSvc.exe`; possible in a windowed slice, but the surrounding chain otherwise captures file creation for `PSEXESVC.exe` and temp files.
- Bash histories include multiple obvious typo commands across users/hosts (`geteent`, `freee`, `grouos`, `lodale`, `fre`, `ct`, `pw`), which helps realism but also feels deliberately seeded.

## Evidence For Real

- I found no visible impossible process lifecycle ordering: no Sysmon termination-before-create, parent-created-after-child, or Security 4689 mismatch for visible matching PIDs.
- Strong RDP correlation: `WS-AJOHNSON-01` launches `mstsc.exe /v:FILE-SRV-01` at `12:04:35`, logs Sysmon network event PID `5224` from `10.10.1.35:61448` to `10.10.2.20:3389` at `12:04:38.480`, and `FILE-SRV-01` records 4624 type 10 for `aisha.johnson` from that same IP/port at `12:04:39.249`.
- PsExec artifacts are source-coherent: `DC-01` Security 4697 records `PSEXESVC` at `16:00:16`, Sysmon 11 records `C:\Windows\PSEXESVC.exe`, and Sysmon 1 then records `PSEXESVC.exe` spawned by `services.exe`.
- The DC attack timeline has expected Windows artifacts: 4720 account creation for `svc_mhsync`, 4728 Domain Admins membership, 4698 scheduled task creation, 1102 Security log clear after `wevtutil cl Security`, and later 4726 account deletion.
- Linux syslog is plausible: `DB-PROD-01` shows SSH connection, accepted key/password, PAM session open, and `systemd-logind` session creation with realistic PID continuity.

## Detailed Analysis

Endpoint process trees are mostly believable. Workstation processes include VPN agents, OneDrive/Dropbox/Google Drive, updater services, SearchIndexer children, WMI, Defender, and user-launched tools. Server processes include `WmiPrvSE.exe`, `dllhost.exe`, `conhost.exe`, `TiWorker.exe`, `spoolsv.exe`, `dns.exe`, and `dfsr.exe` with reasonable parents.

The DC compromise sequence is internally consistent. At `2024-03-18T16:15:24.7713826Z`, Sysmon records `net user svc_mhsync MhsSvc!2024 /add /domain` from `C:\Windows\PSEXESVC.exe`; Security 4720 follows at `16:15:25.9236343Z`. At `16:15:35.3737438Z`, `net group "Domain Admins" svc_mhsync /add /domain` is followed by 4728 at `16:15:36.6828133Z`. That is very good correlation, but also very scenario-shaped.

The log clear sequence is realistic if these are forwarded logs: Sysmon records encoded PowerShell at `17:42:25.7979305Z`, `wevtutil cl Security` at `17:42:26.9569006Z`, and Security 1102 appears at `17:42:33.7624841Z` with EventRecordID reset to `3`. If interpreted as a local post-clear export, retaining pre-clear Security records in the same XML would be odd; as an aggregated collection, it is acceptable.

Logon behavior is coherent. Workstations show type 2, 3, 5, 7, 10, and 11 logons; DC and file server type 3 and 5 are dense but not impossible. Failed logons use plausible status/substatus (`0xc000006d` / `0xc000006a`) and sensible processes (`winlogon.exe`, `lsass.exe`).

## Realism Score by Category

- **Field format accuracy:** 8 - Windows XML, Sysmon fields, Security IDs, and syslog formats are mostly source-native.
- **Temporal patterns:** 7 - Good local ordering, but the activity feels curated and window-bounded.
- **Cross-source correlation:** 9 - Strong PID, port, process, and logon alignment across Security/Sysmon/eCAR/Zeek.
- **Behavioral realism:** 7 - Plausible user/admin/attacker behavior, but too cleanly narrativized.
- **Environmental consistency:** 7 - Hostnames, SIDs, OS builds, and users mostly align; SID and volume-path artifacts reduce confidence.

## Recommendations

- **P1:** Make Windows device paths less templated; vary `harddiskvolumeN` realistically by host.
- **P1:** Ensure SearchIndexer/SearchProtocolHost embedded SIDs match known user/domain/local profile identities.
- **P2:** Add file-drop evidence for installed malicious/service binaries such as `DeviceSyncSvc.exe`.
- **P2:** Broaden endpoint entropy with more mundane partial artifacts, abandoned processes, updater failures, and non-story noise.
- **P3:** Reduce the "training lab" neatness of attacker command sequencing with more operator hesitation, retries, and tool residue.
