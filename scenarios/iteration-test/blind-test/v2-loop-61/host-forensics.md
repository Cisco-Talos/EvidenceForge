# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 91  
**Synthetic-Confidence Score:** 83

## Executive Summary

The dataset has strong cross-source integrity, realistic host specialization, and well-constructed Windows and Linux lifecycle evidence. However, several source-native semantic errors and dataset-wide distribution patterns—especially the Sysmon Event 8 thread-start semantics, highly templated ProcessAccess call stacks, sharply bounded network-logon durations, and repeated browser-process modeling—are difficult to reconcile with organically collected production telemetry.

## Evidence For Synthetic

- `[hard_contradiction]` At `2024-03-18T15:44:42.5922589Z`, `WS-AJOHNSON-01.../windows_event_sysmon.xml` records Sysmon Event 8 from `ms-index-service.exe` into `lsass.exe` with `StartModule=C:\Windows\System32\ntdll.dll` and `StartFunction=NtCreateThreadEx`. `StartFunction` is supposed to describe the new target thread’s entry routine; `NtCreateThreadEx` is normally the creator-side API. This also does not fit the immediately preceding `sekurlsa::logonpasswords` memory-access behavior.
- `[schema_or_format]` Four unrelated workstations record `crashpad_handler.exe` as a Sysmon Event 7 image load inside `GoogleDriveFS.exe`: WS-AJOHNSON at `12:06:31.6444935Z`, WS-EBROOKS at `15:36:01.1156247Z`, WS-SMARTINEZ at `16:37:03.1851978Z`, and WS-DRAMIREZ at `16:50:04.7680848Z`. Crashpad Handler is normally a separate executable process, not a DLL-style module loaded into the Drive process; the repeated description `crashpad_handler.exe module` strengthens the template signature.
- `[distribution_texture]` Across 741 Sysmon Event 10 records, 557 call traces contain exactly three frames, 158 contain one, and 26 contain two. After removing offsets, the entire corpus reduces to only eight module sequences, dominated by short combinations of `ntdll.dll`, `KERNELBASE.dll`, and one of `sechost.dll`, `advapi32.dll`, `combase.dll`, or `wbemcomn.dll`; this is unusually shallow and repetitive for ten hosts and many source/target process pairs.
- `[distribution_texture]` Of 355 visibly paired Windows Logon Type 3 sessions, 353 end within 65 seconds. All 152 paired Type 3 sessions on DC-01 end within 39.044 seconds, all 53 on FILE-SRV-01 within 38.716 seconds, and all 13 on WS-MCHEN within 60.063 seconds. The near-global cutoff resembles a bounded duration generator rather than persistent and heavy-tailed SMB/RPC/network-session behavior.
- `[distribution_texture]` Two unrelated WMI Provider Host processes have exactly `14,400.001`-second lifetimes: FILE-SRV-01 PID 5064 from `13:23:31.757Z` to `17:23:31.758Z`, and MAIL-FIN-01 PID 4052 from `13:51:49.006Z` to `17:51:49.007Z`. The identical four-hour-plus-one-millisecond ceiling is a strong clipped-lifetime fingerprint.
- `[contract_gap]` Ten visible Firefox creations across five Windows workstations are all direct children of `explorer.exe`, all use `-osint -url`, and there are no visible Firefox-to-Firefox content-process creations. On WS-AJOHNSON, four such roots live for 5,301–5,960 seconds; three overlap and terminate within 371 milliseconds at session end. A real Firefox tree normally has one persistent parent, short-lived secondary URL-dispatch processes, and multiple `-contentproc` children.
- `[environment_or_collection_plausibility]` The Windows process population is narrow for apparently active hosts: DC-01’s 172 eCAR process creates are dominated by 39 `conhost.exe`, 31 `WmiPrvSE.exe`, 30 `taskhostw.exe`, and 28 `dllhost.exe`. Similar small palettes recur on DC-02 and the Windows servers, leaving relatively little normal process long-tail activity.

## Evidence For Real

- Matched Security 4688, Sysmon 1, and eCAR process records agree on PID, parent PID, image, parent image, command line, user, and Logon ID. I found no field contradictions among 969 matched Security/Sysmon process-create pairs.
- No visible Sysmon parent is created after its child; no dependent Sysmon event precedes the visible creation of the same ProcessGUID; and no visible termination precedes the corresponding creation.
- The DC-01 Security-log clear is modeled source-natively: `cmd.exe /c wevtutil cl Security` at `17:42:28.936Z`, `wevtutil.exe` at `17:42:29.181Z`, Event 1102 at `17:42:33.180Z`, and EventRecordID resetting from 28,261,442 to 1.
- Linux SSH sequences are convincing. On APP-INT-01, the connection at `12:43:57.269Z` is followed by public-key acceptance at `12:44:03.118Z`, PAM session opening at `12:44:03.282Z`, logind session 376304 at `12:44:03.850Z`, eCAR login at `12:44:04.058Z`, and the shell process at `12:44:06.449Z`.
- Linux privilege changes correctly distinguish the invoking and effective principals. For example, APP-INT-01 records Lina Nguyen’s `sudo systemctl` activity as a `sudo` process owned by Lina with a root-owned `systemctl` child and matching PAM open/close records.
- Bash histories contain realistic shell behavior: redirection is absent from executed `argv`, pipelines produce only external child processes, shell built-ins such as `cd` do not generate process records, and the mistyped `grroups` command on MAIL-CLIN-01 produces no process.
- Host roles are differentiated: FILE-LNX-01 has substantial `smbd`/`smbd_audit` activity, MAIL-EDGE-01 has Postfix/Dovecot activity, DB-PROD-01 has `multipathd` and database administration, Lina Nguyen uses Git/npm/Docker/Cargo, and Omar Haddad uses Python/pandas and SQL clients.
- Expected maintenance and background activity is present, including `TiWorker.exe`, Defender components, Group Policy, search indexing, `snapd`, unattended upgrades, systemd timers, log rotation, DHCP, and workstation lock/unlock events.

## Detailed Analysis

### Windows Process and Sysmon Evidence

The ten Windows hosts contain 970 Sysmon Event 1 records and 976 Security 4688 records. For matched events, Sysmon precedes Security by approximately 35–636 milliseconds, which is plausible source-specific reporting latency. Image hashes remain stable for the same binary and OS build, while Windows 10/11 and Server 2019/2022 binaries appropriately have different hashes and versions.

ProcessGUID use is internally sound. Parent GUIDs reference already-existing processes, termination records reuse the original GUID, and dependent events do not appear before the same visible ProcessGUID’s creation.

The principal Sysmon defect is Event 8 on WS-AJOHNSON. At `15:44:39.204Z`, PID 6200 starts as:

`ms-index-service.exe "privilege::debug" "sekurlsa::logonpasswords" exit`

It opens `winlogon.exe` at `15:44:42.321Z`, opens `lsass.exe` with `GrantedAccess=0x1FFFFF` at `15:44:42.477Z`, then records a remote thread in LSASS at `15:44:42.592Z` whose alleged entry function is `NtCreateThreadEx`. This looks like a generator interpreting the thread-creation API as the target thread’s entry routine.

The ProcessAccess call-stack population is also substantially under-modeled. Only eight normalized stack shapes serve 741 events across diverse sources including `csrss.exe`, `services.exe`, `MsMpEng.exe`, `WmiPrvSE.exe`, `msiexec.exe`, and the suspicious `ms-index-service.exe`. The latter’s LSASS access stack ends in `wbemcomn.dll+15398`, despite the process otherwise presenting as a metadata-less credential-dumping executable.

### Process-Tree and User-Behavior Realism

Core Windows chains are mostly sensible: `services.exe` launches services, `svchost.exe` launches WMI/task-host activity, search processes descend from `SearchIndexer.exe`, and RDP sessions contain `winlogon.exe → userinit.exe → explorer.exe`.

User differentiation is good. Administrative workstations launch PowerShell, SSH, RDP, MMC, `runas`, and Group Policy tools, while other workstations emphasize Office, Webex, browsers, Tableau, Dropbox, or Adobe maintenance.

Browser topology is the main defect. Every visible Firefox creation is an `explorer.exe` child launched with a destination URL. WS-AJOHNSON alone has four separately long-lived Firefox roots, including three started at `16:15:38Z`, `16:24:43Z`, and `16:25:10Z` that all survive until about `17:54:59Z`. There are no Firefox content-process children despite the otherwise detailed process telemetry.

### Logon and Session Lifecycles

I found no visible logout-before-login contradiction for a shared session identifier. RDP Type 10 sessions last tens of minutes to several hours, and lock/unlock activity correctly reuses the existing interactive Logon ID. For example, WS-MCHEN uses Logon ID `0x6b920ba` for Event 4800, Type 7 Event 4624, and Event 4801 during three separate lock/unlock cycles.

Network-logon lifetimes are much less convincing. Almost all visibly paired Type 3 sessions terminate inside an apparent 60-second duration envelope. FILE-SRV-01, despite being a file server with 5140/5145 and SMB activity, has all 53 paired Type 3 sessions terminate within 38.716 seconds. This lacks persistent SMB sessions and the long-tailed connection reuse expected from normal clients.

### Linux, Syslog, and Bash Evidence

The Linux authentication sequences are among the strongest parts of the dataset. SSH connection, authentication, PAM, logind, eCAR session, shell creation, command execution, shell termination, PAM close, and logind removal occur in credible order with modest source-specific delays.

Scheduled activity is staggered by host and includes slight timestamp jitter and occasional missing observations. The recurring `debian-sa1` command appears every 30 minutes on many hosts, while unrelated services contribute uneven noise. FILE-LNX-01’s 310 combined `smbd` and `smbd_audit` lines and WEB-EXT-01’s 918 UFW block messages produce host-specific volume rather than a flat source distribution.

Bash histories preserve shell semantics well. At DB-PROD-01, the visible SSH root session starts at `17:15:11Z`; `mysqldump` starts at `17:15:19.408Z`, creates `/tmp/rpt_0318.sql`, terminates before `gzip`, and `scp` then opens the corresponding SSH flow. Earlier root-history entries cannot be assigned to that session and were treated as potentially belonging to another shell, not as an ordering defect.

### eCAR and Cross-Source Correlation

eCAR process identities, actor IDs, PIDs, Logon IDs, and session IDs are coherent. I found no process actor referencing a later visible creation, no reused PID overlapping another visible lifetime, and no process termination preceding the same object’s creation.

The DB-PROD-01 transfer is a strong correlation example: `scp` PID 884810 opens `10.10.4.10:46919 → 10.10.2.30:22` at `17:15:59.635Z`; Zeek observes the flow at approximately `17:15:58.968Z` with 1,732,499 origin bytes and an `SF` close; APP-INT-01 then creates the received file at `17:16:35.914Z`. The subsequent SMB write to FILE-LNX-01 likewise shares tuple `10.10.2.30:43698 → 10.10.2.21:445` and the same file path across eCAR and Zeek SMB records.

The exact four-hour WMI lifetimes are the principal eCAR lifecycle fingerprint. Independent processes on FILE-SRV-01 and MAIL-FIN-01 terminate exactly 14,400.001 seconds after creation, indicating a configured maximum rather than activity-driven lifetime.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the synthetic-confidence score |
|---|---|---|---|
| `hard_contradiction` | Sysmon Event 8 | One high-salience credential-access event | Uses creator API `NtCreateThreadEx` as the target thread’s entry function and adds injection semantics inconsistent with the adjacent memory-read activity. |
| `distribution_texture` | Sysmon Event 10 | 741 records across ten hosts | Only eight normalized, one-to-three-frame call-stack templates cover diverse process-access behavior. |
| `distribution_texture` | Windows Security logons | 353 of 355 paired Type 3 sessions | Near-universal sub-65-second duration ceiling lacks persistent SMB/RPC session tails. |
| `schema_or_format` | Sysmon Event 7 | Four unrelated workstations | Repeatedly treats `crashpad_handler.exe` as a loaded module rather than a child executable. |
| `contract_gap` | Windows/eCAR process trees | Ten Firefox starts across five hosts | Models each URL as a long-lived Explorer child while omitting normal Firefox content-process topology. |
| `distribution_texture` | eCAR process lifecycle | Two Windows servers | Independent WMI processes hit the identical 14,400.001-second lifetime boundary. |
| `environment_or_collection_plausibility` | Windows process telemetry | Most Windows hosts | Narrow recurring process palettes and a weak long tail for active servers and workstations. |

## Realism Score by Category

- **Field format accuracy:** 6 — Most XML and eCAR fields are well formed, but the Event 8 and executable-as-Event-7 semantics are significant native-field defects.
- **Temporal patterns:** 5 — Cross-source ordering is credible, but Type 3 sessions and WMI lifetimes expose sharp duration boundaries.
- **Cross-source correlation:** 9 — Process, session, SSH, SMB, and file-transfer relationships are highly consistent without visible identifier-ordering contradictions.
- **Behavioral realism:** 6 — Users and host roles are differentiated, but browser topology and network-session behavior remain noticeably modeled.
- **Environmental consistency:** 8 — Services, operating-system versions, maintenance activity, and host-specific noise generally fit their apparent roles.

## Recommendations

If this were synthetic, the following changes would improve it:

- Populate Sysmon Event 8 `StartAddress`, `StartModule`, and `StartFunction` from the actual target-thread entry routine. Do not emit Event 8 for ordinary credential-memory reads unless the modeled operation really creates a remote thread.
- Model Crashpad Handler as a child process of Google Drive rather than a Sysmon Event 7 module. Restrict normal Event 7 records to genuinely mapped images such as DLLs.
- Replace the small ProcessAccess call-stack pool with build- and source-process-specific stacks containing realistic depth, source modules, and occasional unresolved frames.
- Give Logon Type 3 sessions protocol-dependent, heavy-tailed lifetimes. Reuse persistent SMB sessions across multiple file operations instead of terminating nearly every network logon within one minute.
- Model browser process architecture explicitly: one persistent browser parent, renderer/GPU/utility/content children, and short-lived secondary invocations that pass URLs to the existing instance.
- Remove hard lifecycle ceilings such as exactly 14,400.001 seconds. End WMI Provider Host processes based on provider activity, idle timeout, host load, and bounded-window continuation.
- Broaden the normal Windows process long tail while keeping host roles distinct, particularly on domain controllers, servers, and actively used browser workstations.

