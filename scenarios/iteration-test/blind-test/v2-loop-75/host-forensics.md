# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 97
**Synthetic-Confidence Score:** 94

## Executive Summary

The endpoint data is highly polished and correlates well, but it contains a decisive chronology conflict: logs dated 2024-03-18 report several application versions or product generations that had not yet shipped, most clearly Zoom Workplace 6.0.11 on five workstations. An implausible Windows lock/unlock lifecycle, an eCAR flow attributed to an already-terminated process, and highly repeated Linux background-noise profiles independently reinforce a synthetic verdict.

## Evidence For Synthetic

- [hard_contradiction] The entire visible collection is dated 2024-03-18, yet Sysmon Event 1/7 records post-date that window. `WS-AJOHNSON-01.meridianhcs.local/windows_event_sysmon.xml` records `Zoom.exe` at `2024-03-18T14:28:05.7735970Z` with `FileVersion=6.0.11.39959` and `Product=Zoom Workplace`; Zoom Workplace 6.0 was not released until April 2024. The same version and hashes occur on five workstations. The dataset also places Webex `44.4.0.28421` on four hosts and Postman `11.2.14` on two hosts during March 2024, although those version generations post-date the recorded window. This is a dataset-wide timestamp-versus-binary contradiction unless an undisclosed time shift was applied.
- [hard_contradiction] `WS-AJOHNSON-01.meridianhcs.local/windows_event_security.xml` records Event 4800 (workstation locked) at `2024-03-18T16:23:22.1211021Z` and Event 4801 (unlocked) at `16:23:22.1229500Z` for the same `TargetLogonId=0x25a4b39` and `SessionId=2`: only 1.848 milliseconds apart. The associated Type 7 logon was earlier, at `16:22:53.0783558Z`, rather than accompanying this unlock. The visible sequence is not credible as an ordinary workstation lock/unlock lifecycle.
- [contract_gap] `LOG-MON-01.meridianhcs.local/ecar.json` terminates Java PID `739650`, object `214686b0-acef-48ea-873a-f0539cc78d7f`, at `2024-03-18T17:47:39.136Z`, then attributes a new outbound TCP connection to the same process at `17:47:39.266Z`. The later FLOW targets `10.10.1.10:80` from `10.10.2.40:34321`, 130 ms after the process termination.
- [distribution_texture] Linux background telemetry follows conspicuously fixed profiles across unlike systems. Ten of the eleven Linux syslogs contain exactly four `systemd-resolved` messages, and ten contain exactly five `anacron` messages; nine contain exactly eight `dbus-daemon` messages, while the two reduced desktop profiles contain six. Server-class systems repeatedly emit 36-99 `irqbalance` and 38-101 `snapd` records in six hours from a small shared message vocabulary, with workstation/laptop profiles stepping down to 8-14 and 10-22. The exact bundle counts and role-scaled volumes look generated rather than state-driven.
- [environment_or_collection_plausibility] The `irqbalance` and `snapd` rates are themselves unusual for ordinary non-debug production syslog. For example, `APP-INT-01` emits 66 `irqbalance` and 60 `snapd` records, and `WEB-EXT-01` emits 99 and 101 respectively, with messages such as “balancing pass complete” and snap state-engine updates recurring every few minutes. A real fleet could be configured verbosely, but the same behavior across many roles would require an unusual, consistently deployed logging policy.
- [weak_signal] The 771 UFW kernel records on `WEB-EXT-01` show a bounded 0-250 ms difference between the RFC 5424 timestamp and the bracketed kernel monotonic timestamp. Adjacent offsets change by a median 77 ms and as much as 248 ms despite light event rates, resembling independently sampled observation jitter more than a stable journal-to-syslog path. This is supporting evidence only because buffering can create real delay variation.

## Evidence For Real

- Windows process trees are structurally credible. Examples include `smss.exe -> winlogon.exe -> userinit.exe -> explorer.exe`, `svchost.exe -> WmiPrvSE.exe/dllhost.exe/taskhostw.exe`, `csrss.exe -> conhost.exe`, and user-shell launches of PowerShell, SSH, RDP, Office, browsers, and collaboration tools.
- All 967 visible Sysmon Event 1 process creations have exact Security 4688 counterparts by PID, image, and command line. Where a parent ProcessGUID was also created inside the window, 212 parent joins matched PID, image, user, and temporal order with no contradiction. eCAR generally preserves the same process identity and lifecycle.
- Process lifecycle handling is strong overall. Across Windows hosts, 792 Sysmon Event 1/5 pairs had valid create-before-terminate ordering; visible parent and dependent-event checks found no creation-after-use or termination-before-create errors. The unmatched starts and stops cluster naturally at collection boundaries or involve long-lived processes.
- Logon behavior has realistic variety: interactive, network, service, remote interactive, unlock, and new-credentials logons appear where appropriate. Network logons are usually short, while interactive/RDP sessions persist longer. The other observed lock/unlock pairs last approximately 13, 33, and 39 minutes, unlike the single 1.848 ms anomaly.
- Linux SSH telemetry is source-native and coherent in most cases. Forty-four visible successful sessions follow connection, accepted-key/password, PAM-open, logind-session, PAM-close, and logind-removal semantics; eight failed attempts use plausible invalid-user/pre-auth closure sequences. No visible SSH PAM close precedes its corresponding open.
- The DC-01 Security-log clearing sequence is unusually well modeled: `cmd.exe /c wevtutil cl Security` and child `wevtutil.exe` appear in Sysmon, Security 4688, and eCAR at approximately `17:41:44Z`; Event 1102 follows at `17:41:47.8177777Z`; `EventRecordID` legitimately resets from `28260958` to `1`.
- Host roles and user behavior are differentiated. `WS-LNGUYEN-01` shows developer-oriented Git, Docker, compiler, editor, and test activity; mail hosts show Postfix/Dovecot or Exchange processes; `FILE-LNX-01` contains Samba audit activity; domain controllers carry Kerberos and directory-service traffic; and desktop applications vary by user.
- Binary identity is mostly stable: repeated image/version combinations retain hashes, while core Windows hashes vary across the 17763, 19041, 20348, and 22621 operating-system families.

## Detailed Analysis

### Scope and collection window

I examined only the supplied `review-data` directory. Endpoint records span approximately `2024-03-18T12:00:00Z` through `18:00:00Z`: ten Windows systems with Security XML, Sysmon XML, and eCAR; eleven Linux systems with syslog and eCAR; and per-user bash histories on the Linux systems. I treated the data as a bounded six-hour slice, so pre-window process/session terminations and post-window-open lifecycles were not scored as defects.

### Windows process trees and source correlation

The process model is the strongest part of the dataset. Across the ten Windows hosts there are 968 Security 4688 records and 967 Sysmon Event 1 records. Every Sysmon creation matches a 4688 record on PID, image path, and command line; source timestamps differ by a plausible 35 ms to 1.251 seconds, with Security consistently following Sysmon. eCAR contains 962 corresponding PROCESS/CREATE rows after apparent source-level observation drops.

Visible parent relationships also hold. I resolved 212 Sysmon ParentProcessGUID references to process creations within the same file and found no PID, image, user, or ordering mismatch. Representative trees are source-appropriate: `services.exe` launches service executables; `svchost.exe` launches WMI, COM, and task-host children; `explorer.exe` launches interactive applications; PowerShell/cmd launch OpenSSH; and RDP sessions produce `winlogon.exe -> userinit.exe -> explorer.exe`. DC and server processes differ sensibly from user workstations.

The software metadata creates the assessment's clearest authenticity failure. At `2024-03-18T14:28:05.7735970Z`, AJOHNSON's Sysmon Event 1 reports `C:\Users\aisha.johnson\AppData\Roaming\Zoom\bin\Zoom.exe`, `FileVersion=6.0.11.39959`, and `Product=Zoom Workplace`. Identical version/hash pairs appear on DRAMIREZ, EBROOKS, PPATEL, and SMARTINEZ. Zoom's 6.x/Workplace generation post-dates March 18. Webex `44.4.0.28421` appears beginning at `13:10:31.2564324Z` on AJOHNSON and on three other hosts; its 44.4 generation denotes April 2024. Postman `11.2.14` appears at `14:42:42.3972093Z` on MCHEN and also on PPATEL, although Postman 11 belongs to a later release generation. The recurrence across multiple hosts and both process and module records rules out a one-record typo.

There is also some version texture that is suspicious but not independently decisive: every sampled Microsoft core binary is assigned an RTM-style version ending in `.1` (`10.0.17763.1`, `10.0.19041.1`, `10.0.20348.1`, or `10.0.22621.1`) rather than a cumulative-update revision. `WS-MCHEN-01` mixes modal build 22621 with `mstsc.exe`/`gpupdate.exe` at 19041 and `gpresult.exe` at 20348. Some Microsoft utilities retain cross-branch resources, so I treated this as context rather than a separate hard contradiction.

### Process and object lifecycles

Sysmon Event 1/5 lifecycle checks found 792 fully visible process pairs with no negative duration. Visible Event 3, 7, 10, 11, 13, and 22 dependencies did not precede a matching process creation. eCAR process and file dependencies were similarly coherent except for one explicit violation on LOG-MON-01.

The affected eCAR process is created at `17:47:31.788Z` as PID `739650`, `/usr/bin/java -jar /opt/meridian/service-healthcheck.jar --target DC-01.meridianhcs.local`. It connects to `10.10.2.10:636` at `17:47:35.258Z`, terminates at `17:47:39.136Z`, and then emits a second FLOW/CONNECT to `10.10.1.10:80` at `17:47:39.266Z` with the terminated object's UUID, PID, image, command line, and principal. Unlike an unmatched pre-window object, this is a visible same-identifier use after termination.

### Logon sessions and workstation state

Security 4624/4634 ordering is mostly credible. Domain controllers carry a large mix of service and network logons; workstation users show interactive Type 2, network Type 3, service Type 5, unlock Type 7, new-credentials Type 9, and occasional Type 10 activity. Short Type 3 sessions and longer Type 2/10 sessions are present, and visible logoffs do not precede their matching logons.

The exception is AJOHNSON's workstation-state sequence. A Type 7 logon for `0x25a4b39` occurs at `16:22:53.0783558Z`. Event 4800 then says that session 2 locked at `16:23:22.1211021Z`, followed by Event 4801 at `16:23:22.1229500Z`. A software-triggered state transition could be fast, but a 1.848 ms lock/unlock with no contemporaneous Type 7 event is not credible as ordinary Windows user behavior and is inconsistent with the 13-39 minute lock intervals elsewhere in this same dataset.

### Sysmon and Security field fidelity

The XML is parseable and generally follows native provider structure. Security events use appropriate provider GUIDs, channels, task/opcode values, hexadecimal process and logon IDs, SIDs, token-elevation values, and event-specific fields. Sysmon Event 1, 3, 5, 7, 8, 10, 11, 13, and 22 records contain the expected fields; Event 1 ProcessGUIDs remain stable across dependent records and Event 5 termination.

The DC-01 log-clear sequence deserves particular weight on the realism side. Security `EventRecordID` increases normally to `28260958`, Event 1102 uses the Eventlog provider and a `UserData/LogFileCleared` payload, then the record ID resets to `1`. Sysmon and eCAR show the corresponding WMI-spawned `cmd.exe` and `wevtutil.exe` activity before the clear and process termination afterward. This is the sort of source-native detail that many simplistic synthetic datasets miss.

### Linux syslog and bash history

SSH and sudo records are mostly persuasive. Successful SSH sessions use stable per-connection sshd PIDs, source tuples, authentication methods and key fingerprints, PAM opens, logind session IDs, and later closes. Failed connections show `Connection from`, `Invalid user`, `Failed password`, and `[preauth]` closure in valid order. Bash histories contain epoch timestamps, built-ins as well as external commands, and role-specific content. Parallel shell parents in eCAR explain some adjacent bash-history commands that occur at the same second.

The background system texture is much less convincing. `systemd-resolved` contributes exactly four records on ten hosts despite differences in role, DNS load, and total syslog volume. `anacron` contributes exactly five records on the same ten systems; `dbus-daemon` and `polkitd` settle into similarly fixed server/desktop profile counts. More importantly, `irqbalance` and `snapd` emit a Poisson-like stream of a small set of templates every few minutes on most servers. The counts scale with host profile rather than visible daemon state: APP-INT-01 has 66/60 irqbalance/snapd records, FILE-LNX-01 58/66, LOG-MON-01 69/61, MAIL-EDGE-01 51/43, PROXY-01 49/38, and WEB-EXT-01 99/101. That repeated texture is possible under verbose logging but unlikely across this many dissimilar production roles.

### eCAR/EDR relationships

eCAR generally agrees with endpoint-native evidence on hostnames, principals, PIDs, paths, command lines, process ancestry, logon IDs, network direction, and local IP ownership. All FLOW directions resolve consistently to one local address per host. Process-attributed files, registry operations, modules, and flows normally occur inside visible process lifetimes, and the SSH client transport appears before target-side authentication.

The single Java FLOW-after-termination case is therefore more significant than it would be in a generally unordered feed: the surrounding eCAR data consistently uses `timestamp_ms` as event time and respects lifecycle ordering. A 130 ms source-local inversion could be explained only by undocumented per-event pipeline latency, but no separate observation or ingestion timestamp is present.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Impact on score |
|---|---|---|---|
| `hard_contradiction` | Windows Sysmon Event 1/7 | Five hosts for Zoom 6.0.11; four for Webex 44.4; two for Postman 11.2.14 | Post-release software generations appear in telemetry dated 2024-03-18; this is the principal reason for the high synthetic-confidence score. |
| `hard_contradiction` | Windows Security 4624/4800/4801 | One session on WS-AJOHNSON-01 | Same session locks and unlocks 1.848 ms apart, with its Type 7 logon 29 seconds earlier. |
| `contract_gap` | eCAR PROCESS/FLOW | One process on LOG-MON-01 | PID 739650 makes a new attributed connection 130 ms after its visible termination. |
| `distribution_texture` | Linux syslog | Ten or eleven Linux hosts, depending on daemon | Exact repeated daemon bundle counts and role-scaled Poisson-like irqbalance/snapd volumes create a fleet-wide generator texture. |
| `environment_or_collection_plausibility` | Linux syslog | Multiple server and workstation roles | Debug-like irqbalance/snapd verbosity is implausibly universal without a visible collection-policy explanation. |
| `weak_signal` | Linux kernel/UFW syslog | WEB-EXT-01, 771 records | Independently varying but sharply bounded wall-clock-to-kernel timestamp offsets resemble generated observation jitter. |

## Realism Score by Category

- **Field format accuracy:** 8 — XML, RFC 5424, Sysmon, Security, and eCAR shapes are mostly source-native, but the software-version chronology is impossible and a few metadata combinations are questionable.
- **Temporal patterns:** 5 — Most event ordering is sound, but the 1.848 ms lock/unlock and process-attributed post-termination flow are material defects.
- **Cross-source correlation:** 9 — Process, session, SSH, and log-clear relationships are exceptionally coherent; the isolated eCAR lifecycle inversion is the main failure.
- **Behavioral realism:** 7 — Process trees, user roles, administrative activity, and SSH sessions are convincing, while Linux daemon noise is strongly profile-driven.
- **Environmental consistency:** 4 — Host roles and addressing are coherent, but multiple future software generations appearing in a March 2024 environment are decisive.

## Recommendations

- If this were synthetic, bind every application version and product name to the scenario date. Add release-date validation for software catalogs, including modules, and test boundary cases such as Zoom 5.x versus Zoom Workplace 6.x, Webex year/month versions, Office channel builds, and Postman major versions.
- Make workstation locking a real lifecycle: emit 4800, wait a human-scale interval, then align Type 7 logon and 4801 within normal provider latency. Add an invariant that rejects same-session lock/unlock pairs below a configurable minimum unless an explicit automation event explains them.
- Enforce process-lifetime bounds after all source-observation timing is applied. Any eCAR FLOW, FILE, MODULE, REGISTRY, PROCESS/OPEN, or THREAD event carrying an actor UUID must remain between that actor's create and terminate timestamps, or the process termination must be delayed.
- Replace fixed Linux daemon record bundles with daemon-state models. Vary whether `systemd-resolved`, `snapd`, `irqbalance`, `anacron`, D-Bus, and polkit emit at all; couple messages to actual transitions and work; and allow long-tail host-specific services and quiet hosts rather than scaling the same small vocabulary by profile.
- Model the kernel-to-syslog timestamp relationship as a stable clock offset plus realistic queueing delay tied to load, rather than independently varying each record inside a fixed 250 ms envelope.
