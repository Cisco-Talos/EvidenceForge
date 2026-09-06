# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 95  
**Synthetic-Confidence Score:** 93

## Executive Summary

The endpoint telemetry is unusually strong at the ordinary event-schema and correlation level, but several log-visible patterns are much more consistent with a deterministic renderer than with independently produced host telemetry. The decisive indicators are a physically implausible sub-millisecond lock/unlock pair, an incorrect explicit-credential source address, the same wrong TiWorker parent chain repeated on six Windows systems, bounded one-directional Security/Sysmon timing offsets across 926 paired process starts, identical low-level WFP thread-ID support on every Windows host, and exact repeated Linux subsystem event counts across otherwise different systems.

## Evidence For Synthetic

- [hard_contradiction] `WS-AJOHNSON-01.meridianhcs.local/windows_event_security.xml` records Event 4800 at `2024-03-18T17:48:17.3933800Z` and Event 4801 at `17:48:17.3940149Z` for the same user (`aisha.johnson`), Logon ID `0x263743b`, and Session ID `2`: a lock-to-unlock interval of only 0.0006349 seconds. The immediately preceding event is a GoogleDriveFS process start at `17:48:17.3918229Z`; there is no corresponding Type 7 unlock logon in that sequence. A human workstation unlock cannot complete in 0.635 ms.
- [hard_contradiction] On `WS-MCHEN-01`, Event 4688 at `2024-03-18T14:50:12.5963906Z` creates local PID `0x20d0` as `runas.exe /netonly /user:marcus.chen "cmd.exe /c dir \\DC-01\ADMIN$"`. Event 4648 for that same PID at `14:50:15.3596848Z` says `IpAddress=10.10.1.99`, although this host's visible address is `10.10.1.31`; later Event 4648 records on this same host correctly use `10.10.1.31`. The record combines a demonstrably local process identity with another endpoint's source address.
- [contract_gap] Six Sysmon Event 1 records on six different systems—DC-01, WS-AJOHNSON-01, WS-DRAMIREZ-01, WS-EBROOKS-01, WS-MCHEN-01, and WS-PPATEL-01—show `TiWorker.exe -Embedding` as a direct child of `svchost.exe -k netsvcs`, with the parent running as `NT AUTHORITY\NETWORK SERVICE` and TiWorker as SYSTEM. The Windows servicing chain normally has the Windows Modules Installer/TrustedInstaller process own TiWorker. Repeating the same source-native parent substitution across Server 2022, Windows 10, and Windows 11 builds is a family-level process-tree defect, not a one-off host quirk.
- [distribution_texture] I paired 926 Security 4688 records to Sysmon Event 1 by host, PID, image, command line, and a two-second window. Every pair has Sysmon first and Security later. Per-host minimum offsets are tightly bounded at 35.0-42.8 ms, medians at 120.3-166.4 ms, and maxima at 474.1-649.6 ms. There are no negative offsets and no near-simultaneous pairs. This one-sided bounded-jitter envelope repeats on all ten Windows systems and looks like a shared source-delay profile rather than independent provider timing.
- [distribution_texture] All ten Windows Security logs use exactly the same 38 `System/Execution ThreadID` values for Event 5156: every multiple of four from 52 through 200, inclusive. This exact support is fully populated on every host despite volumes ranging from 370 records on WS-EBROOKS-01 to 4,203 on DC-01. Kernel thread IDs being aligned is normal; ten different hosts exhausting the identical finite interval and never emitting a 5156 from any thread outside it is a conspicuous generator-like pool.
- [distribution_texture] Linux source-family counts have exact repeated ceilings across unlike servers and workstations. Nine of eleven syslog files contain exactly eight `dbus-daemon` rows; ten of eleven contain exactly four `systemd-resolved` rows and exactly five `anacron` rows (DB-PROD-01 is the sole zero-count exception for both). The `systemd-resolved` records also repeatedly use a four-message degraded/resumed vocabulary and then stop, even while each file spans six hours. This is concrete count and vocabulary quantization, not merely thin coverage.
- [environment_or_collection_plausibility] Type 5 service logons are especially dense on the domain controllers—154 on DC-01 and 111 on DC-02 in six hours—while only 23 and 9, respectively, have any 4688 process creation within ten seconds. Selective auditing can explain individual missing companions, but the contrast with essentially complete 4688/Sysmon Event 1 pairing elsewhere, plus repeated 4672 privilege rows for the same built-in identities, gives the DC service activity a partially rendered rather than organically collected texture.
- [weak_signal] The endpoint source mix is sharply quantized by host family: each Windows host has the same small set of Security/Sysmon event families, while Linux hosts repeatedly receive the same fixed-count background categories. This is not evidence merely because coverage is curated; it matters only in combination with the exact cross-host cardinalities and bounded timing distributions above.

## Evidence For Real

- The Windows XML is structurally convincing. Provider GUIDs, channels, event versions, tasks, opcodes, keywords, hexadecimal Security PIDs, decimal Sysmon PIDs, SIDs, integrity levels, and message-resource values are consistently source-native across the sampled events.
- Sysmon ProcessGUIDs have credible machine and time structure rather than arbitrary UUIDv4 values. Each host has a stable first component (for example, `83eb9c06` on DC-01 and `fd907e59` on WS-AJOHNSON-01), later components advance with process time, and matching Event 5 records reuse the exact Event 1 ProcessGUID.
- Process lifecycle integrity is strong. Across all eCAR files, I found no dependent record whose visible `actorID` predates that actor's visible process creation, no dependent record after the actor's visible termination, and no actor/PID disagreement. In Sysmon, no visible child was created before its visible parent or after the parent's visible termination, and every visible parent GUID resolved to the same image claimed in `ParentImage`.
- Binary identity is coherent. Across 88 distinct Windows process images, some paths have several hash sets because the hosts show different OS builds, but no `(Image, FileVersion)` pair has more than one hash set. For example, DC-01 uses Server build `10.0.20348.2322`, while workstation binaries show `10.0.19041.3636` and `10.0.22621.3155`, with internally stable hashes.
- The DC-01 Security-log clear sequence is notably accurate. Event 4688 records show `cmd.exe /c wevtutil cl Security` at `17:41:55.4013325Z` and `wevtutil.exe` at `17:41:55.7372768Z`; Event 1102 follows at `17:41:59.2606262Z`, resets `EventRecordID` to 1, and subsequent records continue at IDs 4, 5, 6, and onward. The 1102 payload correctly uses `UserData/LogFileCleared` and identifies SYSTEM/`0x3e7`.
- The PsExec sequence on DC-01 is technically coherent: Event 4697 creates `PSEXESVC` at `16:00:23.2359892Z`; Sysmon Event 1 starts `C:\Windows\PSEXESVC.exe` from services.exe at `16:00:24.7902722Z`; Security 4688 reports it at `16:00:24.8342174Z`; it starts `cmd.exe /c whoami && hostname` around `16:00:31Z`; and the service process terminates around `16:00:35Z` with the same PID/GUID.
- Windows session lifecycles generally respect visible-window boundaries. I found no 4634 preceding a visible 4624 for the same host, account, Logon ID, and type. Network sessions have varied short durations, while interactive/RDP sessions have much longer durations; unmatched starts and stops can plausibly cross the six-hour window.
- Linux SSH records preserve accepted-authentication, PAM-open, session-start, disconnect, and PAM-close ordering by sshd PID. No reversed visible SSH sequence was found. The systems also have role-sensitive noise: FILE-LNX-01 has SMB/audit activity, WEB-EXT-01 has heavy UFW blocks, the mail hosts have Postfix/Dovecot activity, and DB-PROD-01 has multipath/database-administration behavior.
- User activity has credible differentiation. Lina Nguyen's Linux workstation history contains development and operations work (`npm run build`, Git, Docker, Kubernetes, editors, SSH), Omar Haddad uses pandas/CSV/SQL commands, and the Windows finance/developer/admin systems show different application and administration mixes.

## Detailed Analysis

The reviewed window is approximately `2024-03-18T12:00:00Z` through `17:59:54Z`. Host telemetry covers ten Windows systems with Security and Sysmon XML, eleven Linux systems with RFC 5424-like syslog, and eCAR JSON on 21 endpoints. Across eCAR there are 23,866 FLOW/CONNECT, 1,929 PROCESS/CREATE, 1,787 PROCESS/TERMINATE, 1,046 USER_SESSION/LOGIN, 595 USER_SESSION/LOGOUT, 733 PROCESS/OPEN, and smaller file/registry/module/thread/service families.

### Windows process evidence

Security/Sysmon process matching is exceptionally clean: 926 Security 4688 events pair to Sysmon Event 1 on PID, image, and exact command line. FILE-SRV-01 and the principal workstations have complete visible pairings; DC-01, DC-02, MAIL-FIN-01, and WS-DRAMIREZ-01 each have only one extra Security creation. Matching ProcessGUID termination checks reveal no terminate-before-create sequence, and parent GUID checks reveal no visible parent ordering or image contradiction.

The correlations are credible in individual timelines. For example, DC-01's persistence sequence shows WmiPrvSE -> cmd -> sc.exe, Event 4697 for `DeviceSyncSvc`, then cmd -> schtasks.exe, Event 4698, and a later services.exe -> DeviceSyncSvc.exe start. Hashes, PIDs, ProcessGUIDs, parents, users, and command lines remain aligned.

The problem is repeated family-level texture. All 926 matched process starts use the same one-way, bounded Security-after-Sysmon delay model. More importantly, all six visible TiWorker starts use the same implausible `svchost -k netsvcs`/NETWORK SERVICE parent, despite three Windows build families. Production fleets can share configuration; they should not repeat an incorrect servicing-process genealogy this consistently.

### Logon and session evidence

Security contains 872 Event 4624 records: 433 Type 3, 419 Type 5, ten Type 2, four Type 10, three Type 9, and three Type 7. It contains 447 Event 4634 records, of which 430 are Type 3. Visible matching found no logout-before-login contradiction, and the ordinary Type 3 durations vary rather than landing on fixed intervals.

The lock/unlock behavior is mixed. WS-MCHEN-01 has credible pauses: lock at `14:54:54.9118305Z`, Type 7 at `15:00:46.6008045Z`, and unlock at `15:00:47.0586562Z`; another lock at `17:06:19.3313270Z` is followed by Type 7 and unlock around `17:55:48Z`. Against that, WS-AJOHNSON-01's 0.635-ms 4800/4801 pair has no possible human interpretation and no Type 7 bridge. Its contrast with the correctly modeled WS-MCHEN sequence makes it more likely a lifecycle edge-case defect than a collection artifact.

The explicit-credential events are also mostly plausible: Veeam and MonitoringHost use SYSTEM and stable process IDs, while runas/Powershell cases use user sessions. The `14:50:15.3596848Z` WS-MCHEN Event 4648 is the exception. Its PID belongs to a locally observed runas process, but `IpAddress=10.10.1.99` conflicts with later same-host 4648 records that use `10.10.1.31`. This is a concrete ownership/address defect.

### Security and Sysmon metadata

Field schemas are generally accurate. Event 4624 uses the expected version-2 field set; 4688 includes parent process and mandatory label; 1102 correctly switches provider and payload namespace; Sysmon Event 1 includes source-native process metadata; and Event 5 reuses process identity. Event record IDs progress normally, including realistic gaps from source selection and the post-clear reset.

The Security 5156 `Execution` metadata is the strongest statistical fingerprint. Every one of the 11,579 records uses ProcessID 4 and a ThreadID from the exact set `{52, 56, ..., 200}`. ProcessID 4 and four-byte-aligned thread IDs are individually plausible. The implausibility lies in all ten systems independently using every member of that same 38-value support, with zero values outside it, across very different record volumes. By contrast, FilterRTIDs are sensibly host-specific, which makes the shared ThreadID pool stand out further.

### Linux and user behavior

The Linux messages are syntactically convincing and often role-specific. SSH PID sequences are ordered; sudo open/close pairs are sensible; DHCP renewals have REQUEST/ACK/bound phases; and the mail, SMB, proxy, database, and exposed-web systems have distinct workloads. Bash histories also show role differentiation and nonuniform command timing.

However, several generic background families look allocated by fixed quotas rather than emitted by real daemons. Exactly four systemd-resolved records appear on ten systems, commonly alternating “Using degraded feature set” and “Grace period over” messages. Exactly five anacron records occur on the same ten systems. Nine systems have exactly eight dbus-daemon rows, while the two desktop-profile exceptions have five. Because these equalities span servers, mail nodes, an exposed web host, a proxy, and workstations, they materially reduce authenticity despite the better variation in irqbalance and snapd volumes.

### Overall weighting

The dataset does not fail because it is well correlated or because its source set is selected. In fact, the correlation implementation is a major strength. The synthetic verdict rests on concrete source-native defects and repeated distributions: an impossible lock duration, wrong caller address, repeated invalid TiWorker ancestry, a common bounded inter-provider delay profile, a universally identical WFP ThreadID pool, and exact Linux category quotas. Together these are too numerous and too systematic to attribute to sanitization or a narrow collection window.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---:|---|
| hard_contradiction | Windows Security 4800/4801 | One session | 0.635-ms lock/unlock is physically implausible and lacks the otherwise modeled Type 7 bridge. |
| hard_contradiction | Windows Security 4648 | One explicit-credential event | Local runas PID on WS-MCHEN is assigned another host's source address. |
| contract_gap | Sysmon process trees | Six hosts / three OS-build families | TiWorker repeatedly has the wrong svchost/NETWORK SERVICE parent. |
| distribution_texture | Security 4688 + Sysmon 1 | 926 matched starts / ten hosts | Every Security timestamp follows Sysmon inside the same narrow bounded-jitter envelope. |
| distribution_texture | Security 5156 metadata | 11,579 rows / ten hosts | Every host uses the identical fully populated 38-value ThreadID pool and nothing else. |
| distribution_texture | Linux syslog | Ten or eleven hosts | Generic daemon families land on exact repeated counts and small repeated vocabularies. |
| environment_or_collection_plausibility | Security 4624/4672/4688 | Both domain controllers | Dense Type 5 logons have few nearby process-start companions despite detailed process auditing. |

## Realism Score by Category

- **Field format accuracy:** 8/10 — XML/JSON/syslog formatting and most source-native fields are strong, but the 4648 address and repeated TiWorker ancestry are material defects.
- **Temporal patterns:** 5/10 — Most lifecycles are ordered, but the impossible lock/unlock and dataset-wide bounded provider-delay envelope are strong tells.
- **Cross-source correlation:** 9/10 — PIDs, GUIDs, commands, hashes, actor references, and lifecycles correlate extremely well without visible ordering failures in the sampled process graph.
- **Behavioral realism:** 7/10 — Role-sensitive user and service activity is convincing, offset by repeated process-tree and background-quota patterns.
- **Environmental consistency:** 6/10 — Host roles and OS builds are differentiated, but identical WFP thread support and Linux generic-family counts cut across those differences unnaturally.

## Recommendations

- If this were synthetic, derive lock/unlock activity from an explicit session-state machine with a human-scale locked interval and require Type 7/4801 consistency when that source family is observed.
- Make explicit-credential source addressing come from the local caller host/process ownership record. Add a validation invariant that a local 4648 process PID cannot carry an unrelated endpoint's address.
- Correct the Windows servicing process bundle so TrustedInstaller owns TiWorker, and test the invariant across Server 2022, Windows 10, and Windows 11 sibling paths.
- Replace bounded per-source timestamp jitter with source-native event-time behavior. Process-creation providers should permit near-simultaneous timestamps and natural overlap instead of forcing every Security 4688 after Sysmon Event 1.
- Allocate Event 5156 execution metadata from host lifecycle state rather than a global 52-200 ThreadID pool; preserve alignment while allowing host/boot/CPU-dependent support and churn.
- Generate Linux daemon messages from persistent subsystem state and independent transitions rather than fixed per-host quotas. Counts, vocabulary, and timing should vary with role, uptime, failures, and recovery episodes.
- Reconcile Type 5 logons with visible service/process activity under the declared collection profile, especially on domain controllers, so dense service-token creation does not look detached from process auditing.
