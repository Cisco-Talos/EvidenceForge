# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 84  
**Synthetic-Confidence Score:** 78

## Executive Summary

The telemetry is likely synthetic. The strongest basis is not the sanitized naming, the selected event families, the unusually good cross-source matching, missing source families, or the compact intrusion sequence. It is repeated source-native texture that is difficult to reconcile with an organic fleet: all 713 Sysmon Event ID 10 `CallTrace` values stop at one to three frames; 103 same-process/target access bursts exhibit tightly stepped sub-millisecond records; and five failed-logon bursts retain exact whole-second retry intervals and nearly fixed fractional-second phases.

A second strong concern is selective field impoverishment. Sysmon is visibly configured to emit SHA1, MD5, SHA256, and IMPHASH on ordinary process starts, yet 19 of 972 Event ID 1 records use `Hashes=-`. Those omissions include `ms-index-service.exe` performing credential-dumping behavior and both `curl.exe` processes used around the outbound archive transfer. One hundred process-start records also have every PE metadata field set to `-`, concentrated in a small set of executable names rather than looking like a natural mixture of acquisition failures.

The opposing evidence is substantial. XML/JSON structure is credible, Windows event versions and resource codes are appropriate, host-specific WFP/filter and volume identifiers vary plausibly, process and session lifecycles contain no visible reversed pairs, and Windows Security/Sysmon/eCAR views agree on PID, image, parent, command line, identity, and timing without being timestamp clones. Linux SSH trees also preserve transport-before-auth and auth-before-shell order. Those strengths keep the result below the “confidently synthetic” band, but they do not overcome the repeated timing and Sysmon-native artifacts.

## Evidence For Synthetic

- **[schema_or_format] Dataset-wide three-frame ceiling in Sysmon ProcessAccess stacks.** Across 713 Event ID 10 records on ten Windows hosts, `CallTrace` has exactly three frames in 544 records, one frame in 149, and two frames in 20; none has more than three. The cap persists across Windows 10, Windows 11, Server 2019, and Server 2022-like hosts and across Defender, LSASS, WMI, COM, Search, and malicious process access. Sysmon does not normally impose such a universal three-frame ceiling.

- **[contract_gap] Hash collection is active but selectively disappears on important executables.** Of 972 Sysmon Event ID 1 records, 19 contain `Hashes=-` while ordinary records carry four algorithms. Examples include `C:\Windows\System32\ms-index-service.exe` at 15:45:04Z with credential-dumping arguments, `C:\Windows\PSEXESVC.exe`, both `curl.exe` launches at 17:25:27Z, `runas.exe`, and multiple updater/monitoring binaries. A real sensor can fail to hash an image, but the concentration on uncatalogued or storyline-relevant executables is conspicuous.

- **[schema_or_format] PE metadata collapses to all-or-nothing catalog entries.** One hundred of 972 process starts have `FileVersion`, `Description`, `Product`, `Company`, and `OriginalFileName` all equal to `-`. Repetition is executable-specific: all 14 observed `Microsoft.Exchange.Imap4.exe` starts and all nine `EdgeTransport.exe` starts on `MAIL-FIN-01` lack the complete metadata tuple, as do repeated Google updater launches on several workstations. This resembles a finite enrichment catalog more than per-file PE inspection.

- **[distribution_texture] Failed-logon bursts preserve mechanical timing phases.** Five multi-attempt Windows bursts have whole-second interval sequences of `[6.001, 2.000, 4.000, 4.000]`, `[6.998, 2.000, 12.000, 3.000]`, `[4.000, 4.000]`, `[5.999]`, and `[2.000]` seconds. Within each burst, eCAR timestamps preserve exactly the same millisecond component (for example, `.736` on `WS-DRAMIREZ-01`, `.292` on `WS-EBROOKS-01`, and `.770` on `WS-PPATEL-01`), while the Security XML adds only small source-local jitter. That repeated construction is more regular than ordinary human retries and more stylized than a stable machine retry loop.

- **[distribution_texture] ProcessAccess bursts use arithmetic sub-millisecond spacing.** There are 103 clusters, totaling 228 Sysmon Event ID 10 records, where the same source/target process pair is logged repeatedly within 10 ms. Many clusters use nearly exact repeated increments, such as 0/0.978/1.956 ms or 0/0.991/1.982 ms, while cycling a small rights set (`0x0400`, `0x1000`, `0x1400`, `0x1010`, `0x1410`). Tight loops can occur in production, but this fleet-wide, template-like cadence compounds the three-frame call-stack artifact.

- **[distribution_texture] SSH authentication delay occupies an unusually bounded band.** All 48 successful SSH sessions with a matching inbound endpoint FLOW place login 5.975–16.626 seconds after that FLOW; the quartiles are 7.983, 9.072, and 10.103 seconds. No internal session authenticates in under roughly six seconds. Uniformly applying a multi-second handshake window across several servers, users, and interactive/SCP activity is more suggestive of modeled stage offsets than an organic mix of key, password, cached, delayed, and immediately rejected exchanges.

- **[contract_gap] The database archive shell/file sequence is causally awkward.** `DB-PROD-01` root history hashes `/tmp/rpt_0318.sql.gz` at 17:15:00Z and measures it at 17:15:11Z, then runs `gzip -9 /tmp/rpt_0318.sql` at 17:15:12Z. eCAR records the `.gz` file creation only at 17:15:16.883Z and its later SCP read at 17:15:32.873Z. A pre-existing archive or an unlogged removal is theoretically possible, so this is not treated as an absolute contradiction; however, an existing destination would normally cause `gzip` without `-f` to refuse replacement, leaving the observed command/file contract internally strained.

- **[weak_signal] Native file-version enrichment is unusually canonicalized.** Populated Microsoft system-binary versions are dominated by exact baseline strings such as `10.0.19041.1`, `10.0.20348.1`, and `10.0.22621.1`, even where servicing-stack paths expose later patch revisions. Some real binaries retain baseline version resources, so this is only a weak supporting signal, not a decisive defect.

## Evidence For Real

- All 33,663 eCAR records have unique event IDs. Among 1,772 process object IDs with both visible create and terminate records, none terminates before creation. Among 470 session object IDs with both visible login and logout records, none logs out before login.

- The 972 Sysmon process starts produce coherent process trees. No visible child starts before a visible parent start, no child starts after the same visible parent has terminated, no process terminates before its own start, and no PID is visibly reused while a prior process with that PID remains active.

- For 971 Security 4688/Sysmon 1 process-start matches, PID, image, command line, parent PID, and parent image agree. Their event times have plausible source-specific offsets rather than exact duplication. eCAR process views similarly preserve the same semantic facts while using a different identifier and timestamp representation. This semantic agreement, rather than the mere match rate, supports a credible collection model.

- Windows logon semantics are detailed and generally source-native: service logons use type 5/Advapi/Negotiate; RDP uses type 10/User32; network logons distinguish Kerberos and NTLM; account SIDs remain stable across hosts; 4672 follows the associated privileged login; and no paired 4624/4634 sequence is visibly reversed.

- `DC-01` Security Event ID 1102 is formatted under the Eventlog provider with `LogFileCleared` UserData, resets `EventRecordID` to 1, and is followed by a fresh increasing record sequence. Sysmon continues independently. That behavior is a credible representation of clearing only the Security channel.

- WFP Event ID 5156 records retain host-specific, reused `FilterRTID` sets rather than inventing a new filter ID per flow. `LayerRTID`/`LayerName` and direction are internally consistent, and device-volume prefixes differ by host.

- Linux SSH behavior is mostly coherent. For all 48 matched successful sessions, endpoint FLOW precedes login; interactive sessions then create a shell under the correct logon/session identity, while short SCP-style sessions can legitimately have no shell. Shell children, commands, file operations, and logout/termination order are otherwise consistent.

- Bash histories contain 308 monotonically ordered timestamped commands across 26 files and show host-role variation: mail-service inspection on mail hosts, database commands on database systems, web/service diagnostics on application hosts, and developer tooling on user workstations. The histories are not simple copies of one common command list.

- Fleet details vary credibly: server and workstation OS-version families differ; Defender platform paths are not identical everywhere; EventRecordID ranges and gap patterns differ by host; Linux PID bases and cron phases differ; and long-lived GUI/service process durations are distinct from short command-line utilities.

## Detailed Analysis

The review covered only record contents under `review-data`: 33,663 eCAR records, 18,687 Windows Security events, 11,812 Sysmon events, and 308 timestamped bash-history commands. Filesystem timestamps, parent-directory material, scenario context, prior reports, and external manifests were not used.

Windows process telemetry is the strongest mixed area. Lifecycle and identity semantics are excellent: Security 4688, Sysmon 1, and eCAR process events agree on execution facts, process GUID lifetimes are coherent, PIDs are reused only after termination, and RDP-related `winlogon.exe` → `userinit.exe` → `explorer.exe` chains have sensible durations. The credential-dumping process on `WS-AJOHNSON-01` also has a valid parent, runs as `aisha.johnson`, opens `winlogon.exe` and `lsass.exe`, creates a remote thread, and terminates afterward. Conversely, **[schema_or_format]** its hashless process-start record and the universal one-to-three-frame ProcessAccess stacks look like generated source-native approximations rather than raw Sysmon output.

The ProcessAccess population is especially diagnostic. Access masks and source/target pairings are plausible, and exact traces are not reused across inferred OS-build families, which supports realism. Yet **[distribution_texture]** the absence of any four-frame-or-longer stack in 713 records and the frequent arithmetic micro-bursts are fleet-wide regularities, not isolated odd records. That breadth gives them more weight than a single malformed event.

Authentication/session evidence is also semantically strong. Type 2, 3, 5, 7, 9, and 10 events use appropriate packages and process names; Kerberos and NTLM behavior differs; account-disabled failures use `0xc000006d/0xc0000072`; bad-password failures use `0xc000006d/0xc000006a`; and session termination ordering is valid. The adverse point is **[distribution_texture]** rather than event correctness: repeated failed-login attempts preserve integer-second spacing and fixed millisecond phases across several unrelated workstations. RDP transport-to-logon delays likewise sit mainly in a narrow several-second window, though the 19-session sample is too small to score separately from the broader timing concern.

Linux process and SSH records show good DFIR semantics. An inbound flow precedes authentication, `sshd: user [priv]` ownership transitions into the user shell, command children inherit the session/logon identity, and SCP produces transport and file-read activity without requiring an interactive shell. Cron-launched `debian-sa1` activity has stable parentage and per-host PID progression. However, **[distribution_texture]** the successful SSH flow-to-login delays are conspicuously bounded across every matched session. The root database history/file ordering remains the main **[contract_gap]** in the Linux evidence.

Service, task, and boot-adjacent behavior is credible where visible. Security 4697 records for `PSEXESVC`, `DeviceSyncSvc`, and `DirectoryCacheSvc` carry plausible service types, start types, accounts, and paths; the 4698 scheduled-task XML is syntactically coherent; and the relevant service executables later start under `services.exe`. No boot-to-shutdown conclusion is drawn because this is a bounded window and the absence of boot families is not an authenticity indicator. The only environmental concern retained is **[weak_signal]** canonicalized binary-version enrichment; host-specific volumes, filters, OS families, and endpoint-product paths otherwise argue the other way.

I found no defensible `hard_contradiction`. The archive-order issue is close, but a pre-existing archive plus an unobserved removal cannot be excluded from this bounded, selectively observed window. The verdict therefore rests on multiple repeated schema/texture artifacts, not on an asserted impossibility.

## Synthetic Indicator Summary

| Indicator | Category | Scope | Weight |
|---|---|---:|---|
| Sysmon Event ID 10 call stacks never exceed three frames | schema_or_format | 713 records / 10 hosts | Very high |
| Hashes absent on 19 process starts despite active four-hash collection | contract_gap | Repeated / fleet-wide | High |
| All-five-field PE metadata gaps cluster by executable identity | schema_or_format | 100 records | High |
| Whole-second failed-logon bursts retain fixed fractional phases | distribution_texture | 5 bursts / 4 hosts | High |
| Arithmetic sub-millisecond ProcessAccess burst spacing | distribution_texture | 103 clusters / 228 records | Medium-high |
| Successful SSH flow-to-login delay bounded at 5.975–16.626 seconds | distribution_texture | 48 sessions / multiple hosts | Medium |
| Archive hash/size checks precede visible gzip/file creation | contract_gap | One sequence | Medium |
| Canonicalized native binary version strings | weak_signal | Fleet-wide | Low |

## Realism Score by Category

| Category | Score |
|---|---:|
| Field format accuracy | 7/10 |
| Temporal patterns | 5/10 |
| Cross-source correlation | 9/10 |
| Behavioral realism | 7/10 |
| Environmental consistency | 7/10 |

## Recommendations

1. Remove the apparent Sysmon Event ID 10 stack-depth ceiling. Produce source-native call stacks whose depth, modules, and offsets vary by executable, code path, and OS build; validate distributions against real Sysmon ProcessAccess samples.
2. Treat Sysmon hashes as sensor output, not catalog enrichment. When configured algorithms are visible, calculate/populate them for every accessible process image, including unknown and malicious binaries; model a hash failure only with a defensible source-native reason.
3. Populate PE metadata from executable-specific records independently of threat-story importance. Avoid the repeated pattern where all five metadata fields are either fully known or all `-` for every occurrence of a binary.
4. Replace fixed-offset authentication bursts with actor-specific retry models. Human attempts should have reaction-time variance; service retries should show a stable policy cadence plus scheduler/network jitter, without preserving an identical millisecond phase across a burst.
5. Broaden SSH and RDP stage timing. Include credible subsecond LAN authentication, ordinary one-to-several-second sessions, occasional DNS/GSSAPI/PAM delays, and a genuine long tail tied to authentication method and host conditions.
6. Add a causal validation pass between shell history and endpoint file events. For the database sequence, create/compress the archive before hashing and sizing it, or explicitly record the removal/replacement behavior that makes a pre-existing archive path coherent.
7. Preserve the current strengths: PID/GUID lifecycle integrity, source-specific timestamp offsets, SID stability, WFP filter reuse, Security-channel reset behavior, Linux privilege/session transitions, and host-specific environmental variation.
