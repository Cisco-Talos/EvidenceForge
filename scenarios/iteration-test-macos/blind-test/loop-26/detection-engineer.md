# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 80
**Synthetic-Confidence Score:** 64

## Executive Summary

The records are generally convincing and should support practical SIEM parsing and correlation. My synthetic verdict rests on repeated timing distributions rather than broken schemas: macOS shell activity repeatedly preserves fractional-second anchors across different commands, and matching Windows Security process creations always follow Sysmon with a similar bounded delay on every inspected host. I found no demonstrated impossible lifecycle or source-native schema contradiction, so these findings support a moderate synthetic-confidence score rather than certainty.

## Evidence For Synthetic

- [distribution_texture] Near-integer command spacing on both Macs: among consecutive eligible shell commands separated by 10–120 seconds, 18 of 20 intervals fall within 20 milliseconds of an integer number of seconds. In `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson`, lines 33/36/39 execute `pwd`, `ls`, and `du` at `13:48:48.728362`, `13:49:18.729299`, and `13:50:08.724928` UTC: intervals of 30.000937 and 49.995629 seconds. On MAC-MROSS-02, lines 115/118/121 execute `du`, `df`, and `ps` at `17:33:09.354077`, `17:33:57.356931`, and `17:34:45.358394`: 48.002854 and 48.001463 seconds. The shared fractional anchors across otherwise different command groups suggest scheduled command templates with small added jitter. Scripts or replay automation are a possible real-world explanation.
- [distribution_texture] Across 901 matched Security 4688/Sysmon 1 process creations in ten Windows hosts, Security `System/TimeCreated` is later in every match, with delays approximately 35–637 milliseconds. Each host has a median of approximately 120–154 milliseconds. Example: DC-01 Security XML event starting at line 556 timestamps PID `0xf24` (`3876`), `taskhostw.exe`, at `13:02:16.1194299Z`; Sysmon XML event starting at line 564 timestamps the same PID/image at `13:02:15.8782961Z`, 241.134 milliseconds earlier. Consistent ordering alone is not impossible, but the shared narrow timing shape across all hosts is suggestive. These are event creation timestamps, not explicit ingestion timestamps; a provider or export behavior could nevertheless explain part of the effect.

## Evidence For Real

- Windows Security and Sysmon XML parse successfully with their event namespaces and structured fields. The sampled 4624 v2 records include the version-specific outbound, linked-session, virtual-account, and elevated-token fields. Security 4688 v2 distinguishes creator and target security context; numeric PID representations differ appropriately between Security hexadecimal and Sysmon decimal.
- Security file-access events have usable lifecycle linkage. `FILE-SRV-01.meridianhcs.local/windows_event_security.xml`, events starting at lines 9711, 9760, and 9801, retain handle `0xc989ded5`, `aisha.johnson`, and logon ID `0xf6c1c4d` across 4656 request, 4663 access, and 4658 closure. The times progress from `14:15:16.3303824Z` through `14:15:16.6062553Z`.
- The checked Zeek protocol rows join their connection records with matching UIDs and full endpoint tuples, and fit their connection intervals. File byte counts do not exceed corresponding directional connection payload totals in the inspected files. For example, `zeek-core/smb_files.json` lines 1–2 and `files.json` line 1 share connection `CHobQaXTd62NpmDvAm`; file FUID `FHWi70ysEiFCvVUtLq` and size 5,359,834 bytes agree.
- The macOS data distinguishes native ES process observations from Unified Log messages and normalized endpoint telemetry. MAC-MROSS-01 ES lines 1–7 model launchd → xpcproxy → Terminal → login → zsh with stable PID identity across exec and changing PID versions, rather than falsely creating a fresh PID for each exec.
- `MAC-MROSS-01.meridianhcs.local/macos_unified_log.ndjson` line 3 records `sshd-session` accepting a public key at `16:02:23.591596+0000`; the ES shell exec at line 97 occurs at `16:02:23.747524000Z`. The acceptance precedes shell execution and the native writer is an SSH process, not a generic invented authentication source.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory. I parsed representative event shapes covering Security 4624, 4634, 4688, 4689, 4768, 4769, 4771, 5156, and file-access auditing; Sysmon 1, 3, 5, 10, and 22; Zeek DNS, HTTP, TLS, SMB, and files; macOS fork, exec, exit, and Unified Log; and example Linux syslog/eCAR rows. This exceeds twenty distinct representative shapes without trying to manually inspect every record.

I also performed lightweight aggregate consistency checks over the ten Windows Security/Sysmon pairs, both small ES exports, and the three Zeek sensor directories. These checks establish specific invariants, not full native schema certification. I did not consult external platform documentation or infer origin from filenames, domain sanitization, filesystem times, collection thinness, or narrative completeness.

### Shell timing texture

For each Mac, I selected ES exec records whose actor executable is `/bin/zsh`, excluding target executables `/bin/zsh`, `/usr/bin/ssh`, `/bin/cat`, and `/usr/bin/tee`. I compared adjacent selected exec timestamps and retained intervals from 10 through 120 seconds. MAC-MROSS-01 has 7/8 intervals within 0.020 seconds of an integer; MAC-MROSS-02 has 11/12.

Additional reproducible examples are MAC-MROSS-01 lines 12→15 (48.002884 seconds), 53→56 (52.002200), and 67→70 (44.005702); MAC-MROSS-02 lines 77→80 (36.999956), 89→92 (44.000066), and 130→133 (64.992240). This concerns the fine timing distribution, not the fact that discovery commands exist or form an understandable sequence. The parent is a shell in these records, so a script, macro, or command replay could produce the pattern. The data does not establish that automation independently, and both hosts share the same user, limiting independence of the observations.

The associated zsh histories agree at their coarser whole-second precision. That agreement is useful for correlation and is not itself a synthetic indicator.

### Windows source timing and lifecycle

I paired Security 4688 `NewProcessId` with Sysmon 1 `ProcessId` within the same host, converting the former from hexadecimal. Where necessary I selected the nearest timestamp and retained pairs less than five seconds apart. The resulting counts are: DC-01 132; DC-02 138; FILE-SRV-01 94; MAIL-FIN-01 92; WS-AJOHNSON-01 102; WS-DRAMIREZ-01 52; WS-EBROOKS-01 80; WS-MCHEN-01 97; WS-PPATEL-01 68; WS-SMARTINEZ-01 46. All 901 offsets have the same sign. The evidence is a repeated statistical shape, not proof that any individual pair is invalid.

Within Sysmon, no checked same-ProcessGuid observation preceded its visible create or followed its visible terminate. Security logoff checks found no demonstrated username or ordering contradiction among visible matching logons. I specifically did not count WS-MCHEN-01 Security line 4398, type-7 unlock for `0x6c2f76f`, followed by line 9683 type-2 logoff as a contradiction: unlocking an existing interactive session need not change the session's original type, and the initial interactive logon can precede collection.

### Network and native macOS semantics

The three Zeek connection files contain 21,463 distinct indexed UIDs in aggregate. The checked DNS, HTTP, TLS, and SMB rows had no missing connection UID, tuple disagreement, or protocol timestamp more than 50 milliseconds outside its connection interval. Checking files against directional connection bytes found no oversized file evidence. These bounded invariants do not establish complete packet-level accounting or validate every TLS certificate field.

The ES exports declare message `version: 11`; I did not penalize newer or unfamiliar version-specific fields without documentation. Native ES notifications are not treated as authorization decisions. In particular, MAC-MROSS-01's Unified Log policy message about MeetingAssist does not alone establish denied execution, and I did not infer an impossible child execution from it. Sparse Unified Log selection is neutral because the visible files do not claim a complete unfiltered system stream.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Native macOS ES shell executions | 18/20 eligible short intervals across two hosts | Main indicator: command groups retain fractional-second anchors to millisecond precision. Automation remains an alternative explanation. |
| distribution_texture | Windows Security/Sysmon process creation | 901 matches across ten hosts | Supporting indicator: universally positive, similarly bounded source offsets. No individual impossible ordering established. |

## Realism Score by Category

- **Field format accuracy:** 9 — Representative XML, JSON, identifiers, and event-specific fields are credible; this was not exhaustive vendor-schema certification.
- **Temporal patterns:** 6 — Lifecycles are coherent, but shell subsecond texture and repeated Windows source-offset shape are conspicuous.
- **Cross-source correlation:** 9 — Checked UID/tuple, file-size, session, and process relationships generally agree.
- **Behavioral realism:** 8 — Credible service, desktop, authentication, and shell behavior; command timing suggests templated automation.
- **Environmental consistency:** 8 — Source roles and native process representations are generally coherent in the sampled records.

## Recommendations

- If this were synthetic, give separately entered shell commands independent think-time distributions rather than preserving one fractional-second anchor across groups. If the activity represents a scheduled script or macro, retain the observable automation parent and invocation where that evidence falls within the selected collection.
- If this were synthetic, calibrate Security/Sysmon event timestamp relationships using representative native captures and the actual provider/export behavior. Preserve event creation and ingestion time as separate concepts; avoid imposing a similar fixed delay envelope across every host without a collection rationale.
- Preserve the coherent process identity, file-handle lifecycle, and network tuple/FUID relationships demonstrated here. No recommendation to add unselected sources or invent out-of-window session boundaries is warranted by these checks.
