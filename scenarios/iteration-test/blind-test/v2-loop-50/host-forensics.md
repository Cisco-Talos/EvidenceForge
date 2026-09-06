# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 82  
**Synthetic-Confidence Score:** 74

## Executive Summary

The corpus is technically strong in many areas: Windows process identifiers and hashes are coherent, visible process and session ordering is generally sound, and Linux SSH/PAM/logind sequences resemble operational telemetry. I nevertheless assess it as synthetic because the endpoint evidence contains a severe singleton-service lifecycle contradiction on the Exchange host, repeated source-native path escaping artifacts, and target-host eCAR records that carry remote Linux process identity without an explicit remote-host boundary.

## Evidence For Synthetic

- **P0 — [hard_contradiction] Concurrent singleton Exchange service instances.** `MAIL-FIN-01.meridianhcs.local/ecar.json` creates repeated `EdgeTransport.exe` children of the same `services.exe` process without retiring earlier instances. At 2024-03-18 17:06:37.408Z, nine visibly created `EdgeTransport.exe` instances were simultaneously unclosed; examples include PID 4076/object `aa02e2e6-e914-4aca-90a1-9ca831f4fd22` at 13:24:07.385Z (line 228), PID 4316/object `4efc1c80-912c-4053-9360-c971c0b26326` at 14:47:48.751Z (line 465), PID 4480/object `aab661b6-e2e3-4fd5-99f2-b5573b951e28` at 15:48:21.176Z (line 650), PID 4780/object `4048a510-20ff-4a9c-b63b-a8dc7b0e2970` at 16:03:57.681Z (line 670), and PID 5012/object `c0c596fb-75d5-41b3-8c9b-ee2aff35dd3e` at 17:06:37.408Z (line 804). The same analysis found seven simultaneously unclosed `Microsoft.Exchange.Imap4.exe` service processes by 17:09:00.209Z. Brief recycle overlap is believable; hours of accumulated singleton service instances are not.
- **P1 — [schema_or_format] Literal doubled backslashes in native Windows command lines.** Twenty-five of 26 Exchange process-creation command lines in both `MAIL-FIN-01.meridianhcs.local/windows_event_sysmon.xml` and `windows_event_security.xml` contain literal paths such as `"C:\\Program Files\\Microsoft\\Exchange Server\\V15\\Bin\\EdgeTransport.exe" -service`, while the adjacent `Image`/`NewProcessName` uses the native single-backslash path. Concrete Sysmon examples occur at lines 3653, 3729, 3997, and 4281; line 3133 contains the correctly formed single-backslash variant. The inconsistent escaping of the same service image is a rendering fingerprint, not normal source variation.
- **P1 — [contract_gap] Target-host eCAR records expose remote Linux process identity as if it were local endpoint provenance.** `DC-01.meridianhcs.local/ecar.json:1461` is a `FILE READ` on a Windows SYSVOL path but reports `src_pid=1473685` and `source_image_path=/usr/bin/smbclient`; `FILE-SRV-01.meridianhcs.local/ecar.json:529` similarly records a write to `C:\Mounts\Archive\...snapshot-draft.vhdx` with Linux PID 3387298 and `/usr/bin/smbclient`. Equivalent examples occur on DC-01 lines 4759 and 4792, DC-02 lines 2717/2885/4512, and FILE-SRV-01 lines 1044/1066/1308/1399. Because these target-host records have no explicit `source_hostname` or remote-process namespace, an analyst cannot distinguish a remote client process from an impossible local Linux process on Windows.
- **P2 — [distribution_texture] Foreground terminal processes accumulate and drain as a synthetic-looking batch.** On `WS-AJOHNSON-01`, ten concurrent `powershell.exe` instances were visible by 17:48:47.918Z. Five argument-less terminal processes alone remained alive for 3,572–6,468 seconds and then terminated within 180 ms at 17:54:58.183–17:54:58.363Z: PowerShell objects `6ca2cf18-...` (create line 808, terminate line 1358), `32bf72d4-...` (895/1368), `bb48a3f2-...` (1040/1370), `e194f4c8-...` (1057/1371), and `cmd.exe` object `81a2362f-...` (1021/1369). A user can leave shells open until logoff, but the volume, repeated argument-less command lines, long survival, and tightly serialized finalization form an overly strong session-drain texture.
- **P3 — [weak_signal] Cross-source process-create latency is globally one-sided and tightly bounded.** Across ten Windows hosts, all 926 Sysmon Event 1 records matched Security 4688 by PID and image within ten seconds; every matched Sysmon timestamp preceded Security by approximately 35–650 ms, with per-host medians clustered around 119–164 ms. This is operationally possible, and complete matching was not treated as suspicious, but the universal ordering and shared envelope across unrelated hosts look more like a fixed projection-delay model than independent source timing.

## Evidence For Real

- The six-hour corpus contains a plausible mix of Windows servers, workstations, Linux servers/workstations, and role-specific endpoint volume rather than one repeated host template.
- Across 926 Sysmon Event 1 records, process fields are structurally complete and usable: `ProcessGuid`, parent identity, user, integrity, hashes, current directory, and command line are populated. Security 4688 correlation is excellent without visible PID/image disagreement in the matched population.
- Visible process causality is strong. I found no Sysmon child whose visible parent `ProcessGuid` was created later, no termination preceding the visible creation of the same `ProcessGuid`, and no overlapping reuse of the same PID in eCAR.
- Hash behavior is internally coherent. Repeated executions of the same path on one host retain the same SHA1/MD5/SHA256/IMPHASH values, while some system binaries vary across host groups in a way compatible with different Windows builds.
- Process trees include credible chains: `winlogon.exe` → `userinit.exe` → `explorer.exe`; `explorer.exe`/terminal → `ssh.exe`; `services.exe` → service binaries; `WmiPrvSE.exe` → administrative `cmd.exe`; and `cmd.exe` → `net.exe`, `sc.exe`, or `schtasks.exe`.
- Windows logons show a useful mixture of types 2, 3, 5, 7, 9, and 10. Built-in service identities use expected authentication IDs (`0x3e4`, `0x3e5`, `0x3e7`), network sessions carry plausible NTLM/Kerberos details, and I did not treat pre-window sessions or post-window continuations as defects.
- The DC-01 Security `EventRecordID` reset is supported by a native Event 1102 at 2024-03-18T17:41:59.2606262Z with record ID 1, followed by new records 4, 5, and 6. This is a convincing audit-log-clear sequence rather than an unexplained counter reset.
- Linux SSH evidence is persuasive. For example, `DB-PROD-01.meridianhcs.local/syslog.log:120-127` records connection, accepted public key, PAM open, and logind session creation for Marcus Chen and Aisha Johnson; lines 133-142 later show coherent close/removal and overlapping-session behavior. Public-key fingerprints remain stable per user, while source ports and session identifiers vary.
- Bash histories contain per-user and per-host command variation, irregular pauses, routine administration, and role-aware tools. Exact repeats are mostly ordinary commands such as `whoami`, `df -h`, and `last -20`, not long duplicated scripts.

## Detailed Analysis

### Scope and sampling

I examined only files beneath the supplied `data` directory. The visible interval is approximately 2024-03-18 12:00–18:00 UTC. Host-focused sources include eCAR on 19 hosts, Security XML and Sysmon XML on ten Windows hosts, syslog and bash history on Linux systems, plus limited use of endpoint flow fields for ownership checks. I parsed all Windows XML event headers and EventData, all eCAR JSON records, all bash histories, and sampled syslog authentication/lifecycle records.

### Windows process trees and lifecycle

The Windows corpus contains 926 Sysmon process creations and 781 Sysmon process terminations. Normal bounded-window asymmetry is present, so unmatched starts or stops were not counted as defects. Within visible paired identities, I found no termination-before-create ordering and no child whose visible parent began later. Security/Sysmon PID and image agreement was unusually strong: 926 matches and four additional Security 4688 records without a Sysmon Event 1 counterpart.

The dominant process relationships are generally credible. Domain controllers show `csrss.exe` → `conhost.exe`, `svchost.exe` → `WmiPrvSE.exe`/`dllhost.exe`/`taskhostw.exe`, and visible administrative chains through WMI. Workstations show recognizably different user activity: Marcus Chen uses VS Code, Sublime Text, Postman, SQL clients, and administrative shells; Aisha Johnson uses PowerShell, MMC snap-ins, SSH, and remote administration; Priya Patel and Sophia Martinez show office, browser, conferencing, and collaboration applications.

The exception is `MAIL-FIN-01`. The repeated direct children of one `services.exe` PID are not ordinary multi-process browser or provider-host behavior. At least five `EdgeTransport.exe` processes overlap for substantial periods beginning between 13:08 and 13:44 UTC, and the later accumulation reaches nine. IMAP4 follows the same pattern. The recurrence in eCAR, Security 4688/4689, and Sysmon 1/5 means this is not merely one malformed row.

### Windows source-native formatting

Sysmon event shapes are otherwise credible. Event IDs 1, 3, 5, 7, 8, 10, 11, 13, and 22 carry the expected families of fields, timestamps use appropriate source-specific precision, and Security events use normal hexadecimal process/logon identifiers. The Exchange command-line escaping is therefore conspicuous: the XML text contains doubled separators even though XML does not require backslash escaping, and the corresponding image field is correctly normalized. This affects both Security and Sysmon, indicating a shared upstream value rather than a single-emitter typo.

### Logon and system lifecycle

Security logons are varied and mostly coherent. Network logons usually close within seconds to about a minute, with a few long SMB/Kerberos sessions that are plausible. Interactive and remote-interactive sessions last from roughly 50 minutes to several hours. Lock/unlock evidence exists on selected workstations. I observed a few logoffs whose login was outside the window; these were not treated as causality defects.

DC-01's audit-log clearing sequence is especially convincing. A visible `wevtutil cl Security` process precedes Event 1102, the Security record counter resets, and subsequent records continue monotonically. This is the kind of source-native consequence that supports authenticity.

### Linux endpoint evidence

Syslog shows credible facility/severity values, stable daemon PIDs, irregular background service messages, sudo command/open/close triplets, failed SSH pre-auth sequences, and successful SSH sessions with PAM and logind lifecycle. Session IDs increase with gaps compatible with uncollected activity. Bash-history timestamps are irregular rather than fixed-interval, and command selections differ meaningfully among users and hosts.

The main Linux-related defect appears at the eCAR boundary, not in syslog. Linux `smbclient` identity is inserted into records stored under Windows target hosts without a source-host field. Enrichment can legitimately preserve a remote actor, but a normalized endpoint schema must namespace that actor explicitly; otherwise fields named `src_pid` and `source_process_uuid` imply impossible local ownership.

### eCAR identity and timing

eCAR process UUIDs are stable across create, dependent activity, and terminate records, and visible actor creation never followed its dependent event in my checks. PID reuse was also lifecycle-safe. File identifiers use mixed morphology (UUIDs, `file-<uuid>`, and 16-hex `file-00000000xxxxxxxx` values), which looks generated but was not scored independently because opaque object identifiers can legitimately vary by event family.

The terminal accumulation on `WS-AJOHNSON-01` is less convincing. Individual long-running shells and SSH clients are reasonable, but ten concurrent PowerShell processes and a dense batch of shell/SSH teardown events at one session boundary create a repeated lifecycle texture rarely seen at this concentration in a six-hour endpoint slice.

## Synthetic Indicator Summary

| Priority | Category | Source family | Scope | Score effect |
|---|---|---|---|---|
| P0 | `hard_contradiction` | MAIL-FIN eCAR, Security, Sysmon | Repeated; one host, two Exchange service families | Nine concurrent `EdgeTransport.exe` and seven concurrent IMAP4 service instances create an immediate endpoint-lifecycle disbelief anchor. |
| P1 | `schema_or_format` | MAIL-FIN Security/Sysmon/eCAR | Repeated; 25 of 26 Exchange starts | Literal doubled path separators vary between executions of the same service and leak escaped configuration text into native logs. |
| P1 | `contract_gap` | Windows-target eCAR file events | Repeated across DC-01, DC-02, FILE-SRV-01 | Remote Linux PIDs/images are presented without an explicit remote-host namespace on Windows endpoint records. |
| P2 | `distribution_texture` | WS-AJOHNSON eCAR/Sysmon/Security | Repeated; concentrated on one workstation | Ten concurrent PowerShell processes and tightly batched terminal finalization overstate session-drain regularity. |
| P3 | `weak_signal` | Security 4688 vs. Sysmon 1 | Dataset-wide | A universal one-sided 35–650 ms projection envelope is plausible but overly uniform across ten hosts. |

No separate P0 was assigned to bounded-window missing initiators/terminators, high correlation completeness, sparse source families, or the audit-record reset; the visible evidence does not support those as defects.

## Realism Score by Category

- **Field format accuracy:** 6/10 — Most Security/Sysmon fields are strong, but repeated literal path escaping and ambiguous cross-host eCAR process fields are material defects.
- **Temporal patterns:** 7/10 — General ordering and Linux session timing are convincing; Exchange accumulation and batched workstation teardown are not.
- **Cross-source correlation:** 9/10 — Process, PID, image, session, and audit-clear relationships align with no sampled impossible visible ordering.
- **Behavioral realism:** 7/10 — User/tool differentiation is good, but some foreground-shell and service-process populations accumulate unnaturally.
- **Environmental consistency:** 6/10 — Host roles are recognizable, while the Exchange service population and unnamespaced Linux-on-Windows eCAR provenance undermine the environment model.

## Recommendations

- **P0:** If this were synthetic, model Exchange Transport and IMAP4 as singleton service lifecycles. A replacement/recycle start should require a prior stop or a short, explicitly bounded overlap; active instances must be tracked by service identity, not merely image name.
- **P1:** Normalize Windows command lines once before projection. Preserve one native backslash in XML text and JSON values, and add a cross-source assertion that `Image`, `NewProcessName`, and the executable token in `CommandLine` resolve to the same path representation.
- **P1:** Namespace remote SMB actor identity explicitly in target-host eCAR records. Add fields such as `source_hostname`/`source_os` and separate client-process context from local server-process ownership; do not overload local-looking `src_pid` and `source_process_uuid` fields.
- **P2:** Give interactive shells and one-shot terminal launchers behavior-aware lifetimes. Retain genuinely interactive shells when they own a live child or terminal, but reduce accumulation and avoid draining many long-lived shells in a millisecond-scale serialized batch.
- **P3:** Add host- and source-specific variation to Security/Sysmon observation latency while preserving causal bounds. This is low priority because the current ordering is valid and useful.
