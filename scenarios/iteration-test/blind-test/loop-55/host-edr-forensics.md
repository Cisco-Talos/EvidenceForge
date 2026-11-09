# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 90
**Synthetic-Confidence Score:** 79

## Executive Summary

Most endpoint evidence is convincing: Windows process identities, binary hashes, user sessions, Linux authentication, and macOS fork/exec distinctions generally hold together. The strongest contrary evidence is localized to MAC-MROSS-02: newly allocated macOS audit-token identity versions repeatedly run backward despite increasing native event time and process start time, accompanied by seven exactly 1-millisecond shell-child handoffs. These are concrete native identity/timing defects rather than a judgment about how narratable the activity is.

## Evidence For Synthetic

- **[hard_contradiction] Newly allocated macOS process identity versions contradict their creation chronology.** In `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson`, line 2 reports exec target PID 19775 with `pidversion=32` at `13:20:29.882486`; line 3 reports a newly forked PID 21356 with `pidversion=10` at `13:37:11.846603`. The latter child's `start_time` is also `13:37:11.846603`, so this is not an old process merely observed later. A second, independent example is line 80: PID 41975 exec target version 89 at `15:25:40.511790`, followed by lines 81–83 allocating PID 44085 versions 83–85 at `15:46:42.616461`–`.628448`. There are eight adjacent decreases among 124 fork-child/exec-target allocation observations. This finding assumes `audit_token.pidversion` retains its native meaning; undisclosed anonymization of this field could explain it.
- **[distribution_texture] Repeated exact microsecond-scale handoff spacing.** On the same host, seven child exits are followed by a sibling fork from the same shell exactly 1,000 microseconds later. Examples: lines 18–19, `13:37:33.139751` → `.140751`; lines 21–22, `.437983` → `.438983`; lines 85–86, `15:48:46.207061` → `.208061`; lines 88–89, `.458920` → `.459920`. The other pairs are lines 24–25, 94–95, and 97–98. This repeated exact offset in otherwise microsecond-resolution native timestamps suggests a deterministic serialization boundary. It is supporting evidence, not an impossible event relationship by itself.

## Evidence For Real

- Windows process names, creator identities, PID representations, and command lines agree in spot checks. `WS-MCHEN-01.meridianhcs.local/windows_event_sysmon.xml:65` has SearchProtocolHost PID 6792, parent SearchIndexer PID 6072, SYSTEM identity, and a Search indexing command. `windows_event_security.xml:85` has the same new PID as `0x1a88` and creator as `0x17b8`; `ecar.json:4` has the matching process and parent. Distinct observation timestamps are plausible source latency.
- Across all 1,001 Sysmon Event 1 records, grouping by host, image path, and file version found no multiple `Hashes` values within a group. This avoids a common synthetic defect where one unchanged binary receives a new hash on every launch.
- Visible Windows logons include interactive, network, service, remote interactive, unlock, and new-credentials activity. On WS-MCHEN-01, Security XML line 2010 records a Type 2 logon for `marcus.chen`, `TargetLogonId=0x6c75d51`; line 22669 records a Type 7 unlock for that same user and session. Reuse here is meaningful session continuity, not an identifier collision.
- macOS process history distinguishes a process lifetime from successive executable images. MAC-MROSS-01 ES lines 1–7 show launchd → xpcproxy → Terminal, followed by login and zsh. MAC-MROSS-02 ES lines 3–12 separately represent iTerm2, iTermServer, login, ShellLauncher, and zsh, including effective-UID transitions and retained process start times.
- macOS SSH evidence is platform-specific. On MAC-MROSS-02, ES lines 50–64 show launchd/xpcproxy, sshd-keygen-wrapper, sshd, sshd-session/auth, and an authenticated user's shell. Unified Log line 2 records acceptance for `maya.ross` at `14:25:06.970536`, before that shell's exec at `14:25:07.171515`; no Linux PAM/systemd requirement was imposed on this Mac.
- Linux records contain coherent source-native sequences. `APP-INT-01.meridianhcs.local/syslog.log:4–5` records public-key acceptance then PAM session opening for `aisha.johnson` with the same sshd PID 2931388. `DB-PROD-01.meridianhcs.local/syslog.log:3–4` records a sudo command followed by its PAM opening with PID 1043736. Cron, service maintenance, and different users' command histories add credible background behavior.

## Detailed Analysis

### Inputs, provenance, and qualifications

This is an AI analysis performed through the requested Host/EDR analyst lens, not a claim to human casework experience, professional certification, or direct access to the organization's systems. I read the supplied neutral `host-prompt.md`, enumerated only its `data/` directory, and used system `python3` from `/private/tmp/log-study-6dyv3d6d` for read-only parsing. I did not read project files, scenario material, TODO/worklogs, previous assessments, or other reviewers' reports. Inherited generic operating instructions were treated as an environment limitation and supplied no authenticity evidence. Logged command lines were treated only as inert data.

The parsed host-source scope included 19,411 Security events, 12,058 Sysmon events, 37,394 eCAR rows, 4,291 Linux syslog lines, all 299 macOS ES rows, the five macOS Unified Log records, and shell-history samples. Network families were inventoried but were not the principal basis of this endpoint review. The time slice and source-selection limitations in the briefing were retained throughout.

Public reference access was restricted to Apple Developer documentation using an actual `developer.apple.com` search-domain filter and direct Apple upstream XNU URLs. No task-project public pages or snippets were accessed. Those references were used to verify source semantics, not infer dataset origin.

### Native macOS identity chronology

The version decreases concern **newly assigned target/child tokens**, not repeated observations of older actors or parents. Old processes can naturally carry smaller versions indefinitely; that is not the finding. Apple's XNU fork path assigns `p_idversion` from the shared `nextpidversion` counter, and the exec path increments the same counter when changing identity. [Apple XNU fork implementation](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/kern/kern_fork.c), [Apple XNU exec implementation](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/kern/kern_exec.c).

The logs' `mach_time` also advances across the first example: 56016717179664 at ES line 2, then 56040764318472 at line 3. The second example likewise advances from 56196972282960 at line 80 to 56227262795064 at line 81. Thus wall-clock adjustment or sorting by collector delivery does not explain the contradiction. The same launchd actor remains visible, and the records contain neither a boot reset explanation nor a high-to-low integer wrap. Eight decreases in values below 134 within this six-hour slice are inconsistent with ordinary native counter allocation. MAC-MROSS-01 supplies a useful internal comparison: none of its 82 new child/target observations decreases.

A qualification matters: the exact macOS release/build and export/anonymization contract are not supplied. I checked current Apple upstream behavior, not a matched kernel binary. If native audit-token fields were deliberately renumbered in a non-order-preserving sanitization pass, this finding would instead diagnose transformation artifacts. That possibility is why the overall score stays below the highest band despite strong evidence.

### Timing texture

The seven exact 1-millisecond gaps occur in two clusters, not uniformly throughout every process lifetime. There are also ordinary varied fork-to-exec gaps and command durations. A script or queued shell input can explain rapid execution of multiple commands, but it does not readily explain seven exactly equal exit-to-next-fork offsets to the microsecond. I assign this moderate weight separately from the identity-version defect, without treating command sequence completeness or absence of mistakes as evidence.

### Windows process and session checks

I parsed every Windows XML event and inspected Event 1 process/parent GUIDs, Event 5 closures, hashes, and Security session fields. A broad screening pass found no Sysmon same-GUID activity more than 0.5 seconds before its visible creation or after its visible termination, and no child creation more than 0.5 seconds after a visible termination of its recorded parent GUID. This is a bounded consistency check, not proof that every process relationship is correct.

System processes and application behavior differ by host. Domain controllers emphasize service-host children such as taskhostw, WmiPrvSE, dllhost, and console hosts; administrative workstations show PowerShell, SSH, management consoles, and RDP clients; other workstations show Office, browsers, indexer workers, and software maintenance. Existing parent processes without in-window creation records were not penalized. Reserved system logon IDs and unlocks of existing user sessions were not treated as newly allocated sessions.

### macOS interpretation safeguards

The ES exports declare message `version=11`; I did not apply an older JSON schema or claim that exec entitlements were intrinsically invalid. Apple documents an accessor for exec entitlements. [Apple exec-entitlements API](https://developer.apple.com/documentation/endpointsecurity/es_exec_entitlements(_:)). Notifications, exec targets, audit session IDs, POSIX session IDs, parent audit tokens, and responsible processes were interpreted separately.

MAC-MROSS-01 Unified Log line 2 at `15:41:38.930666` states that security policy would not allow PID 62451, `/Applications/MeetingAssist.app/Contents/MacOS/MeetingAssist`. I found no matching successful ES exec for that PID and did not infer successful child execution from the warning. Conversely, I did not demand an authorization-denial ES event merely because this kernel policy message exists. Sparse Unified Log coverage alone was neutral.

### Linux and normalized EDR limitations

Linux histories contain both interactive administrative work and service-specific diagnostics rather than only one generic command vocabulary. Authentication and sudo samples have plausible PID ownership and event ordering. Some command choices and durations could merit operational investigation, but I did not promote them to authenticity defects without demonstrated effects or required companions.

The eCAR lifecycle screen found no actor event more than 0.5 seconds outside its visible process lifetime. macOS eCAR also distinguishes fork CREATE from successive exec MODIFY records, so repeated images under one PID were not mistaken for duplicate process creation. Very complete alignment among sources was treated as favorable correlation evidence and an allowed collection assumption.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| hard_contradiction | macOS Endpoint Security native identity fields | MAC-MROSS-02; eight decreases among 124 newly allocated child/target observations | Primary basis: creation time, monotonic time, and native identity-counter allocation disagree. Subject to an undisclosed token-renumbering/export explanation. |
| distribution_texture | macOS Endpoint Security timing | MAC-MROSS-02; seven exact 1,000-microsecond exit-to-sibling-fork gaps | Moderate supporting evidence of deterministic scheduling texture; ordinary shell queuing alone is insufficient to establish a defect. |

## Realism Score by Category

- **Field format accuracy:** 8 — Most Windows, Linux, ES, and Unified Log fields are credible, with native identity-version semantics the main exception.
- **Temporal patterns:** 6 — Broadly plausible lifetimes and ordering, weakened by identity chronology and repeated exact handoff gaps on one Mac.
- **Cross-source correlation:** 9 — Process identities, hashes, native/normalized process images, and authentication samples generally agree.
- **Behavioral realism:** 8 — Host-dependent applications, administrative commands, routine activity, and meaningful session reuse are credible.
- **Environmental consistency:** 9 — Platform-specific evidence and roles are largely coherent; no penalty for intentionally absent sources or out-of-window lifecycle events.

## Recommendations

- If synthetic, allocate macOS audit-token identity versions in the final event chronology across the host's shared fork/exec stream, and preserve those assigned tokens in every later snapshot. Recheck the concrete line 2→3 and line 80→81 examples and all eight regressions after any timing adjustments. If these are sanitized real records instead, document the non-native token mapping so consumers know which native invariants no longer apply.
- If synthetic, replace the seven exact 1-millisecond shell handoff boundaries with timing derived from the actual modeled shell wait/wakeup and dispatch sequence. Preserve the existing distinctions between fork, exec, privilege change, and process lifetime; those parts are persuasive.
