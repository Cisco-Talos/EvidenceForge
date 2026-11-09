# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 88
**Synthetic-Confidence Score:** 69

## Executive Summary

The endpoint evidence has convincing process identities, platform distinctions, session metadata and ordinary background activity. My synthetic verdict rests principally on reproducible timing patterns in otherwise unrelated endpoint actions: six Mac inventory processes have exactly identical fork-to-exit durations, the two Macs repeat the same inter-command cadence across different commands, and one Linux developer repeatedly changes editors at almost identical intervals. I did not find a demonstrated impossible process lifecycle or a dataset-wide schema failure; the score therefore remains in the “likely synthetic” band.

## Evidence For Synthetic

- [distribution_texture] All six Mac launchd inventory invocations terminate exactly **2.000000 seconds after fork**, despite different exec delays. In `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson`, fork/exit line pairs 28/31, 66/69 and 126/129 give `13:31:25.866513` → `13:31:27.866513`, `15:16:13.776833` → `15:16:15.776833`, and `17:38:38.057008` → `17:38:40.057008`. The corresponding pairs in MAC-MROSS-02 are 31/34, 94/97 and 135/138. These are `/usr/bin/sw_vers` launches through `xpcproxy com.meridianhcs.endpoint-inventory`, rather than an explicitly visible two-second sleep command.
- [distribution_texture] The two Macs repeat identical inter-command gaps while selecting different commands. Their zsh histories begin with three-command groups separated by **21 then 48 seconds**: MAC-MROSS-01 history lines 1–3 (`id`, `sw_vers`, `uname`) and MAC-MROSS-02 lines 1–3 (`sw_vers`, `uname`, `pwd`). Later groups share gaps of **30, 37, 44 and 51 seconds**, in that order across the day. Native ES fork timestamps retain the shared fractional-second anchors within these groups. The repetition extends beyond simply sharing an administrative command vocabulary.
- [distribution_texture] `WS-LNGUYEN-01.meridianhcs.local/ecar.json` repeatedly starts foreground editors at approximately 96-second spacing, changing among `vim`, `nano`, and `emacs -nw` on different projects. For example, lines 375, 388 and 391 start `emacs -nw .../server.go`, `vim .../Makefile`, and `nano .../index.js` at `17:02:01.629`, `17:03:37.865`, and `17:05:14.126`. Lines 399, 419, 436 and 472 then start `vim`, `emacs`, `vim`, and `code` at `17:13:43.574`, `17:15:19.305`, `17:16:55.093`, and `17:18:31.173`. The shell history independently contains the corresponding repeated 95–97-second intervals. This looks like timed activity slots with commands selected from an editor pool.

## Evidence For Real

- Process identities survive lifecycle checks. Across all 23 supplied `ecar.json` files, matching `actorID` references did not precede their visible PROCESS/CREATE or follow their matching visible PROCESS/TERMINATE. Processes without a visible initiating or terminating record were not treated as defects.
- Windows Security and Sysmon contain credible shared process truth. On WS-MCHEN-01, Sysmon Event 1 at `13:05:02.8117220Z` identifies SearchProtocolHost PID `7208`, parent PID `6072`/SearchIndexer; Security 4688 at `13:05:02.9873348Z` gives matching hexadecimal IDs `0x1c28` and `0x17b8` and the same detailed pipe command line. This is a substantive correlation rather than merely similar host naming.
- Repeated Sysmon binary paths retain their hashes. I found no same-host path with conflicting Event 1 hash sets, nor a shared hash associated with conflicting visible FileVersion values across hosts. Workstation and server binaries also carry distinct Windows version families, for example `10.0.22621.1` on WS-MCHEN-01 versus `10.0.20348.1` on DC-01.
- Native macOS records distinguish fork, successive exec images, and exit. MAC-MROSS-01 ES lines 1–7 show launchd → xpcproxy → Terminal, a child exec to `/usr/bin/login`, and another child exec to `/bin/zsh`. PID continuity across exec is preserved while `pidversion` changes. The second Mac uses an iTerm-specific lineage rather than copying the Terminal tree.
- Linux SSH evidence contains accepted authentication, PAM session opening and later closure with stable sshd PIDs. APP-INT-01 syslog lines 15–16 show lina.nguyen authenticated from `10.10.1.21:35355` at `13:03:47.566502Z`, then PAM session open at `13:03:47.732667Z`; line 73 closes that same PID `2931865` at `14:00:39.727029Z`.
- User and system evidence is differentiated. Lina's Linux workstation shows development work and SSH, while Windows hosts contain SearchIndexer children, Defender accesses, service principals, lock/unlock records, and domain authentication. Linux syslog also includes cron, resolver and package/service messages rather than only security events.

## Detailed Analysis

### Scope and method

I examined the supplied host sources only, reading actual records and performing identity/timing summaries over the endpoint files. The dataset includes 23 hosts with eCAR records, ten hosts with Windows Security/Sysmon XML, two with native macOS ES/Unified Log exports, and Linux syslog and shell histories. The visible period is approximately the six hours beginning `2026-11-02T13:00Z`.

For lifecycle checks I indexed each host's eCAR PROCESS/CREATE and PROCESS/TERMINATE by `objectID`, then checked records referencing that identity as `actorID`. This did not reveal a visible use-before-create or use-after-termination. It is a bounded check, not a claim that every possible semantic relationship was validated. I also checked Mac ES process identities by PID/pidversion and executable file identity by device/inode; repeated observations did not change executable path/start time for the same process image identity, or path/size/mtime for the same executable inode.

### Windows processes and sessions

The Windows material generally survives close inspection. SearchProtocolHost on WS-MCHEN-01 has matching user/security context, command line and parent identity between Sysmon and Security. Its different source timestamps are subsecond and do not themselves contradict creation ordering. Sysmon process launches include a useful long tail of service-hosted work, SSH clients, browser processes and tools rather than only conspicuous activity.

On the same workstation, the initial displayed service logon at `13:21:36.2564810Z` is NETWORK SERVICE (`S-1-5-20`), Type 5, LUID `0x3e4`, and services.exe caller. The following 4672 has that same LUID and service-appropriate privileges. Lock/unlock events at `14:55:27.3831936Z` and `15:05:50.8883813Z` retain marcus.chen's LUID `0x6c1c6a0` and SessionId `5`. These details are internally plausible.

Security 4648 on WS-MCHEN-01 at `14:14:01.4080780Z` distinguishes marcus.chen as subject and marcus.chen-admin as the explicitly supplied account, with powershell.exe PID `0x1d70`. I did not equate a caller identity with the credentials it supplied. Similarly, nonzero differences between Sysmon, Security and normalized eCAR observations were not automatically classified as clock defects.

I did not penalize omitted Sysmon event families or the absence of boot events: the study explicitly selects event types, and the systems may have booted before collection.

### macOS native evidence and timing texture

The Mac records are substantially more convincing than a generic Unix process export. They carry audit tokens, process start times, original/current parent concepts, code-signing information, file stat identities, and separate exec target structures. The visible Terminal lineage uses PID `42171` successively for launchd's forked image, xpcproxy and Terminal, with PID versions `10`, `11` and `12`. This is a sequence of exec images, not three independently created processes with an accidentally reused PID.

The strongest authenticity concern is the inventory timing:

| Host | Fork line / exit line | PID | Fork time (UTC) | Exit time (UTC) | Duration |
|---|---:|---:|---|---|---:|
| MAC-MROSS-01 | 28 / 31 | 44501 | 13:31:25.866513 | 13:31:27.866513 | 2.000000 s |
| MAC-MROSS-01 | 66 / 69 | 59635 | 15:16:13.776833 | 15:16:15.776833 | 2.000000 s |
| MAC-MROSS-01 | 126 / 129 | 73882 | 17:38:38.057008 | 17:38:40.057008 | 2.000000 s |
| MAC-MROSS-02 | 31 / 34 | 21921 | 13:43:12.852095 | 13:43:14.852095 | 2.000000 s |
| MAC-MROSS-02 | 94 / 97 | 44140 | 15:47:17.579489 | 15:47:19.579489 | 2.000000 s |
| MAC-MROSS-02 | 135 / 138 | 56599 | 17:52:26.343304 | 17:52:28.343304 | 2.000000 s |

All table references are to the respective `macos_endpoint_security.ndjson`. Exec transitions have varied delays: for PID 44501, sw_vers exec is at `13:31:25.873119`, whereas PID 59635 exec is at `15:16:13.785370`. Exit remains anchored exactly two seconds after fork, preserving six fractional decimal places each time. An inventory policy with fixed runtime could explain some regularity, but the observed executable is a short version-query tool, and ordinary scheduling/runtime variation would usually remain. I score this as a distribution artifact, not impossible behavior.

The shell cadence is a separate pattern. MAC-MROSS-01 ES lines 8/11/14 fork commands at `13:07:47.128964`, `13:08:08.611321` and `13:08:56.611321`; the history rounds these to gaps 21/48 seconds. Later pairs on MAC-MROSS-01 include `ifconfig`/`dscl` at `15:22:49.103240`/`15:23:33.103240` and `sw_vers`/`id` at `16:34:22.030570`/`16:35:13.030570`. MAC-MROSS-02 ES lines 88/91 and 105/108 have different commands but the same exact 44- and 51-second anchors. Both are attributed to their visible interactive zsh parents. Shared user habits or a sourced script are possible explanations; the patterned sequence across multiple groups, combined with the inventory durations, favors generated activity.

The Unified Log policy message for MeetingAssist on MAC-MROSS-01 at `15:42:28.922523` says security policy “would not allow” PID `62521`. I did not infer a successful malicious child or successful effects from this message. I found no basis here to turn a policy-related message into an execution contradiction. I likewise did not require Linux PAM/systemd events from either Mac.

### Linux behavior and distribution

Linux SSH/PAM timing, per-user UID values, varied command vocabulary, and role-specific workstation activity are mostly credible. Commands such as `systemctl status cifs-utils` or `systemctl show smbclient` could fail because those are not normally service units, but real administrators issue unsuccessful commands; without output, this is not a demonstrated synthetic defect.

The stronger issue is the developer activity's timing and editor selection. The repeated editor starts cited above all use the same visible parent shell PID `2950047`, with durations ranging from about 28 to 93 seconds. The durations vary, but new editing activity returns to the same approximately 96-second grid. For example, the later four starts are separated by 95.731, 95.788 and 96.080 seconds. This repeated cadence is observable independently of whether the work is benign or suspicious. The finding concerns a concrete distribution, not whether an intrusion is easy to narrate.

### Limits and alternative explanations

A production organization could run timed inventory commands and scripted shell routines, and the visible user may use several editors. Those possibilities keep the score below the hard-contradiction band. Conversely, source completeness, matching identifiers, sanitized names, and similar filesystem copy times were not used as synthetic indicators. Missing Mac exits or other companion source rows were not scored without a demonstrated source coverage requirement.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the score |
|---|---|---|---|
| distribution_texture | Native macOS ES | Six inventory process lifetimes on two hosts | Every fork-to-exit interval is exactly 2.000000 seconds despite varied exec delay; strongest isolated timing artifact. |
| distribution_texture | Mac shell histories and ES | Multiple command groups across both Macs | Different command choices repeat the same sequence of exact/intersecond gaps, suggesting shared activity scheduling. |
| distribution_texture | Linux eCAR and bash history | Lina's workstation editor activity | Repeated approximately 96-second launch grid plus rapid switching among several editors/project paths. |

These are three manifestations of timing/behavior texture, not three independent hard contradictions. I did not find a source-native impossibility sufficient to justify an 81–100 score.

## Realism Score by Category

- **Field format accuracy:** 9 — Structured XML/JSON, Windows principals and process metadata, and Mac audit/exec distinctions are generally credible.
- **Temporal patterns:** 5 — Good lifecycle ordering coexists with exact repeated Mac durations and shared command cadences.
- **Cross-source correlation:** 9 — Sampled Security/Sysmon/eCAR identities agree, and automated endpoint identity checks found no visible lifecycle inversion.
- **Behavioral realism:** 6 — Broad role-specific work and system activity, weakened by timed editor-pool behavior and repeated shell routines.
- **Environmental consistency:** 8 — Distinct workstation/server Windows builds and separate Linux/Mac process/session semantics; no demonstrated platform contamination.

## Recommendations

- If this were synthetic, derive inventory process exit from its actual exec/runtime semantics and introduce plausible runtime variation; avoid assigning every instance an exact two-second lifetime from fork.
- If this were synthetic, give the two Macs independent command timing unless a specific shared automation explains the repeated cadence. Preserve real dependencies while varying human think time and routine composition.
- If this were synthetic, model a developer's stable editor preferences and task-driven editing sessions. Replace the repeated 96-second editor-start grid with durations tied to each task and interaction rather than command-pool slots.
- Retain the current shared process identities, hash consistency, platform-specific lineage and session semantics; these materially improve endpoint plausibility.
