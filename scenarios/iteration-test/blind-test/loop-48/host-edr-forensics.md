# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 70
**Synthetic-Confidence Score:** 38

## Executive Summary

The endpoint evidence is mostly production-like: process identities, parentage, privilege transitions, and visible session ordering survive broad consistency checks across Windows, Linux, and macOS. There are weak distributional tells in repeated Mac shell diagnostics and clustered Linux daily-maintenance startup, but I did not establish a hard contradiction that distinguishes a carefully constructed dataset from sanitized production telemetry.

## Evidence For Synthetic

- [weak_signal] The two Mac histories have a narrow, overlapping diagnostic vocabulary across six hours. `MAC-MROSS-01.meridianhcs.local/zsh_history/maya.ross.zsh_history` has 20 entries, including `id` three times, `sw_vers -productVersion` twice, and repeated `ls`, `find`, `df`, and `ps`; the second Mac's 19 entries reuse most of those exact commands. Examples are Mac 01 history lines 4–6 and 17–20, and Mac 02 lines 4–7 and 14–19. This resembles a small reusable activity pool, but the same named user operates both machines, so repeated habits and collection selection are strong alternative explanations. This is a modest texture concern, not a process-tree or lifecycle defect.
- [weak_signal] Ten of the eleven Linux syslog files contain exactly one five-message anacron run, all beginning within the first 28 minutes of the visible period. Examples: `PROXY-01.../syslog.log:6–15` starts at 13:03:39, `MAIL-EDGE-01.../syslog.log:13–37` at 13:06:26, and `MAIL-CLIN-01.../syslog.log:45–55` at 13:27:55. The scope-wide clustering at the leading edge is noticeable. A common maintenance policy or a collection window selected around that policy can explain it; the jobs' actual delays and completion times are coherent. I do not classify the regularity of scheduled jobs itself as an error.

## Evidence For Real

- Windows process creation is strongly coherent. Across all ten Windows hosts, 894 of 895 Sysmon Event 1 records have a Security 4688 candidate with the same process PID, image path, and parent PID; no contradictory matched pair was found. The single unmatched Sysmon creation is not scored as a coverage defect.
- Hash stability is good: grouping Sysmon process creations by host, image path, and reported version produced no group with multiple hash sets. Different hashes across different hosts were limited to a few paths with unspecified versions and are not a contradiction.
- A scan of all 35,805 eCAR records found no process creation after its explicitly identified parent's visible termination, no child creation before that parent's visible creation, and no actor activity more than two seconds after its visibly recorded termination. The scan used process object UUIDs rather than PID alone.
- Windows nonreserved logon IDs had no process creation demonstrably before their earliest visible 4624 or after their latest visible 4634 in the checks performed. Reserved SYSTEM/service logon IDs were excluded from this inference, because repeated observations of those IDs cannot be treated as unique fresh sessions.
- Linux privilege transitions have distinct caller and privileged child evidence. `MAIL-EDGE-01.../ecar.json:3–5` shows user `aisha.johnson` running sudo PID 1985795, root `iptables` child PID 1985796, then that child's termination; `syslog.log:2–4` carries the corresponding sudo command and PAM open/close.
- macOS evidence preserves fork versus exec semantics instead of treating each executable image as a new process lifetime. For example, Mac 02 ES lines 1–10 trace launchd, xpcproxy, iTerm2, its server, login, ShellLauncher, and zsh with same-PID exec transitions and separate fork children.
- macOS SSH evidence distinguishes bootstrap helpers, authentication, shell lifetime, and teardown. Mac 02 ES lines 47–73 show sshd bootstrap, sshd-session/auth children, a later shell, and ordered shell/helper/leader exits; the Unified Log authentication observation is at 14:24:44.399410, before the shell's exec at 14:24:44.513340.

## Detailed Analysis

### Inputs, provenance, and limits

Actual inputs read were the complete neutral `host-prompt.md`, an inventory strictly within `/private/tmp/log-study-gel6klid/data`, all 23 eCAR files, all ten Security XML files and ten Sysmon XML files, all eleven Linux syslog files, both Mac Endpoint Security files, both small Unified Log files, and the supplied bash/zsh history files. I used Python standard-library parsing, file-content searches, and targeted record inspection. No project files, scenarios, TODO/worklog files, prior assessments, or other reviewers' reports were accessed. No external references were used, and logged command strings were only read as inert text.

The inherited operating context is an environmental limitation, not evidence of data origin. This assessment rests on the supplied telemetry. The general dataset inventory contains network sources, but their record contents were not used in this host-focused review; therefore, the correlation findings below do not certify network-sensor semantics. I also do not claim exhaustive validation of the native macOS version-11 message schema.

There are 35,805 eCAR records, 19,030 Windows Security events, 11,785 Sysmon events, 283 Mac ES records, and six Unified Log records. XML line counts are not event counts. Source filtering, sanitization, and the finite collection window substantially limit conclusions from absence.

### Windows process, identity, and session evidence

The workstation material contains credible parent families and service/user separation. `WS-MCHEN-01.../windows_event_sysmon.xml:146` identifies PID 6852, SearchFilterHost.exe, with parent SearchIndexer.exe PID 6072, SYSTEM user, logon ID `0x3e7`, and system integrity. Its Event 1 time is 13:03:21.9551241; the corresponding Security 4688 at 13:03:22.0078938 identifies `NewProcessId=0x1ac4` (6852), parent `0x17b8` (6072), and the same images (`windows_event_security.xml:189` anchors the child PID). The roughly 53 ms source difference is plausible and is not an inverted process lifecycle.

User launches carry different identities and integrity. Priya Patel's ZSATray launch at 13:17:50 is an explorer.exe child with user logon ID `0xd8070f4`, a limited token, and medium integrity, rather than a SYSTEM service masquerading as an interactive application. The image appears in `WS-PPATEL-01.../windows_event_sysmon.xml:460`.

The broad PID/image/parent comparison found 894 matching process creations out of 895 Sysmon Event 1 records. I permitted source timestamps to differ and searched repeated PIDs using the nearest timestamp; I did not treat PID alone as a durable identity. Independent eCAR lifetime checking used object UUIDs. These results support internal coherence, although coherence alone cannot prove production origin.

The visible Security family includes process create/exit, interactive/network/service authentication, privilege assignments, workstation lock/unlock, file/share access, and administrative events. Its presence is credible for the roles implied by hostnames and actual records. I did not penalize deliberately selected Sysmon event coverage, missing pre-window process creation, or post-window logoff/termination.

### Linux privilege and maintenance lifecycles

MAIL-EDGE-01 provides an inspectable privilege chain: sudo creation at timestamp_ms 1793624423195, root iptables child creation at 1793624423398, and child termination at 1793624430301 (`ecar.json:3–5`). Its syslog records command admission at 13:00:23.238967, PAM opening at 13:00:23.402550, and closure at 13:00:30.303901 (`syslog.log:2–4`). The separate principal, process ownership, and closure timing are materially more convincing than merely repeating a command in several sources.

SSH authentication records reuse a user's public-key fingerprint across repeated sessions while varying session PIDs and source ports. For example, MAIL-EDGE-01 accepts Aisha's public key at 13:21:38 with PID 1988317, source 10.10.1.35:64221, and again at 15:31:07 with PID 2005791, port 53334 (`syslog.log:51,196`). The corresponding visible PAM closures occur at 14:00:48 and 16:06:10 (`:131,250`). These are differentiated session instances, not one PID impossibly reused within overlapping sessions.

The maintenance clustering remains weak evidence because the lifecycle itself is correct. MAIL-EDGE-01 schedules cron.daily five minutes after 13:06:26, starts it at 13:11:33, ends it at 13:14:06, and exits normally at 13:14:07. LOG-MON-01 has a distinct eleven-minute delay and a shorter job (`syslog.log:34–60`). Common deployment policies can yield similar jobs across many hosts. Likewise, repeated sysstat commands are normal scheduled telemetry and were not scored as a suspicious command pool.

Linux histories differ by role: Lina's workstation has git/npm activity; mail hosts have mail-service checks; DB-PROD has MySQL administration; and the monitoring host includes journal queries. A command being suspicious, linear, or easy to narrate was not used as an authenticity indicator.

### macOS process and authentication evidence

Mac 02 ES lines 1–3 show PID 19023 transitioning from forked launchd image to xpcproxy and then iTerm2. The pidversion advances across these exec images while the process start time remains anchored to the fork. Lines 4–10 then separate the iTerm server, login child, ShellLauncher, and login shell. That is a coherent distinction between executable identity and process lifetime.

A small command also aligns across representations. ES lines 11–13 fork PID 19027 from zsh, exec `/usr/bin/sw_vers -productVersion`, and exit. eCAR lines 22 and 24 retain object UUID `29052f35-c8ad-4dd3-84f7-19f130decfd1`, representing exec as MODIFY and later terminating the same lifetime; source publication times differ by several tenths of a second. This is compatible observation delay, not duplicate process creation.

The remote Mac session's helper exits precede the accepted-auth log but do not prove denial: they are separate helper processes, and the session leader persists. At 14:24:44.399410 Unified Log records accepted keyboard-interactive/PAM authentication for Maya from 10.10.1.41:49252. ES line 61 then execs the remote zsh under PID 30066 at 14:24:44.513340. Lines 71–73 terminate shell, intermediate session process, and session leader at 14:34:59.389845, .693690, and .997535 respectively. I found no contradiction in those visible transitions.

The small number of Unified Log rows and ES event-type selection are neutral collection facts. I did not demand unrelated policy, launch-item, file-write, or authorization records. Repeated Mac diagnostic commands are the weaker part of the behavioral texture, but both machines belong to the same visible user and share a plausible routine.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| weak_signal | Mac shell history / endpoint process activity | Two hosts, 39 history entries | Narrow repeated diagnostic vocabulary raises a modest texture concern; same-user operation is a strong explanation. |
| weak_signal | Linux syslog maintenance | Ten of eleven hosts | All visible anacron starts cluster within the first 28 minutes; common maintenance scheduling or window selection can explain this. |
| No demonstrated hard contradiction | Windows, Linux, Mac endpoint evidence | Checks described above | Prevents a high synthetic-confidence score; broad lifecycle coherence materially offsets the weak signals. |

## Realism Score by Category

- **Field format accuracy:** 8 — Windows/native and normalized endpoint fields are internally credible; full native macOS schema validation was outside this record-only check.
- **Temporal patterns:** 8 — Inspected process, sudo, SSH, and maintenance ordering is coherent; maintenance onset clustering is weakly suspicious.
- **Cross-source correlation:** 9 — Broad Windows creation matching and targeted Linux/Mac identity transitions agree; network-sensor correlation was not assessed here.
- **Behavioral realism:** 7 — Distinct administrative/developer/mail workflows are present, while Mac interactive diagnostics show a narrow repeated vocabulary.
- **Environmental consistency:** 8 — Source-specific OS roles and principal ownership are mostly credible, with no demonstrated impossible host-role relationship.

## Recommendations

- If this were synthetic, increase the variety of ordinary Mac shell activity only where consistent with the visible user's actual work; the repeated diagnostics in the two histories are the main behavioral texture weakness. Preserve same-PID fork/exec/lifetime relationships while doing so.
- If this were synthetic, make the reason for the cross-host maintenance onset coherent with the modeled collection period and scheduling policy. Avoid placing anacron near every collection start solely because a new output window begins; retain the observed realistic scheduling delays and job lifecycles.
- Preserve the demonstrated privilege, session, parentage, and executable-identity distinctions. The supplied evidence does not justify adding missing sources or out-of-window lifecycle records merely to make the dataset more complete.
