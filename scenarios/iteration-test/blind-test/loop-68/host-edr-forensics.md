# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 80
**Synthetic-Confidence Score:** 46

## Executive Summary

The endpoint data has credible process identities, operating-system distinctions, and visible session lifecycles; I did not establish an impossible same-identity process ordering. Some document-access ownership and repeated interactive command vocabulary look modeled, but these are distribution and behavioral concerns, not decisive native-format contradictions. The evidence supports a mixed assessment rather than a confident synthetic or real verdict.

## Evidence For Synthetic

- [distribution_texture] On `MAC-MROSS-02.meridianhcs.local/ecar.json`, all nine READ/WRITE observations of `.pdf`, `.docx`, or `.xlsx` files use command-line utilities: eight `/bin/cat` reads and one `/usr/bin/tee` write. Examples are lines 65 (`/Volumes/ClinicalResearch/Team/2026/project-plan.pdf`), 301 (`.../service-review.xlsx`), 365 and 371 (`.../project-plan.docx` and `.../onboarding.docx`), and 481 (`tee .../draft.docx`). The corresponding ES exec records include lines 108, 118, 121, and 157. Reading binary office documents this way is possible, but its dominance across this host's visible document operations suggests a generic file-access behavior model. This is not evidence that the commands could not execute.
- [environment_or_collection_plausibility] Several Windows document operations are attributed to generic shell/broker processes rather than document applications. `WS-DRAMIREZ-01.meridianhcs.local/ecar.json:1` attributes a WRITE to `...\Temp\~$document-57161.docx` to `RuntimeBroker.exe`; line 721 attributes a READ of `...\Documents\report.docx` to the same image family. `WS-EBROOKS-01.../ecar.json:645` attributes a WRITE of `Q4-review.pdf` to `RuntimeBroker.exe`, and line 827 a READ of `~$document-98026.docx` to it. The recurrence across users and machines raises an ownership-realism concern, especially for Office-style temporary filenames. Brokered file access, shell previews, or normalized collector attribution could explain individual instances, so this is not a hard contradiction.
- [distribution_texture] The two Mac interactive histories repeatedly cycle through a compact inventory/status vocabulary. `MAC-MROSS-01.../zsh_history/maya.ross.zsh_history:1-6,9-13,15-17,19-22` repeatedly uses `id`, `sw_vers`, `uname`, `pwd`, `ls`, `du`, `df`, `ps`, and `find`; the second Mac repeats much the same pool at history lines 1-5,7-10,12-19. The commands are valid and routine troubleshooting could explain them, but repetition across both machines contributes modestly to the appearance of templated user behavior. This finding concerns the visible command distribution, not how narratable the activity is.

## Evidence For Real

- Windows executable metadata distinguishes server and workstation builds. DC-01 and DC-02 process creations identify core Windows binaries as `10.0.20348.1`, while WS-MCHEN uses `10.0.22621.1` for its corresponding core processes. Hashes were stable for the same image within each host; I also found no identical full hash set carrying conflicting FileVersion values across the parsed process-create records.
- Visible Windows process lifetimes were coherent. Across the ten supplied Sysmon files, my GUID-based checks found no child created before its visible parent creation, no child created after its visible parent's termination, and no checked ProcessGuid/SourceProcessGUID/TargetProcessGUID observation outside its visibly established lifetime. These checks do not prove complete coverage, but they avoid several common endpoint inconsistencies.
- Mac Endpoint Security records distinguish fork from successive exec images. On MAC-MROSS-01, ES lines 1-7 show launchd fork, xpcproxy, Terminal, login, and zsh with stable lifetime PIDs and changing pidversion values. MAC-MROSS-02 ES lines 1-10 show a distinct iTerm2 → iTermServer → login → ShellLauncher → zsh path rather than copying the Terminal tree.
- Linux SSH evidence includes actual authentication and session phases. `DB-PROD-01.../syslog.log:99-102` records connection, password acceptance, PAM opening, and logind session creation for `maya.ross`, source `10.10.1.42:54165`, between 14:48:07 and 14:48:18 UTC. Lines 125-126 close PAM and remove the same logind session at 15:31:30-31.
- The Windows workstation evidence includes unlock semantics rather than treating every login as a fresh desktop session. For example, WS-MCHEN Security contains Type 2, Type 3, Type 5, Type 7, and Type 9 logons, along with 4800/4801; WS-AJOHNSON additionally includes remote interactive sessions and reconnect/disconnect events.
- Source timestamps are not mechanically identical. For WS-MCHEN PID 6852, Sysmon Event 1 has `UtcTime=2026-11-02 13:04:53.587`, Security 4688 records 13:04:53.7158462Z, and eCAR records 13:04:53.707Z. The image, parent PID, and command agree while source observation times differ.

## Detailed Analysis

### Scope and provenance

I read the supplied neutral briefing and raw files under `/private/tmp/log-study-kg97anv_/data` only, using system Python with `/private/tmp` as the explicit working directory. I did not inspect repository files, scenario definitions, prior assessments, or other reviewers' reports, and used no external lookup. File references below are relative to the supplied data directory; line numbers are one-based physical lines.

The endpoint collection spans approximately 13:00-19:00 UTC on 2026-11-02 and contains Windows Security/Sysmon XML, Linux syslog and bash histories, normalized eCAR, and two Macs' ES/Unified Log exports and zsh histories. I parsed all endpoint eCAR files, all ten Windows Security and Sysmon files, and both Mac ES files, with targeted inspection of Linux syslog and histories. Network-only sources were not the basis of this endpoint verdict.

### Windows process identity and native fields

`WS-MCHEN-01.../windows_event_sysmon.xml:149` begins a concrete process-create example: PID 6852, `dllhost.exe`, parent PID 5896 `svchost.exe -k DcomLaunch`, SYSTEM, LogonId `0x3e7`, integrity System. The corresponding Security 4688 at `windows_event_security.xml:264` uses NewProcessId `0x1ac4` and creator ProcessId `0x1708`, which convert to the same decimal child and parent. eCAR line 9 agrees with that relationship. This is credible source-native representation, including hexadecimal versus decimal PIDs.

The same host's early Sysmon Event 5 records at lines 65, 93, and 121 terminate preexisting cmd, explorer, and ssh processes. Their creation records need not be inside this slice. I did not count these as orphaned lifecycles.

I checked visible Sysmon identities against create and terminate UtcTime values, including parent identities and Event 10 source/target identities. No impossible ordering was found in these checks. Repeated hashes for the same image remain consistent within each host, and machine-specific ProcessGuid prefixes differ between the ten hosts. These are affirmative consistency observations, not reasons to call the dataset synthetic because it correlates well.

The document-operation attribution is a separate concern from process trees. Explorer and RuntimeBroker can legitimately access documents, and a collector may normalize brokered activity. Nevertheless, the repeated assignment of ordinary document reads/writes and Office-style temporary names to this small pair of actors across several workstations makes the actor distribution less persuasive than the process-create telemetry. I have not elevated it to an impossible field claim.

### Mac lifecycle and policy interpretation

The 303 ES records comprise 96 fork, 113 exec, and 94 exit notifications. Within each host, I keyed snapshots by PID plus pidversion and found no key associated with conflicting executable paths and no observed process snapshot after its matching visible exit. Executable device/inode identities likewise did not acquire conflicting path, cdhash, size, or mode combinations in the inspected snapshots. A stable PID across exec images was treated as one process lifetime, not as PID reuse or duplicate creation.

The SSH tree on MAC-MROSS-02 is particularly useful: ES lines 50-64 show launchd/xpcproxy, sshd-keygen-wrapper, sshd, sshd-session, a short-lived sshd-auth branch, and the eventual zsh. ES lines 74-76 close the shell and session processes around 14:34:59; these are not generic Linux PAM messages transplanted onto the Mac. Its Unified Log line 2 records keyboard-interactive/pam acceptance at 14:24:35.331567 UTC from `10.10.1.41:50250`.

MAC-MROSS-01 Unified Log line 2 says `ASP: Security policy would not allow process: 62517, /Applications/MeetingAssist.app/Contents/MacOS/MeetingAssist` at 15:42:20.850119 UTC. I did not treat this wording alone as proof of a denied successful execution, nor infer unseen child execution from it. The sparse Unified Log export is neutral under the stated collection assumptions.

The principal remaining Mac concern is behavioral distribution: repeated command-line inventory work and using cat/tee for the entire visible office-document read/write set on MAC-MROSS-02. The ES and eCAR records agree on the utility process identities, so the concern is the represented workload rather than a broken cross-source join. A legitimate research, inspection, or automation workflow remains possible.

### Linux sessions and background activity

DB-PROD's 14:48 session has consistent source tuple, sshd PID 1063740, PAM user UID 2176, and logind session 277489. eCAR lines 197 and 200 establish the privileged sshd process and user shell; subsequent commands belong to that shell. Its history mixes database queries, ordinary file/status inspection, and a backgrounded `tail -f`, rather than requiring every command to have a process event when it is a shell builtin.

FILE-LNX's syslog lines 91-96 show a plausible authenticated Samba access sequence: user maya.ross, source 10.10.1.42, share ClinicalResearch, open/read/close of `Team/2026/project-plan.pdf`, and service disconnect. Lines 85-88 separately show successful authentication followed by an access-denied file open for a different user; authentication success is correctly distinct from resource authorization.

Periodic `debian-sa1` collection occurs twelve times on several Linux hosts in this six-hour slice. A shared cron schedule readily explains that, so I did not score the fixed count as a synthetic tell. Likewise, gaps in selected endpoint sources and out-of-window process/session starts and endings were not penalized.

### Weight of the evidence

I found credible source-native identities and extensive lifecycle consistency, with no demonstrated hard contradiction. The concerns are narrower: endpoint document-access ownership and repeated visible user-command vocabulary. Their possible operational explanations prevent a likely-synthetic score, while their recurrence prevents me from calling the data indistinguishable from production or confidently real. The score of 46 reflects that mixed evidence; the higher verdict confidence expresses confidence in withholding a categorical verdict.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Mac ES and eCAR | All nine observed office-document READ/WRITE operations on MAC-MROSS-02 use cat/tee | Largest concern: plausible executions, but a narrow and unusual document-workload distribution |
| environment_or_collection_plausibility | Windows eCAR | Repeated RuntimeBroker/Explorer document attribution across several workstations | Moderate concern about actual I/O ownership; broker/collector explanations remain possible |
| distribution_texture | Mac zsh history and ES | Two machines repeatedly use overlapping small status/inventory command pools | Small concern; consistent with real troubleshooting as well as templated behavior |

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed native records and normalized records are coherent; no demonstrated native schema defect.
- **Temporal patterns:** 8 — Source-specific offsets and visible lifecycles are credible; a six-hour slice limits broader behavioral inference.
- **Cross-source correlation:** 9 — Checked Windows PID/parent representations and Mac process lifetimes agree without an established impossible relationship.
- **Behavioral realism:** 6 — Repeated inventory vocabulary and utility-based binary-document access weaken workload realism.
- **Environmental consistency:** 8 — Server/workstation versions and platform-specific session trees are persuasive, with reservations about document actor attribution.

## Recommendations

- If this were synthetic, model document operations from the application or utility actually issuing the I/O. In particular, validate repeated RuntimeBroker attribution to Office-style temporary files against a real collector example, and retain broker attribution when justified by that collector's semantics.
- If this were synthetic, ensure the dominance of cat/tee for binary office documents reflects an explicit inspection or automation workload. Ordinary document usage should have the appropriate application-owned file operations when those operations fall within the selected collection scope.
- If this were synthetic, expand repeated interactive command vocabulary only where the represented user's work supports it, and preserve coherent per-shell process lifetimes and source timestamps while doing so. No extra event families are required merely to increase apparent richness.
