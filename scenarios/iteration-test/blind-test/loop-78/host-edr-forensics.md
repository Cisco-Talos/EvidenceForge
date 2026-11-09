# Blind Host/EDR Forensics Review — Loop 78

## Verdict

**Verdict: Inconclusive**  
**Verdict confidence: 66/100**  
**Synthetic-confidence: 18/100** (low; lower means more production-like)

The inspected six-hour host slice is internally coherent and contains no high-confidence host/EDR contradiction. Windows process trees and session records, Linux PAM/systemd activity, and macOS Endpoint Security lifecycles are broadly plausible. There is a small weak signal in repetitive shell-history enumeration, but it is not enough to distinguish generated from real operator activity. I cannot establish provenance from these records alone, so I do not call the data Real; the host evidence does not support a Synthetic verdict either.

## Scope and method

Reviewed only `/private/tmp/log-study-loop78/dataset-pine/data`, across the observed window on 2026-11-02 from approximately 13:00 to 19:00 UTC. Inspected Windows Sysmon and Security XML, host eCAR JSONL, Linux syslog and shell histories, and macOS Unified Log, Endpoint Security, eCAR, and zsh history. The six-hour window was treated as a bounded slice: an absent initiating or terminating event at its edges was not counted as a defect. Cross-source gaps were not treated as synthetic evidence by themselves.

## Evidence by category

### hard_contradiction

**None found.**

- On the inspected Windows hosts, Sysmon process creation and termination records did not show a process ending before its observed creation. For the ten Sysmon streams, observed event-1/event-5 counts ranged from 54/31 on `WS-PPATEL-01` to 162/160 on `DC-01`; paired GUIDs had valid ordering. Where a child’s parent creation was also present in the six-hour stream, the parent did not start after the child.
- A concrete cross-source example is `WS-EBROOKS-01` at 13:06:09 UTC: Sysmon process creation reports PID 4292 for `dotnet-sdk-installer.exe`; Security 4688 reports `NewProcessId=0x10c4` (4292), the same image, interactive user, and Explorer parent. At 13:06:39, Sysmon and Security 4688 similarly agree on Edge PID 4116 (`0x1014`) and its Explorer parent. Subsequent Sysmon network events at 13:06:42 use that Edge PID and image.
- The very large Mac-MROSS-02 process-exit cluster initially merits inspection, but it is consistent with an actual session end: 13 processes (including Chrome, Word, Outlook, Zoom, iTerm, and the user shell) exit between 18:56:58.009 and 18:56:59.843 UTC; eCAR records the corresponding local `maya.ross` session logout at 18:57:05.984. This ordering is plausible for desktop logout and is not an orphaned mass exit.
- Mac Endpoint Security event records have a continuous, unique `global_seq_num` in each reviewed host stream (0–121 on MAC-MROSS-01; 0–185 on MAC-MROSS-02). Observed fork/exec/exit records use plausible executable paths, parent PIDs, and execution order. For example, MAC-MROSS-02’s iTerm → iTermServer → login/shell chain is represented around 13:11:51, and later interactive SSH process trees have matching child and parent identities.
- Linux syslog contains ordinary PAM and systemd-logind session evidence, SSH open/close messages, and service-specific messages. Nothing inspected showed a definite impossible session or process ordering.

### contract_gap

**None established from this slice.**

- Windows client lifecycle counts are not perfectly paired (for example, `WS-PPATEL-01` has 54 Sysmon process-create and 31 process-terminate records), but processes may outlive the window or have one side outside source coverage. Given the bounded slice and the task’s edge rule, these differences are not actionable by themselves.
- Mac Endpoint Security focuses on fork/exec/exit events while eCAR also includes FLOW, FILE, and USER_SESSION records. That source-level difference is not a contradiction without a required-companion contract visible in the supplied records.
- Only a few Unified Log rows are present per Mac host, while Endpoint Security carries 122 and 186 records respectively. This may reflect a narrow Unified Log collection predicate; no concrete missing companion or impossible record was found to make thinness diagnostic.

### distribution_texture

**Weak signals only.**

- Windows domain controllers have markedly higher event volume than workstations, in a role-consistent way. DC-01 has 3,239 Sysmon Event ID 3 network records and 4,625 eCAR FLOW records over roughly six hours; DC-02 has 3,889 Security 5156 records, 1,078 Event 4769 service-ticket records, and 398 Event 4768 TGT records. The visible concentration on DNS, Kerberos, LDAP, and SMB is plausible for domain-controller activity; volume alone is not evidence of synthesis.
- On the two Macs, eCAR has 501 and 631 records, chiefly FLOW CONNECT, process create/modify/terminate, and a small set of login/logout and file events. This is sparse compared with the Windows DC streams but is not a demonstrated distribution contradiction.
- Shell histories show repeated administrative discovery commands (for example `id`, `uname`, filesystem inspection, process listing, and repeated SSH usage by maya.ross). The content is somewhat schematic at a glance, but the commands vary by host/user and fit the corresponding administration roles. Do not elevate this to a synthetic finding without evidence of impossible repetition or incompatible host activity.

### schema_or_format

**No material format issue found.**

- Windows event XML parsed successfully, with expected namespaced Event/System/EventData structure and source-specific event IDs including Sysmon 1/3/5/10/22 and Security 4624/4634/4688/4689/4768/4769/5156.
- eCAR records parsed as JSON lines and contained the expected timestamp, host, object, action, identifier, and properties structure in the reviewed files. The sampled timestamps align with the 2026-11-02 window.
- macOS Endpoint Security and Unified Log files use parseable NDJSON; macOS shell history uses normal zsh extended-history syntax. Linux syslog rows use RFC 5424-style timestamps and host/process fields.

### environment_or_collection_plausibility

- Host roles and OS-native artifacts are coherent: Windows domain controllers produce dense Kerberos/DNS/network evidence; Windows workstations show interactive process launches and browser traffic via the modeled proxy; Linux servers show PAM/systemd, SSH, service administration, and shell histories; Macs show desktop applications, Terminal/iTerm shells, local login/logout, and SSH sessions.
- A Linux example is FILE-LNX-01: PAM records a local `aisha.johnson` session opening at 13:00:09, followed by a systemd-logind session creation at 13:00:16; syslog also records independent SSH session close and Samba service activity. The row mix and timings are plausible for a file server.
- On MAC-MROSS-02, the local GUI session starts at 13:04:09; Endpoint Security records user applications and shell activity during the slice; eCAR records a remote SSH login at 14:25:19 and logout at 14:35:11; the local session logs out after the desktop processes exit near 18:57. This is coherent as a host activity sequence.

### weak_signal

- Shell history on several hosts contains compact bursts of routine enumeration and monitoring commands, with some repeated command families. History alone is incomplete, and shell-history timestamps/content do not prove that a command completed or that the history is exhaustive. This remains a low-weight signal.
- The comparatively sparse Mac Unified Log output limits assessment of OS-native log semantics, but sparse collection is not itself synthetic evidence.

## Recommendations

1. Keep this result classified as **Inconclusive** unless independent provenance or a broader host interval resolves it.
2. If follow-up review is requested, prioritize a longer interval around macOS desktop login/logout and representative Windows workstation/DC process and session histories. Current sampled ordering looks sound; review should seek contradictions rather than penalize ordinary slice-edge gaps.
3. Do not change the dataset based on the shell-history repetition or uneven source volume alone. No specific host/EDR repair is supported by the inspected evidence.
