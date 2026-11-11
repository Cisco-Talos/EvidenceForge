# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 24

## Executive Summary

The bounded endpoint sample is predominantly production-like: Windows process identity agrees across three sources, and Linux SSH transport precedes authentication and session opening. I found no demonstrated impossible field value, exact-identity lifecycle inversion, or source-native contradiction; the available sample supports a low synthetic-confidence score, but does not establish production provenance.

## Evidence For Synthetic

- [weak_signal] On `WS-AJOHNSON-01.meridianhcs.local/windows_event_sysmon.xml`, recurring parent/image pairs include explorer→PowerShell nine times, explorer→mstsc nine times, PowerShell→ssh eight times, and cmd→PowerShell eight times among 118 Event 1 records. This warrants a larger behavior-distribution comparison, but can reflect a real administrator's work. It is not a demonstrated generator fingerprint and has very little weight in the score.
- No hard contradiction, contract gap, or demonstrated native-format defect was established within this review. Sparse macOS Unified Log coverage and absent pre-window process creators were not treated as synthetic evidence.

## Evidence For Real

- Windows PID 5180 (`0x143c`) on WS-AJOHNSON-01 is consistently `taskhostw.exe /Run`, parent PID 4356 (`0x1104`) `svchost.exe`, SYSTEM/session 0: Sysmon Event 1 at `2026-11-02T13:10:01.7957426Z`, eCAR CREATE at `13:10:02.033Z`, and Security 4688 at `13:10:02.1751666Z`. The small observation delays are plausible.
- Linux APP-INT-01 has an exact SSH tuple `10.10.1.21:38780 → 10.10.2.30:22`: eCAR inbound FLOW at `13:34:38.134Z`, sshd Accepted password at `13:34:47.103568Z`, PAM session opened at `13:34:47.243309Z`, and eCAR USER_SESSION LOGIN at `13:34:48.126Z`, all on November 2. User `lina.nguyen` agrees across auth/session records.
- All 118 sampled-workstation Sysmon Event 1 records have stable hash strings per executable path across 41 paths. Across the hash-bearing Sysmon records examined as an aggregate, SHA1/MD5/SHA256 lengths are valid for all 134 values per algorithm, and all 131 IMPHASH values have the expected 32 hexadecimal-character length.
- In WS-AJOHNSON-01 eCAR, 86 exact objectIDs have both visible CREATE and TERMINATE; none terminates before creation. Other lifetimes can cross the collection boundary.
- APP-INT-01 syslog includes an rsyslog queue backlog of 2,028 pending messages at `13:00:32.218756Z` and systemd-resolved resuming UDP+EDNS0 at `13:00:58.761421Z`, adding plausible operational background unrelated to intrusion narration.
- macOS ES distinguishes fork and exec rather than treating every image transition as a new PID: launchd forks PID 41136 at `13:00:06.950823Z`, then the child execs xpcproxy at `13:00:06.953308Z`, preserving PID/start time while changing pidversion 12→13.

## Detailed Analysis

### Scope and method

I read only the supplied data directory and the assigned briefing. I inspected 20 representative logical records/commands, with two exact cross-source pivots (one Windows process and one Linux SSH session). Supplemental counts were restricted to the selected workstation's process/security sources, two Linux hosts' shell histories, and the two Macs' endpoint/Unified Log source types; these were aggregate checks, not exhaustive per-record adjudication. XML wrappers were not counted as telemetry records. The assessment does not use filesystem timestamps, sanitized names, scenario assumptions, outside reports, or absent selected Sysmon families.

The representative sample comprised two initial eCAR process terminations, two Linux operational syslog records, two macOS ES records, three macOS Unified Log records, two Windows process records used in the first pivot, its matching eCAR record, three additional Linux SSH records used with its Accepted record, the Accepted record itself, two shell-history commands, and two Windows user-process creations.

### Windows process ownership and lifecycle

The PID 5180 three-source pivot provides a concrete ownership check rather than a match on image alone. Sysmon gives ProcessGuid `{fd907e59-8ba9-6ae8-5f00-00102d8b8bdb}`, parent PID 4356 and SYSTEM LogonId `0x3e7`; Security represents those PIDs in hexadecimal, and eCAR represents them in decimal with its own object identity. Different source object-ID namespaces are not a defect.

Two later user-process samples are credible explorer children in the same user session: PowerShell PID 5216 at `13:18:20.223` and GlobalProtect PanGPA PID 6192 at `16:14:11.858`, both parent PID 4980, principal `MERIDIANHCS\\aisha.johnson`, LogonId `0x24a146b`, TerminalSessionId 2, and medium integrity. GlobalProtect carries a product-specific `6.2.3.123` version and its installation directory, rather than a Windows system-directory fallback.

The workstation source totals are 593 Sysmon records and 833 Security records. Security includes 117 process creates, 97 process terminations, 24 successful logons, 14 logoffs, six failed logons, five explicit-credential events, and paired lock/unlock counts of two each. These counts need not match every source exactly because their observation scopes differ. The eCAR aggregate has 117 CREATE, 98 TERMINATE and 42 OPEN process records, with 86 fully visible nonnegative lifetimes. The initial eCAR ssh.exe terminations (PID 5116 at timestamp_ms 1793624422137 and PID 5124 at 1793624477850) do not imply a defect merely because their initiators were outside the inspected slice.

A preliminary all-event grouping showed several hash strings associated with a process image; restricting to Event 1 removed that concern. Image-load records can describe a module hash alongside the owning process image. I did not score that apparent difference as binary mutation.

### Linux session and shell behavior

The APP-INT-01 SSH pivot uses the exact client address and port, not just username. The sshd process identifier 2937762 is identical on Accepted and PAM records, while eCAR ties the tuple to LOGIN objectID `3451c175-9da0-45cb-ba13-aefd36fb3f7b`, logon_id `0x1518bcf1`, session_id 337, session_type ssh. The approximately nine-second interval from visible FLOW to authentication is possible; session opening then follows authentication rather than preceding the transport.

APP-INT-01 histories contain 36 commands, 34 distinct; the only two duplicated strings are `docker compose ps` and `cat /proc/sys/kernel/osrelease`, twice each. WS-OHADDAD-01 has 16 commands, all distinct. Its sampled history has timestamp `#1793626343` with `python3 --version`, then `#1793626389` with `find . -name '*.csv' -o -name '*.xlsx' | head`. This shows host-specific developer/data work and human-scale spacing; it is too small a sample to infer a template or daily routine.

### macOS source interpretation

MAC-MROSS-01 ES contains 141 notifications: 52 EXEC (9), 45 FORK (11), and 44 EXIT (15). MAC-MROSS-02 contains 175: 64 EXEC, 54 FORK, 57 EXIT. More execs than forks are compatible with successive image transitions, and the counts alone are not a lifecycle defect. The selected launchd→xpcproxy records preserve native audit-token distinctions, executable stat/code-signing metadata, and a coherent process start time. I did not attempt to certify every version-11 native field against SDK documentation.

The selected Unified Log entries include loginwindow workspace launch at `13:03:16.611945+0000`, an AppleSystemPolicy message at `15:47:27.953941+0000` saying policy would not allow PID 62993 `/Applications/MeetingAssist.app/Contents/MacOS/MeetingAssist`, and sshd-session Accepted publickey at `16:02:15.419201+0000` for maya.ross from `10.10.1.42:59648`. The policy message does not establish successful child execution. No MeetingAssist-bearing ES row was identified by the bounded target search, so there is no demonstrated denied-execution/successful-effect contradiction. Neither this thin Unified Log selection nor the absent attempt notification was scored as missing mandatory evidence.

### Limits and alternate explanations

A well-constructed synthetic corpus can produce each positive finding above. Conversely, recurring administrative tool pairs can be real work, or arise from collection selection. The review does not establish organization roles independently, examine full-day behavior across all hosts, validate every macOS native structure, or require out-of-window lifecycle evidence. Therefore the authenticity verdict remains inconclusive despite strong local consistency.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| weak_signal | Windows Sysmon process creation | One workstation; 118 creates; recurring administrative parent/image pairs | Small concern only; compatible with repeated real administration and insufficient for a synthetic verdict |
| No demonstrated high-impact indicator | Windows, Linux, macOS endpoint sample | 20 representative records/commands plus two exact cross-source pivots | No hard-contradiction or contract-gap uplift warranted |

## Realism Score by Category

- **Field format accuracy:** 9 — Sampled Windows identifiers/hash lengths and macOS process structures are coherent; full native-schema certification was outside scope.
- **Temporal patterns:** 9 — Exact process and SSH pivots have plausible source delays and correct ordering; no negative matched process lifetime.
- **Cross-source correlation:** 9 — Windows PID/parent/principal and Linux SSH tuple/user relationships agree across distinct sources.
- **Behavioral realism:** 8 — Credible operational background and user applications; repeated administrative tool pairs remain a weak unresolved texture question.
- **Environmental consistency:** 8 — Platform-specific evidence is maintained; host roles and collection policies cannot be independently established from this bounded sample.

## Recommendations

- If this were synthetic, retain the observed shared process/tuple ownership and source-specific timestamp delays; the examined joins need no corrective change.
- Before changing the repeated Windows tool-launch texture, compare exact command-line frequencies and host-specific administrative workload over a larger visible interval. The current counts support investigation, not a demonstrated defect or a requirement to add arbitrary noise.
- No additional event family, pre-window creator, post-window terminator, or macOS policy effect should be invented merely to fill the limits of this collection.
