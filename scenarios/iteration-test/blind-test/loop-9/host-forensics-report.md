# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 49

## Executive Summary

The endpoint evidence is substantially coherent: I found no demonstrated visible process-lifecycle inversion, inconsistent per-host executable hashes, or mismatching image/command line between matched Security 4688 and Sysmon 1 records. Some behavior distributions look constructed, especially the Windows console-process profile and repeated command-line consumption of binary documents on one Mac, but these are plausibility concerns rather than proof of fabrication. The supplied records support uncertainty more strongly than a categorical real/synthetic verdict.

## Evidence For Synthetic

- [distribution_texture] Across all ten Windows hosts, all 102 visible Sysmon 1 `conhost.exe` creations have `ParentImage=C:\Windows\System32\csrss.exe`, `User=NT AUTHORITY\SYSTEM`, `LogonId=0x3e7`, and `TerminalSessionId=0`. This is a remarkably narrow console profile alongside visible user shell activity and multiple interactive sessions. Examples are DC-02 at `2026-11-02T13:13:54.5397719Z`, PID 6944, and WS-MCHEN-01 at `13:17:14.8915189Z`, PID 6820. These records are internally consistent; the concern is their fleet-wide distribution, not a claim that any single parent relationship is impossible.
- [distribution_texture] Four Windows server-like hosts share a dominant four-image process-start vocabulary: `dllhost.exe`, `taskhostw.exe`, `WmiPrvSE.exe`, and `conhost.exe` account for 117/160 starts on DC-01, 107/125 on DC-02, 78/88 on FILE-SRV-01, and 56/78 on MAIL-FIN-01. The common concentration across different roles is suggestive of a reusable background-activity pool. This is moderate evidence only: persistent workloads may have started before the slice, and a shared management platform could cause similar activity.
- [environment_or_collection_plausibility] MAC-MROSS-02 repeatedly executes `/bin/cat` against PDF, XLSX, and DOCX files, with corresponding eCAR file reads: `project-plan.pdf` at `13:37:29.955Z`, `service-review.xlsx` at `16:05:57.822Z`, `project-plan.docx` at `17:10:47.491Z`, `onboarding.docx` at `17:12:31.889Z`, `draft-draft.pdf` at `18:37:52.027Z`, `project-plan-review.docx` at `18:42:16.083Z`, and `meeting-notes.docx` at `18:45:05.346Z`. Seven such reads distributed across the day look more like a generic file-access mechanism than ordinary document viewing. Raw-byte inspection or deliberate collection would also explain them; none is an impossible operation.

## Evidence For Real

- Windows native event shapes have meaningful differences rather than a single generic wrapper. Sysmon versions vary appropriately by represented event family: 1/3/22 use version 5, 5/7/10 use version 3, and 8/11/13 use version 2. Security records distinguish hexadecimal process IDs from WFP's decimal process IDs and represent device paths in 5156.
- Across the ten Windows hosts, matched Security 4688 and Sysmon 1 process starts agree on executable path and command line. I also found no per-host `Image` with competing `Hashes` values among its visible Sysmon 1 records.
- The 37,413 eCAR records across 23 hosts retain process ownership consistently. Checking visible actor references against visible process creation and termination records found no actor operation before its visible creation or after its visible termination. macOS image transitions are represented by `PROCESS/MODIFY`, avoiding the false assumption that every exec is a new process lifetime.
- MAIL-EDGE-01 has a credible cron lifecycle: shell PID 2284663 is created at `13:05:00.058Z`, child `debian-sa1` PID 2284664 at `13:05:00.372Z`, child termination at `13:05:01.792Z`, and shell termination at `13:05:01.945Z`. Syslog records the matching sysstat cron command at `13:05:00.203088Z`.
- DB-PROD-01 SSH records preserve source tuple, authentication, session open and close: PID 1372071 receives `10.10.1.31:60321` at `13:43:49.252679Z`, accepts marcus.chen's public key at `13:43:55.566288Z`, opens PAM at `13:43:55.688693Z`, and closes at `14:01:03.772992Z`. eCAR records the corresponding session login and logout with the same source tuple and session identity.
- macOS records distinguish Terminal from iTerm and local from remote execution. MAC-MROSS-02 includes iTermServer and ShellLauncher; MAC-MROSS-01 uses Terminal/login/zsh. SSH observations use macOS executable paths and audit tokens, not Linux PAM/systemd messages.
- At `15:42:09.009673Z`, MAC-MROSS-01's Unified Log reports an AppleSystemPolicy rejection for PID 42008 and MeetingAssist. I did not find a corresponding successful eCAR process creation for that PID. The rejection is therefore not contradicted by visible successful execution.

## Detailed Analysis

### Examination scope and limits

I examined the provided data directory only. I parsed all 23 eCAR files and all ten pairs of Windows Security/Sysmon XML files, examined both macOS Endpoint Security exports and Unified Log exports, and inspected Linux syslog and shell histories. The endpoint files describe approximately `2026-11-02 13:00–19:00 UTC`. Their eCAR inventory contains 2,659 process creations, with substantially different record volumes by host role.

My automated checks tested relationships that actually have visible identifiers and initiators. They do not prove all telemetry is authentic, nor do they assume that unmatched initiators or terminations must lie within this slice. I did not score missing Sysmon event types, sparse Unified Log output, sanitization of names/domains, or cross-source completeness as evidence of generation.

### Windows process and session evidence

There are 923 Sysmon 1 records and 922 Security 4688 records. I matched starts by host, process ID and nearest timestamp, then compared `Image/NewProcessName` and `CommandLine`; those matched fields did not disagree. Count differences alone are compatible with collection loss or event selection and did not affect the score.

For Sysmon events carrying `ProcessGuid`, I checked whether a referenced process had a later visible create or an earlier visible termination. No such ordering defect was demonstrated. Visible parent-image references also agreed with the parent creation records when both sides were present. Executable metadata distinguishes Windows build families 17763, 19041, 20348 and 22621; it is not uniformly stamped with one build.

Interactive evidence includes session-specific winlogon/userinit/explorer chains, network logons, service identities, workstation locking, and type 7 unlocks. WS-AJOHNSON-01, for example, has 4624 types 2, 3, 5, 7, 9 and 10. Comparing visible 4624/4634 pairs by host and target logon ID did not reveal a logout preceding a later visible login for the same identifier. Repeated built-in service IDs such as `0x3e7` are not treated as ordinary newly allocated user sessions.

The main reservation is the background-process distribution. DC-02 has 32 taskhostw, 31 dllhost, 28 conhost and 16 WmiPrvSE starts out of 125 total. FILE-SRV-01 has 22, 10, 18 and 28 respectively out of 88. These are plausible individual images, but the repeated concentration and all-SYSTEM console profile weaken behavioral authenticity. They do not establish an impossible Windows state.

### Linux service, session and shell evidence

The Linux material contains source-specific service vocabulary, sudo command records with PAM session transitions, periodic sysstat activity, SSH authentication, and mail transaction stages. Bash histories differ by user and include typos, administrative investigation, development tooling, and operational service commands. For example, lina.nguyen's workstation history includes git, pytest, compiler and container commands; omar.haddad's history includes database client and Python data-tool checks.

Samba ownership deserves care: FILE-LNX-01 starts an smbd worker as root, while later file operations carry a user principal and explicit `effective_uid`, `effective_gid`, `auth_session_ref` and `account_scope=directory`. That can describe impersonation and is not evidence that the process identity is corrupt. For example, PID 2774026 starts at `13:15:01.584Z` and reads a Shared document as marcus.chen at `13:15:02.042Z`, with effective UID/GID 4119.

The slice starts with some already-existing Linux sessions and services. Their missing visible startup is not a defect. Similarly, a history file containing an `exit` followed by later commands can aggregate multiple shells and is not by itself a causality contradiction.

### macOS execution and source semantics

The two ES exports contain 147 and 167 records respectively, with fork, exec and exit notifications. I preserved the distinction between PID lifetime and successive executable images. On MAC-MROSS-02, PID 88255 transitions from ShellLauncher to `/bin/zsh` at `13:12:07.954212Z`, while retaining its process start time and changing pidversion. A separate CREATE is not required for that exec.

File stat and signing snapshots were stable for repeated observations of the same executable identity within each host. Original/current parent fields, audit-session identifiers and normalized eCAR logon IDs were not conflated. The declared ES message version is 11; I did not call unfamiliar newer fields invalid on the basis of older export examples.

The repeated `cat` operations remain my most concrete macOS behavioral concern. Native ES exec arguments and normalized eCAR file reads agree about these operations, so this is not a correlation error. The issue is that the same raw-byte utility repeatedly handles formats normally consumed through structured document applications; the data does not show why that workflow is appropriate. Because it could reflect legitimate inspection or deliberate collection, I give it limited weight.

### Weight of evidence

I found no defensible hard contradiction or generator identity leak. The concerns above are correlated plausibility/texture observations and should not be counted as three independent proofs. High-quality deterministic synthesis could produce the coherent lifecycle evidence; equally, a production slice with standardized management and unusual document inspection could produce the observed distributions. That balance supports a synthetic-confidence score near the rubric's genuinely uncertain midpoint.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Windows Sysmon process creation | All 102 conhost starts across 10 hosts use SYSTEM, session 0, and csrss parent | Moderate upward pressure from a narrow fleet-wide console profile; no impossible individual event established |
| distribution_texture | Windows Sysmon process creation | Four common images account for 72–89% of starts on four server-like hosts | Modest upward pressure from repeated background vocabulary across roles; shared management and pre-window services remain alternatives |
| environment_or_collection_plausibility | macOS ES and eCAR file/process records | Seven PDF/XLSX/DOCX reads through cat on MAC-MROSS-02 | Modest upward pressure from repeated unusual application/file pairing; raw-byte access is technically valid |

## Realism Score by Category

- **Field format accuracy:** 9 — Source families preserve native distinctions, event versions, identifiers and executable metadata; no demonstrated parser/schema contradiction.
- **Temporal patterns:** 8 — Visible lifecycle and SSH ordering hold up; the six-hour slice limits conclusions about daily rhythm.
- **Cross-source correlation:** 9 — Matched Windows process fields and examined Linux/macOS identity chains agree without demonstrated impossible ordering.
- **Behavioral realism:** 6 — Console ownership, recurring Windows background images, and repeated cat/document pairings create noticeable texture concerns.
- **Environmental consistency:** 8 — Mixed operating systems, differentiated user tooling and service roles are plausible, with limited application/file-use reservations.

## Recommendations

- If this were synthetic, make console-process ownership, session placement and parentage follow the actual caller and hosting model. Validate the observed all-SYSTEM/session-0 distribution against representative captures from the Windows builds represented here.
- If this were synthetic, tie server process-start distributions to role-specific activity and concrete triggers, especially the four-image concentration on DC-01, DC-02, FILE-SRV-01 and MAIL-FIN-01. Preserve genuine differences in workload while retaining valid shared management behavior.
- If this were synthetic, use document applications or explicit inspection/collection actions for PDF, DOCX and XLSX reads. Retain cat when raw-byte reading is the intended behavior, rather than using it as the default file-access stand-in.
- Preserve the existing strengths: coherent process identifiers, exec-versus-fork separation, Samba impersonation context, SSH session timing, and rejection-versus-success distinctions. No recommendation here requires expanding source coverage merely to make the incident easier to reconstruct.
