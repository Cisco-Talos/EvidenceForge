# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 48

## Executive Summary

The endpoint evidence is technically coherent enough that I cannot confidently distinguish production telemetry from a carefully constructed synthetic dataset. Repeated shell-based handling of binary documents is the strongest synthetic-looking behavior, but my process-identity, lifecycle, hash, and cross-source checks did not establish a hard contradiction that would justify a high synthetic-confidence score.

## Evidence For Synthetic

- [distribution_texture] MAC-MROSS-02 repeatedly reads binary document formats through the same terminal-driven process pattern. Its macos_endpoint_security.ndjson records seven separate /bin/cat executions against two PDF files, one XLSX file, and four DOCX files: lines 32, 108, 118, 121, 149, 155, and 161. Examples include project-plan.pdf at 13:37:11.214478Z, service-review.xlsx at 16:05:48.676562Z, and project-plan.docx at 17:10:43.529782Z on November 2. These are not merely command strings in history: matching eCAR FILE/READ observations attribute actual reads to those processes. Repeating a generic text-display operation across unrelated binary document types looks more like an abstract “read file” behavior than ordinary document use. It remains possible that this is deliberate raw-file inspection or testing.
- [weak_signal] The two Macs' interactive shell activity repeatedly samples a small diagnostic vocabulary. MAC-MROSS-01 runs id, sw_vers, uname, ls, find, ps, and df in separated clusters; MAC-MROSS-02 similarly returns to sw_vers, uname, pwd, ls, du, find, and ps. For example, MAC-MROSS-01 repeats sw_vers/id at 16:33:33/16:34:07 after an earlier startup cluster, while MAC-MROSS-02 repeats uname/id at 16:46:28/16:47:16. The commands and times are visible in the native ES export and zsh histories. This is a weak behavioral texture signal, especially because both machines belong to the same named user and diagnostic work is entirely plausible.
- [weak_signal] Some Linux administrative commands appear selected from advertised capabilities rather than clearly identified daemon names. APP-INT-01/syslog.log line 25 records “systemctl status cifs-utils --no-pager” at 13:09:44.973831Z and line 37 queries “journalctl -u smbclient -n 80”; both mail Linux hosts also have “systemctl status imaps” commands. These are valid command invocations, and custom units or ordinary operator mistakes could explain them. I do not infer successful service management or an impossible configuration from sudo's PAM session records, and give this observation little scoring weight.

## Evidence For Real

- Windows process creation agrees across independent source shapes. I matched 873 Sysmon Event 1 records to Security 4688 records by host and PID; image path, command line, and parent image agreed for every matched pair. Four additional 4688 records lacked a matched Sysmon 1, which I did not treat as an authenticity defect.
- Repeated Sysmon process creations retain consistent hashes for the same image on each host. Comparing available process/module hash sets across hosts also did not reveal a hash set claiming different file versions.
- Windows process trees contain meaningful system and user relationships, including SearchIndexer → SearchFilterHost/SearchProtocolHost, services → svchost, smss → winlogon → userinit → explorer, and explorer → applications or administrative tools. These are more specific than flat, arbitrary PID assignments.
- macOS evidence distinguishes fork, successive exec images, and final exit. MAC-MROSS-01 PID 25527 transitions from the launchd fork image through xpcproxy to Terminal without inventing three process lifetimes. Its login child and zsh grandchild are separate processes. MAC-MROSS-02 uses a different iTerm/iTermServer/login/ShellLauncher chain.
- A rejected Mac application attempt does not produce a contradictory successful execution in the visible native process records. MAC-MROSS-01's Unified Log reports an AppleSystemPolicy rejection for MeetingAssist PID 42008 at 15:42:09.009673Z; I found no matching successful ES exec for that application.
- Linux SSH evidence has realistic transport/authentication/PAM/session sequencing. DB-PROD-01 logs a connection from 10.10.1.41:56332 at 13:26:13.677283Z, public-key acceptance at 13:26:19.866241Z, PAM session opening at 13:26:19.924343Z, and systemd-logind session 321 at 13:26:20.417851Z. Its close at 14:00:35.921400Z precedes session removal at 14:00:36.198192Z.
- Linux logs include cron/anacron, package maintenance, DHCP renewal, resolver state, journald, forwarding queues, and host-specific service noise rather than only interactive commands. The mere presence or completeness of correlated records was not scored as suspicious.

## Detailed Analysis

### Scope and examination method

I examined only the supplied data directory. Endpoint coverage consists of 23 host directories with 36,715 total eCAR records: ten hosts have Windows native event exports, eleven have Linux-style syslog, and two have macOS native exports. The Windows files contain 17,375 Security events and 11,315 Sysmon events; the Macs contain 322 ES records and six Unified Log records. The visible activity is approximately the 13:00–19:00 UTC window on November 2, 2026.

I parsed the Windows XML and endpoint JSON, read concrete native events and histories, compared process identities across sources, and examined lifecycle ordering. I did not consult an external scenario, ground truth, repository, other analysts, or external documentation. Consequently, unfamiliar version-specific native details were not promoted into schema violations.

### Windows process and hash integrity

There are 877 Security 4688 and 873 Sysmon Event 1 records. All 873 matched pairs agree on the process image, command line, and parent image after normal case-insensitive comparison. A concrete example is WS-AJOHNSON-01 PID 5184/0x1440: Sysmon EventRecordID 30298 records SearchFilterHost.exe at 13:02:46.1434287Z with SearchIndexer.exe PID 4636 as parent; Security EventRecordID 129948 records the same creation at 13:02:46.2523414Z. SYSTEM ownership and LogonId 0x3e7 are consistent.

I checked visible Sysmon creations against dependent ProcessGuid, SourceProcessGUID, and TargetProcessGUID references, as well as matching terminations. I found no dependency more than one second before its visible creation or more than one second after its visible termination. For parents with a visible creation record, I found no conflicting parent image/PID or parent creation later than the child. These checks do not claim that every possible subsecond timing relationship or missing event has been validated.

The equivalent eCAR graph check across all hosts found no actor/process use more than two seconds before a visible PROCESS/CREATE or more than two seconds after a visible PROCESS/TERMINATE for the same object identity. The tolerance accommodates source timestamp/observation differences; it is not evidence of native clock accuracy.

Hashes are stable within each host/image combination. Matching hashes across different per-user installation paths, such as Zoom or Teams, are compatible with the same installed application build. I did not find an available hash set paired with conflicting version strings. Several processes have unavailable metadata, but that fact alone is not a demonstrated native-format defect.

### Windows sessions and collection-window boundaries

The dataset includes interactive, network, service, remote-interactive, new-credentials, and unlock logon types. Workstation lock/unlock evidence is present: WS-AJOHNSON-01 has 4800/4801 plus a Type 7 unlock, and WS-MCHEN-01 has two lock/unlock pairs. Server hosts have substantially more network/service authentication than the workstations.

I explicitly excluded Type 7 unlocks from tests that would treat a 4624 as the first creation of a session. For example, WS-DRAMIREZ-01 has processes under LogonId 0x96cfaea before its visible Type 7 event at 15:50:34.9509362Z; this is compatible with an already-existing session and is not a process-before-logon contradiction. Likewise, reuse of the same session identity between an interactive logon and later unlock is not evidence of synthetic generation.

Processes and sessions without visible initiating or closing records were not penalized simply because the dataset is a time slice. In particular, the number of service logons exceeding visible logoffs is insufficient to prove a lifecycle defect.

### Linux host evidence

The DB-PROD-01 SSH example above is a useful positive correlation: the Mac-side eCAR FLOW uses the same 10.10.1.41:56332 → 10.10.4.10:22 tuple and precedes the server's authentication/session records. Source observation times differ, so I did not demand identical timestamps across endpoint normalization and syslog.

Sudo messages generally have distinct command, PAM-open, and PAM-close records. DB-PROD-01's first visible command, “systemctl is-active mysql,” is logged at 13:01:01.185662Z, followed by PAM open at 13:01:01.257511Z and close at 13:01:03.031146Z. This is a credible sequence. A sudo PAM close establishes the end of that sudo session, not successful completion of every command's intended operation.

WS-OHADDAD-01 has a coherent anacron sequence: start at 13:06:28, a stated eleven-minute delay, cron.daily starting at 13:17:36, termination at 13:18:33, and normal exit at 13:18:35. Scheduled repetition is expected for cron and is not itself a synthetic timing artifact.

The service-name observations remain weak because the logs do not supply the commands' output or exit status. I cannot establish that the named units are absent.

### macOS identities, policy, and file behavior

The ES exports declare message version 11 and schema_version 1, and their observed event types are fork, exec, and exit. I interpreted the normalized eCAR records separately rather than demanding that eCAR's Windows-like hexadecimal logon IDs be native macOS audit-session identifiers.

MAC-MROSS-01's initial Terminal sequence runs from the launchd fork at 13:07:32.811343Z through xpcproxy and Terminal execs, then login PID 25528 and zsh PID 25529. Exec target PID versions advance while process start_time remains tied to the process lifetime. MAC-MROSS-02 instead shows iTermServer and ShellLauncher stages. The process snapshots distinguish real/effective credentials, audit IDs, parent tokens, and responsible tokens; those fields were not assumed interchangeable.

The visible inventory plist creation and later deletion are separate file events. I did not infer job unloading from deletion or require an activation to coincide with the initial write. Similarly, the MeetingAssist policy rejection was not interpreted as a successful process merely because the rejection message names a PID.

The principal concern is MAC-MROSS-02's document handling. All seven native execs that directly cat a mounted PDF/Office document have corresponding eCAR FILE/READ evidence. Four examples are:

| Native ES line | Exec time (UTC) | File | Matching eCAR FILE/READ time |
|---|---|---|---|
| 32 | 13:37:11.214478 | ClinicalResearch/Team/2026/project-plan.pdf | 13:37:29.955 |
| 108 | 16:05:48.676562 | ClinicalResearch/Archive/2025/service-review.xlsx | 16:05:57.353 |
| 118 | 17:10:43.529782 | Shared/Reference/project-plan.docx | 17:10:47.996 |
| 121 | 17:12:27.402087 | Shared/Reference/onboarding.docx | 17:12:32.454 |

These are mechanically valid reads. Their repeated choice of a binary-unaware utility is an authenticity concern about behavioral texture, not a claim that the operating system could not execute the commands. Intentional binary inspection, a test script, or an unusual user's workflow remains a credible alternative explanation.

### Scoring rationale and limits

The behavioral concern is concrete and recurrent, but localized. The remaining concerns are explainable weak signals, while numerous identity and lifecycle checks support technical plausibility. That combination supports a score near the uncertain middle of the rubric, not the 61–100 bands that call for stronger defects or contradictions. My verdict confidence reflects confidence that the evidence is inconclusive under this restricted examination, not confidence that the dataset has either particular origin.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| distribution_texture | macOS ES and normalized eCAR | Seven binary-document cat executions on MAC-MROSS-02 | Largest upward influence: repeated generic file-read behavior across PDF, XLSX, and DOCX; valid operations with plausible alternative explanations |
| weak_signal | macOS ES and zsh history | Recurring diagnostic clusters on both Macs | Small upward influence; same user and diagnostic work substantially weaken the inference |
| weak_signal | Linux syslog/sudo | Several service/status queries on application and mail hosts | Minimal upward influence; custom units and operator mistakes are possible, and success is not established |
| No established hard contradiction | Windows, Linux, macOS, eCAR | Parsed endpoint records and tested identity/lifecycle relationships | Limits the score: no demonstrated impossible endpoint lifecycle or native schema error |

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed source structures and native/normalized identity distinctions are credible; no demonstrated native schema defect.
- **Temporal patterns:** 8 — Tested lifecycles and sampled SSH/cron sequences are plausible; repeated diagnostic clusters are a weak concern.
- **Cross-source correlation:** 9 — All 873 matched Windows process creations agree on key fields, and sampled SSH/file relationships align.
- **Behavioral realism:** 6 — Seven binary-document cat reads create a conspicuous generic file-interaction pattern.
- **Environmental consistency:** 8 — Mixed platform and service roles are broadly coherent; a few service-management targets need context.

## Recommendations

- If this were synthetic, make file interaction depend on the actual file format and intended activity. For the seven MAC-MROSS-02 document reads, model an appropriate document application, a format-aware inspection tool, a transfer utility, or a specifically motivated raw-binary inspection workflow rather than repeatedly choosing cat.
- If this were synthetic, give the repeated diagnostic clusters more persistent task context and vary the command repertoire according to the particular host and task. Keep routine repetition where it is motivated; the concern is the recurring small vocabulary across otherwise different work.
- If this were synthetic, distinguish daemon/unit names from client utilities and package capabilities when selecting service-management commands. Where commands such as “systemctl status cifs-utils” are intentional mistakes or reference custom units, preserve evidence of that outcome when the collection includes it; do not treat sudo authentication as proof that the requested service operation succeeded.
