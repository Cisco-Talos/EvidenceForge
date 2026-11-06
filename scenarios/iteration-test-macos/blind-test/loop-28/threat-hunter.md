# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 84
**Synthetic-Confidence Score:** 29

## Executive Summary

The supplied records support practical hunting across Windows, Linux, macOS, network sensors, proxy and firewall sources. Representative SSH, file-staging and Windows credential-access pivots are technically coherent; I found no demonstrated impossible ordering or source-native contradiction in the checks described below. Shell-history texture merits scrutiny, but plausible collection settings prevent treating it as decisive evidence of synthesis.

## Evidence For Synthetic

- [weak_signal] Both Mac histories encode every command with elapsed duration `0`: 23/23 entries on MAC-MROSS-01 and 18/18 on MAC-MROSS-02. This includes SSH commands whose processes demonstrably live for minutes: MAC-MROSS-01 `zsh_history/maya.ross.zsh_history:7` records `: 1793629466:0;/usr/bin/ssh maya.ross@MAC-MROSS-02.meridianhcs.local`, while `macos_endpoint_security.ndjson:47–48` observes PID 51637 exec at `14:24:26.418920Z` and exit at `14:34:59.985491Z`. This resembles a history template if elapsed duration is intended to be final, but immediate/shared history writing can also leave zero durations. It receives only slight weight, not a contradiction finding.
- [weak_signal] The Mac file-access sample has an unusually shell-centric texture. MAC-MROSS-01 `ecar.json:122,173,202` records `/bin/cat` reading an XLSX and two PDFs; line 293 records `/usr/bin/tee` writing `team-roadmap.xlsx`. MAC-MROSS-02 lines 347 and 448 similarly read a PDF and XLSX with `/bin/cat`. These are possible operations, and a filtered endpoint export can emphasize them; I do not infer absence of GUI applications or failure of these accesses. This is a small behavioral-texture concern only.

## Evidence For Real

- A concrete SSH pivot preserves the tuple and operational sequence. APP-INT-01 `ecar.json:650` starts `ssh -tt root@DB-PROD-01.meridianhcs.local` at `18:14:26.367Z`; `zeek-db/conn.json:386` observes `10.10.2.30:37141 → 10.10.4.10:22` at `18:14:34.531763Z`. DB-PROD-01 `syslog.log:192–195` records the connection, accepted password, PAM session open and logind session 279039 in that order, followed by the shell and dump process in DB `ecar.json:578–579`.
- The reverse SCP transfer has a separate SSH tuple and receiver identity. `zeek-db/conn.json:387` observes `10.10.4.10:46978 → 10.10.2.30:22`; APP-INT-01 `syslog.log:196–199` identifies PID 2983966 and public-key acceptance for root. APP `ecar.json:655` attributes the receiving file to the same daemon PID, with closure in syslog lines 201–202.
- Windows credential-access evidence is actionable: WS-AJOHNSON-01 `ecar.json:702,711–714` links the renamed credential tool, its LSASS access, remote thread, and termination. Native Sysmon includes the same tool and arguments at `windows_event_sysmon.xml:9546,9552`, rather than relying solely on normalized EDR prose.
- In three Windows hosts examined for token identity, every in-window Sysmon process-create row with a matching Security 4624 LogonId agreed on LogonGuid: 106 matches on WS-AJOHNSON-01, 130 on DC-01 and 105 on WS-MCHEN-01. A separate bounded process-parent check across all ten Windows Sysmon files found 204 children with visible parent ProcessGuids and no disagreement between the child's ParentCommandLine and that parent's recorded CommandLine.
- Network observations are not byte-for-byte identical copies across sensors. The long APP-to-DB SSH flow has `missed_bytes=11`, `orig_bytes=3942`, `orig_pkts=27` in `zeek-db/conn.json:386`, versus `missed_bytes=0`, `orig_bytes=3953`, `orig_pkts=28` in `zeek-core/conn.json:10309`. This is compatible with differing packet visibility.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory. It contains 23 endpoint directories: ten with Windows XML telemetry, two with Mac ES/Unified Log telemetry, and eleven with Linux-style syslog/endpoint evidence. Network collection includes zeek-core, zeek-db and zeek-dmz, plus two Snort locations, a perimeter ASA log, proxy and web-access logs. These observations establish the apparent collection surface; they do not establish complete OS auditing.

The normalized endpoint records span `2026-11-02 13:00:01.077Z` through `18:59:59.688Z`. Counts are 34,926 eCAR records, 11,615 Sysmon events, 18,471 Security events, 4,148 syslog lines, 310 ES records, 21,137 Zeek connection records across sensors, and 21,343 ASA lines. XML event counts were obtained by parsing Event elements, not counting physical lines; multi-sensor network counts are not unique conversations. Those volumes do not by themselves demonstrate an implausible signal-to-noise ratio.

The review combined whole-file field/lifecycle checks with representative hunting pivots. It was not an exhaustive native-schema audit or packet reconstruction. File/line references are relative to `data`; endpoint names abbreviate the `.meridianhcs.local` directory suffix.

### Credential access and Windows identity

At `16:44:46.740Z`, WS-AJOHNSON-01 eCAR records PID 5964 under PowerShell PID 5872, principal aisha.johnson, LogonId `0x26d7ab7`, with `privilege::debug` and `sekurlsa::logonpasswords` arguments. LSASS access follows at `16:44:50.182Z`, then remote thread creation at `16:44:50.239Z`, and termination at `16:44:52.511Z`. The process is not attributed to SYSTEM merely because it accesses a SYSTEM target. Native Sysmon process creation reports High integrity, which is compatible with a privileged user process attempting this activity. The evidence proves observed process access/injection behavior, not that particular credentials were successfully recovered.

LogonGuid and parent-command checks described above support pivot feasibility. I also checked all 34,926 eCAR rows for references through actorID/source_process_uuid to a process more than two seconds after its visible termination, excluding termination rows themselves. No such references were found. This limited check does not prove every possible ownership relationship, but it avoids falsely declaring absent pre-window process creates to be defects.

### Linux staging and transport

DB-PROD-01 `ecar.json:579–589` shows the dump, SQL file, gzip output and SCP process in a feasible order between `18:14:49.552Z` and `18:16:11.397Z`. The initiating root SSH login uses source APP-INT-01, whereas SCP back to APP uses a different source port and public-key authentication. This separation is operationally plausible.

For the reverse transfer, the core sensor transport begins at `18:15:43.416203Z` with duration `26.269625`, closing near `18:16:09.686Z`; APP's native PAM close is `18:16:11.182690Z`. The short offset is compatible with application cleanup after transport completion. The normalized receiver file event at `18:16:10.476Z` follows the network close by under a second; without a documented endpoint timestamp/latency contract this is not evidence of a write after an impossible boundary.

The mysqldump argv lacks shell redirection, but that is not an error by itself: shell redirection is not normally part of the executed program's argv. The normalized FILE/CREATE attribution would require a known sensor semantic contract before assigning a shell-versus-program file-open defect.

### Scanning, Mac activity and limits

WEB-EXT-01 `ecar.json:1042` starts `nmap -sn 10.10.2.0/24` at `14:40:22.134Z`; associated endpoint flows are ICMP, and the corresponding sensor rows include responding and nonresponding hosts. The following process at line 1293 explicitly uses `-Pn -sT` with a five-port list. The two commands are not conflated into one TCP-only discovery operation.

The Mac history elapsed-time concern is reproducible on a second host: MAC-MROSS-02 history line 10 gives duration zero for its SSH client, whereas ES lines 99 and 102 show PID 45533 from `16:02:06.903116Z` through `16:18:00.955641Z`. This remains a collection-setting question. The sparse Unified Log export is not presumed complete; its policy message about MeetingAssist is not treated as proof of execution or proof of a successful installation. No absent Sysmon event family, missing optional source, domain resolution, file mtime, narrative linearity or mere cross-source completeness contributes to this score.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| weak_signal | Mac zsh history versus ES | All 41 history rows; six completed SSH clients provide long-runtime counterexamples | Small upward adjustment; immediate/shared history can explain zero elapsed fields |
| weak_signal | Mac normalized process/file telemetry | Representative cat/tee access to Office/PDF paths across both Macs | Small texture concern; valid commands and possible export selection prevent a stronger conclusion |

No hard contradiction, demonstrated contract gap, or proven native schema defect was established in this bounded review.

## Realism Score by Category

- **Field format accuracy:** 8 — Parsed XML/JSON and useful native identifiers; history elapsed-time semantics remain uncertain.
- **Temporal patterns:** 8 — Representative transport/auth/process ordering works, with plausible sensor offsets.
- **Cross-source correlation:** 9 — Concrete credential-access and SSH/SCP pivots preserve actors, tokens and tuples.
- **Behavioral realism:** 8 — Scanning, administrative SSH and staging are plausible; Mac file-access texture is somewhat repetitive.
- **Environmental consistency:** 8 — Mixed platforms and segmented sensor viewpoints are coherent in the inspected sample.

## Recommendations

- If this were synthetic, model zsh history according to an explicit shell configuration: finalized EXTENDED_HISTORY records should reflect elapsed runtime where appropriate, while immediate/shared-history captures may legitimately retain zero. Preserve that collection explanation rather than unconditionally rewriting zero values.
- If this were synthetic, review the repeated Mac cat/tee access to XLSX/PDF paths. Keep these operations when their intended workflow is actually shell-based; represent the corresponding application or automation when that is what performed the visible file action.
- Retain the demonstrated identity and transport relationships. The evidence does not justify adding absent optional log families or extra failed attack steps merely to create messiness.
