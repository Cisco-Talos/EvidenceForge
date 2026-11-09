# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 93
**Synthetic-Confidence Score:** 82

## Executive Summary

This is a largely coherent mixed-platform dataset, but a zero-byte Zeek file record carrying non-empty content hashes and repeated arithmetic timing patterns in native Mac and Windows process telemetry favor synthetic generation. Process ownership, account boundaries, transport pivots, and most visible lifecycles are considerably more realistic than those defects; the verdict does not depend on how complete or easy to reconstruct the suspicious activity is.

## Evidence For Synthetic

- **[hard_contradiction] [P1] Zero observed file bytes with non-empty content digests.** `zeek-core/files.json`, line 625, at **2026-11-02 18:18:35.437160 UTC**, file ID `FZgEgCqVzTxAGQgCiu`, reports `seen_bytes=0`, `total_bytes=0`, `missing_bytes=0`, `overflow_bytes=0`, and `timedout=false`, while listing `MIME`, `MD5`, `SHA1`, and `SHA256` analyzers. Its MD5 is `764c0b9cf699b8690bc946daddb4a123`, rather than the empty-content MD5 `d41d8cd98f00b204e9800998ecf8427e`. The SHA1 and SHA256 also differ from their empty-content values. The associated `zeek-core/smb_files.json`, line 181, records `SMB::FILE_WRITE`, `size=0`, and the same file ID. This contradicts ordinary native file-analysis semantics, unless an undocumented enrichment layer has replaced the hash fields. Only **one of 2,488** Zeek file records has this particular defect.
- **[distribution_texture] [P2] Matching arithmetic command-spacing progression on both Macs.** In the two `macos_endpoint_security.ndjson` files, six successive three-command groups under local interactive shells have interval pairs approximately **(30,50), (37,52), (44,54), (51,56), (58,58), (65,60) seconds** on *each* host. Across the two hosts, all 24 measured intervals are within about 12 ms of these integer targets. The first interval grows by seven seconds per group and the second by two, despite changing command combinations and different wall-clock anchors. The histories independently expose the same pattern at one-second resolution. This is a concrete behavioral timing fingerprint, rather than a claim that the activity is narratively too clean.
- **[distribution_texture] [P2] Reused exact Windows parent-to-child launch delay.** `WS-AJOHNSON-01.meridianhcs.local/windows_event_sysmon.xml`, Event 1 `UtcTime` values show four separate `powershell.exe` → `ssh.exe aisha.johnson@LOG-MON-01.meridianhcs.local` pairs with exactly **4.460 seconds** between parent and child. Child PIDs/times are `5232` at `14:20:29.418`, `5380` at `15:25:03.082`, `5340` at `15:42:03.706`, and `5980` at `17:04:35.711`. The parent command line is simply `powershell.exe` in all four cases. Shared automation could produce this, but repetition of the same precise delay across widely separated interactive-looking launches supports the Mac timing evidence.

## Evidence For Real

- **Substantial background and varied source mix.** There are 23 endpoint eCAR files, 36,022 normalized endpoint records, 18,838 Windows Security events, 11,632 Sysmon events, 3,913 Linux syslog lines, 307 native Mac Endpoint Security notifications, 22,400 Zeek connections, 4,062 DNS records, 3,142 TLS records, 4,008 proxy lines, 23,095 ASA lines, and 128 IDS alerts. This is not just a handful of malicious commands surrounded by a token baseline.
- **Sound Linux export and transfer sequence.** On `DB-PROD-01`, root SSH authentication at `18:14:36`, shell PID `1088868`, `mysqldump` PID `1088891`, gzip PID `1088989`, and scp PID `1089089` have sensible visible ordering. The root history retains the shell redirection omitted from the child process argv. The receiving host records root SSH and target-file creation for the same transfer tuple.
- **Correctly differentiated local and outbound Windows identity.** `WS-AJOHNSON-01/ecar.json` records `runas.exe /netonly /user:marcus.chen "cmd.exe /d /q"` at `18:00:44.605`; the new command shell and children retain local principal `aisha.johnson` under new logon ID `0x27c99c4`. A `/netonly` launch does not require the local process principal to become the remote account.
- **Useful, numerically consistent proxy pivot.** The archive upload at `18:25:00` correlates endpoint curl PID `6164`, client tuple `10.10.1.35:61235 → 10.10.3.20:8080`, CONNECT and inspected POST records, and network byte accounting. The proxy's 302-byte setup plus 18,782,990 tunnel client bytes equals the connection's 18,783,292 originator bytes; the response components also add correctly.
- **Native Mac process transitions preserve identity distinctions.** On Mac 01, PID `42171` executes launchd → xpcproxy → Terminal while its `pidversion` changes, followed by separate login and zsh processes. The SSH session uses a distinct audit session (`100002`) from the local login (`100001`); POSIX session/group fields are separately represented. This is materially better than treating each exec transition as a fresh unrelated process.
- **Security-log clearing has native consequences.** On `DC-01/windows_event_security.xml`, Event 1102 at `18:42:21.0745228Z` uses the Eventlog provider and `UserData/LogFileCleared`, with `EventRecordID=1`. Subsequent records use small IDs, including `4`, `5`, `6`, and `7`, rather than continuing the preceding 28-million range.

## Detailed Analysis

### Scope, parsing, and hunting method

The visible window is approximately **2026-11-02 13:00–19:00 UTC**. Endpoint coverage consists of ten Windows hosts, eleven Linux/syslog hosts, and two Macs. The observed address space includes a workstation segment `10.10.1.0/24`, servers in `10.10.2.0/24`, DMZ/proxy systems in `10.10.3.0/24`, and database address `10.10.4.10`. These are log-derived interpretations, not imported environment facts.

I streamed all JSON/NDJSON and Windows XML files for inventories and consistency checks, then used bounded examples to follow suspicious activity across endpoint, shell-history, syslog, network, proxy, and SMB sources. The JSON/NDJSON inventory found no parsing failures, and the Windows XML files parsed successfully. Counts above refer to records in the supplied files, not inferred full-fleet production volumes.

A same-host eCAR identity check found **zero** records referencing a visibly terminated process more than two seconds after its termination, and **zero** process creations more than two seconds after the referenced visible logon session's logout. The reference check covered `actorID` and `source_process_uuid` where supplied; it does not prove that every possible relationship is represented. A separate check found no references to a visibly created source process more than two seconds before its creation. These results support internal coherence and are not scored as synthetic merely because they match well.

### F1 — File analysis contradicts its own byte accounting

**Priority P1; category `hard_contradiction`.** The consequential row is reproducible by selecting `fuid == "FZgEgCqVzTxAGQgCiu"` from `zeek-core/files.json`.

| Field | Observed value |
|---|---|
| Timestamp | `1793643515.43716` / `18:18:35.437160 UTC` |
| Source | `SMB` |
| File | `Integration\DB-Staging\rpt_0318.sql.gz` |
| Connection | `CjC6URGfRxvboYEdC2` |
| Bytes | `seen_bytes=0`, `total_bytes=0`, `missing_bytes=0`, `overflow_bytes=0` |
| Duration | `0.000002` seconds |
| MD5 | `764c0b9cf699b8690bc946daddb4a123` |
| SHA256 | `4762093d05edb921cef281ceae02e73c226c0ce5aa96227505c6aaadca440ace` |

Zeek defines `seen_bytes` as bytes delivered to its file-analysis engine, and its hash fields as digests of file contents. Those meanings are documented in the primary [Zeek Files::Info reference](https://docs.zeek.org/en/current/scripts/base/frameworks/files/main.zeek.html#type-Files::Info). A zero-byte analyzed stream cannot yield the displayed digests; calculating the empty-content digests with Python's standard `hashlib` reproduces the mismatch.

Companion evidence narrows the issue. `zeek-core/smb_files.json` lines 180–181 show FILE_OPEN then FILE_WRITE on the same tuple and file, with `size=0`. `zeek-core/conn.json` line 10983 is an SF SMB connection from `10.10.2.30:45723` to `10.10.2.21:445`, with 2,326 originator bytes and 2,361 responder bytes. `FILE-LNX-01/ecar.json` line 1314 records the destination WRITE by `svc_mhsync` at `18:18:36.845`. The endpoint can legitimately observe an empty-file operation; that does not explain a sensor-computed non-empty-content hash.

This defect is localized: streaming all three sensors' `files.json` files found one zero-seen-byte/non-empty-hash record, among 684 core, 15 database, and 1,789 DMZ file records. I therefore do not claim a dataset-wide file-analysis failure. A custom enrichment pipeline that injects known-file hashes could explain the fields, but no provenance marker distinguishes such enrichment from the listed native analyzer results. That alternative reduces certainty about origin, without resolving the delivered record's semantics.

### F2 — Mac command timing has a shared arithmetic signature

**Priority P2; category `distribution_texture`.** The two Macs execute a rotating pool of 11 routine commands: identity/OS queries, `pwd`, listing and sizing the Documents directory, disk/process listings, PDF search, interface listing, and directory-user enumeration. Repetition alone could be normal diagnostics. The matching interval progression is the stronger issue.

The following table uses native ES exec timestamps, selecting local-shell children and separating SSH and the remote-session commands. Mac 01's relevant local shell is PID `42173`; Mac 02 uses its visible Terminal/iTerm shell lineages. Values are seconds between the first and second, then second and third exec in each group.

| Group | Mac 01 first exec | Mac 01 intervals | Mac 02 first exec | Mac 02 intervals |
|---|---|---|---|---|
| 2 | `13:48:56.636518` | 30.008260, 49.993990 | `14:11:50.346991` | 30.006686, 50.007163 |
| 3 | `14:37:57.665636` | 37.001127, 52.000529 | `14:51:46.634541` | 37.006997, 51.996254 |
| 4 | `15:23:11.240484` | 43.991199, 54.000075 | `15:31:22.671071` | 44.004047, 53.995181 |
| 5 | `16:34:17.954572` | 51.007739, 55.991521 | `16:45:41.063556` | 51.008111, 55.991607 |
| 6 | `17:26:16.209358` | 57.999773, 58.002392 | `17:32:35.712114` | 57.992309, 58.011095 |
| 7 | `18:11:56.671052` | 65.005710, 59.999305 | `18:24:29.813860` | 65.008429, 60.000112 |

For example, Mac 01's group 2 is `pwd` → `ls` → `du` at ES lines 33, 36, and 39. Mac 02's group 2 is `ls` → `du` → `df` at lines 52, 55, and 58. This keeps the same timing formula while shifting the command cycle. Later examples include Mac 01 ES lines 119/122/125 and Mac 02 lines 149/152/155. The respective `zsh_history/maya.ross.zsh_history` files show the matching integer-second gaps.

The same user operates both hosts, so a shared diagnostic routine is a real alternative. Interactive zsh parents do not exclude shell functions or terminal automation. However, the arithmetic growth across different command combinations is stronger evidence of a generated baseline than ordinary repeated maintenance commands. I count the timing and cycling as one related finding rather than inflating them into independent defects.

### F3 — Windows SSH launch timing corroborates deterministic texture

**Priority P2; category `distribution_texture`.** In native Sysmon Event 1, subtract parent `UtcTime` from child `UtcTime`, matching `ParentProcessGuid` to `ProcessGuid`. Four Aisha-to-LOG-MON pairs yield exactly 4.460 seconds; their parent PIDs are `5224`, `5364`, `5336`, and `5976`. eCAR independently retains the relationship, with millisecond-scale source differences.

There is a smaller corroborating pattern on `WS-MCHEN-01`: two LOG-MON pairs at `15:20:06.340` and `17:44:05.102` have the same 3.092-second native delay; two MAIL-EDGE pairs at `15:41:34.160` and `18:13:21.920` have the same 3.952-second delay. These delays are not impossible. Target-specific wrappers or user automation remain possible, so this finding is secondary to F1 and F2.

### Operational hunting pivots and platform boundaries

The database activity is technically plausible through most of its visible sequence. On `DB-PROD-01/syslog.log`, lines 242–244, the incoming root connection from `10.10.2.30:43357` is followed by accepted password authentication and PAM session opening. Endpoint process creation follows with `-bash`, export, compression, and transfer. `bash_history/root.bash_history` includes `mysqldump ... > /tmp/rpt_0318.sql`; the process record omits the redirection, as expected for the invoked executable's argv. I did not execute or decode any command as an instruction.

The scp connection `10.10.4.10:60883 → 10.10.2.30:22` appears at `18:15:42` in both core and database sensor connections, with independently represented sensor IDs and nearly matching durations around 28.93 seconds. On `APP-INT-01/ecar.json`, lines 834–838, the target records sshd, root login, file creation at `18:16:12.105`, process exit, and later logout. These observations make the pivot feasible. The later SMB file-hash inconsistency is a distinct defect and should not erase the validity of the preceding SSH evidence.

The Windows archive upload also provides a viable hunt pivot. `WS-AJOHNSON-01/ecar.json` line 1109 creates curl PID `6164` at `18:24:56.222`. Proxy lines 3527–3528 at `18:25:00` pair CONNECT with an inspected POST using tunnel ID `PT-f3f0c6bb74930871` and client source port `61235`. `zeek-core/conn.json` line 11212 and `http.json` line 2138 expose that tuple and CONNECT. The measured byte sums distinguish control messages from tunnel traffic sensibly. This is positive realism evidence, not a synthetic indicator based on complete matching.

On the Macs, ES exec target audit tokens, parent tokens, POSIX session IDs, and process start times require different interpretation. An exec changes the image and `pidversion` while preserving the process lifetime; a fork is a new process. Mac 01's local login uses audit session `100001`, while its incoming SSH shell PID `64391` uses `100002` and UID 501. The SSH root monitor and privilege-separated authentication process have different credentials from the user's shell. I found no basis to demand one shared namespace with Windows directory logon IDs.

Mac 01's Unified Log policy message at `15:41:59.392044` names `MeetingAssist` PID `62474`. That message alone establishes neither successful execution nor the effects of an app or launch item; I do not infer those effects. Unified Log timestamps and normalized endpoint timestamps also have collection/observation differences, so small cross-source timing offsets are not treated as proven impossible ordering.

### Source mix and limits

The supplied source mix supports real hunting: failed and successful authentication, service/system activity, cron processes, varied TCP states, DNS, certificates, DHCP, SMB, mail, scanning, and web/proxy activity coexist. Connection states vary substantially: core Zeek includes 10,124 SF, 1,898 S0, 154 RSTO, 75 RSTR, 46 REJ, and smaller partial/other populations. No TCP SF record in the three connection files had fewer than two packets in either direction in the bounded accounting check.

Identical scheduled `debian-sa1` counts across several Linux hosts are not scored: shared deployment and cron schedules can produce them. Sparse Unified Log export, selected Sysmon types, missing facilities, sanitized domains, filesystem copy timestamps, and out-of-window initiators/terminators are likewise not used as authenticity clues. No score component is based on narrative linearity, attack completeness, missing attacker mistakes, or perfect source matching.

The P1 finding is a record-semantics contradiction; F2/F3 are distribution evidence with automation alternatives. This combination warrants the 81–100 rubric band, while the localized scope of the hard defect, otherwise strong lifecycle modeling, and possible enrichment/automation explanations keep the score near the bottom of that band.

## Synthetic Indicator Summary

| Finding | Priority | Category | Affected source family | Scope | Effect on score |
|---|---|---|---|---|---|
| F1: Zero seen/total bytes with non-empty content digests | P1 | `hard_contradiction` | Core Zeek files; corroborating SMB metadata | One file record of 2,488; one SMB write | Strongest evidence: inconsistent native analyzer results, subject to an undocumented enrichment alternative |
| F2: Shared arithmetic inter-command gaps | P2 | `distribution_texture` | Mac native ES and zsh history | Six matched groups on each of two hosts; 24 intervals | Strong timing fingerprint across shifted command cycles; shared automation remains possible |
| F3: Exact repeated shell→SSH delays | P2 | `distribution_texture` | Windows Sysmon; eCAR corroboration | Four Aisha LOG-MON launches; two repeated Marcus target pairs | Secondary evidence that timing reuse extends beyond Mac telemetry |

## Realism Score by Category

- **Field format accuracy:** 8 — JSON/XML parse cleanly and platform-specific structures are convincing; F1 violates file-analysis field semantics.
- **Temporal patterns:** 5 — Lifecycle ordering is generally sound, but Mac arithmetic spacing and exact repeated Windows launch delays are conspicuous.
- **Cross-source correlation:** 8 — SSH, endpoint, proxy, and byte-accounting pivots work; the isolated SMB file-analysis inconsistency limits trust.
- **Behavioral realism:** 6 — Administrative activity and suspicious commands are technically plausible, but routine Mac command cycling has weak organic variation.
- **Environmental consistency:** 8 — Host roles, segments, local/directory identity distinctions, and varied source mix generally agree with visible activity.

## Recommendations

- If this were synthetic, make file-content identity and byte accounting share the same truth: a zero-byte file must use empty-content hashes or omit hashes that were not calculated. Mark externally enriched hashes separately from native analyzer output. F1 provides a concrete regression example.
- If this were synthetic, remove the shared arithmetic timing progression from Mac interactive command groups. Preserve deliberate automation when intended, but represent its actual ownership and schedule; vary human command choices and spacing without the same rotating pool and index-based interval formula across hosts.
- If this were synthetic, avoid replaying one target-specific parent→SSH delay to exact millisecond precision across separate interactive launches. Where a real wrapper or automated routine is intended, make the visible process lineage or command invocation support that interpretation.
- Preserve the good behaviors already visible: separate exec transitions from process lifetimes on macOS, retain audit versus POSIX session distinctions, preserve shell redirection in history rather than executable argv, maintain `/netonly` local identity semantics, and keep proxy control/tunnel byte scopes consistent.
