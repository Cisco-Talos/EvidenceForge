# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 84
**Synthetic-Confidence Score:** 65

## Executive Summary

The endpoint records have strong process identity, platform separation, and session detail, but the macOS command timing repeatedly preserves identical fractional seconds across separate commands. This repeated timestamp arithmetic, together with a narrow and unusual document-access process pattern, makes synthetic origin more likely; I did not establish an impossible process lifetime or a native schema contradiction.

## Evidence For Synthetic

- [distribution_texture] Separate shell commands repeatedly fork at exactly the same fractional second despite gaps of tens of seconds. In `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson`, lines 32, 35, and 38 report zsh forks at `13:48:48.715405000Z`, `13:49:18.715405000Z`, and `13:50:08.715405000Z`; their respective exec records run `pwd`, `ls`, and `du`. Lines 49, 52, and 55 repeat this with fraction `.314210000`, and lines 127 and 130 with `.126535000`. Across both Macs, 35 of 55 zsh fork records belong to 15 groups sharing an exact fractional second. This is a substantial repeated event-time texture, not merely complete collection or regular scheduled-task cadence.
- [distribution_texture] The same timing construction affects an SSH shell as well as local shells: `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson` lines 61, 64, and 67 have PID 30083 forking at `14:26:53.627715000Z`, `14:27:06.627715000Z`, and `14:27:39.627715000Z`, followed by `id`, `sw_vers`, and `find` execs. Local PID 18979 has analogous groups at lines 120/123/126 and 138/141/144. Actual exec timestamps have variable millisecond offsets, but the preceding independent forks preserve the phase exactly.
- [distribution_texture] The explicitly recorded Mac shared-document accesses use a very small CLI mapping across diverse formats. `MAC-MROSS-01.meridianhcs.local/ecar.json` lines 80 and 261 attribute writes of `.pptx` and `.xlsx` documents to `tee`; lines 122, 165, and 200 attribute `.xlsx`/`.pdf` reads to `cat`. The second Mac repeats `cat` for a PDF and spreadsheet at lines 401 and 506. These are possible commands, but the repeated process-to-document mapping is unusual for the visible desktop application environment. This is supporting behavioral texture, not proof that the files could not be accessed this way.

## Evidence For Real

- Windows process identities and lifetimes are coherent in the parsed records. For example, `WS-AJOHNSON-01.meridianhcs.local/windows_event_sysmon.xml` around lines 54–105 shows PID 5204, `taskhostw.exe`, created at `13:06:37.575` and terminated at `13:06:53.073` with the same ProcessGuid `{fd907e59-8add-6ae8-0702-000094a4144b}`. Its parent is a SYSTEM `svchost.exe` instance, a plausible task-host relationship.
- A scan of all ten supplied Windows Sysmon files found no overlapping visible Event 1 lifetimes for the same PID and no changing hashes for a repeated exact executable path within a host. This does not prove authenticity, but it removes common endpoint inconsistencies.
- Linux SSH logs contain layered, sensibly ordered authentication evidence. `DB-PROD-01.meridianhcs.local/syslog.log` lines 8–11 progress from connection, to public-key acceptance for `aisha.johnson`, to PAM session opening, to systemd-logind session 276589, while preserving source `10.10.1.35:59353` and sshd PID 1044253.
- Mac process records distinguish fork from successive exec images. `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson` lines 1–7 retain PID 42169 through launchd/xpcproxy/Terminal images and then model separate login and zsh children. The second Mac models a different iTerm/ShellLauncher path rather than applying the same Terminal tree mechanically.
- The macOS policy rejection at `MAC-MROSS-01.meridianhcs.local/macos_unified_log.ndjson:2` names MeetingAssist PID 62501, but the supplied ES stream does not claim successful exec of that image or children from that denied attempt. I found no visible denial-versus-execution contradiction.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory, parsed all ten Windows Security and ten Sysmon XML files, inspected all endpoint eCAR streams, and read both Mac ES streams plus representative Linux syslog and shell history. The dataset contains 23 endpoint eCAR streams. I treated collection-window boundaries, source selection, sanitized names, and absent optional sources as neutral.

My strongest finding is concentrated in native-looking Mac process timestamps. It does not imply that all endpoint families are defective.

### Process trees, identities, and hashes

The Windows records contain differentiated service, user, and maintenance activity rather than merely explorer-spawned command tools. The sample taskhostw process has System integrity and a service-host parent; GoogleUpdater is parented by services.exe. User activity includes browser, office, and other application processes. The per-host Event 1/5 PID check found no visible concurrent PID reuse, and repeated exact image paths had stable hash strings.

An actor-ID check across the eCAR streams found no rows using a process actor after that actor's visible TERMINATE timestamp. I did not treat an absent pre-window parent or an unclosed final process as an error.

On macOS, fork records preserve inherited executable state while exec records supply a target image and changed pidversion. eCAR uses PROCESS/MODIFY for successive images under the same process object identity; those are not duplicate process births. Per-host ES executable `(st_dev, st_ino)` references were consistent with their path and stat snapshots in the inspected streams.

### Repeated fractional-second command starts

The exact-fraction groups are reproducible by selecting ES records with `event.fork` and `process.executable.path == /bin/zsh`, grouping their `time` strings by fractional second. There are 26 such records on MAC-MROSS-01 and 29 on MAC-MROSS-02. Sixteen and nineteen records, respectively, fall into groups of two or three having the same fractional second.

For example, the first Mac's `pwd`, `ls`, and `du` children originate 30 and then 50 whole seconds apart at exactly `.715405000`. The second Mac's local `du`, `df`, and `ps` children originate at `17:32:54.495937000`, `17:33:42.495937000`, and `17:34:30.495937000`. The SSH command group has a different fraction but the same whole-second offset structure. A script could launch commands at planned intervals, and an exporter could reconstruct timestamps; neither possibility is excluded. However, independent fork notifications retaining exact subsecond phase repeatedly across differently spaced command groups is much stronger evidence of constructed timing than ordinary repetitive user routines.

I did not score the separate fact that native ES time strings end in three zero digits: timestamp precision alone can reflect serialization.

### Document activity

The native exec arguments corroborate the CLI mapping rather than eCAR merely attaching a broad original shell command. For example, the first Mac's ES line 59 has `/bin/cat` with argument `/Volumes/Users/Documents/contacts.xlsx`; line 45 has `/usr/bin/tee` with the PowerPoint path. The second Mac's ES lines 116 and 136 similarly exec cat against a PDF and an XLSX file.

Reading binary documents with cat and writing them with tee is possible. Repetition across a small set of document operations, while graphical Office/browser applications are present, weakens behavioral realism. It receives less weight than the timestamp finding because collection selection, troubleshooting, or scripted testing could explain it.

### Collection interpretation and neutral observations

Several Mac file-access process exits appear in eCAR but are absent from the native ES file. For example, first-Mac eCAR line 123 terminates PID 55151, whose native exec is ES line 59. The native stream has a corresponding global sequence gap before line 60. Similar gaps exist for the other cat/tee exits. I therefore do not allege that these processes remained alive for hours, and I do not count those missing rows as an impossible lifecycle or a scored authenticity defect. Filtering or loss remains a plausible collection explanation.

The three-line Unified Log export on MAC-MROSS-01 is thin, but thinness alone is not evidence. Nor does removal of the inventory plist require an immediately visible unload or process kill. Local and SSH sessions are distinct, and the presence of network observations of a Mac was not treated as native Mac evidence.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | macOS ES process fork timestamps | 35/55 zsh forks, 15 exact-fraction groups across two hosts and local/SSH shells | Primary reason for likely-synthetic range: repeated arithmetic phase across separately timed commands |
| distribution_texture | macOS ES exec and eCAR file/process activity | Repeated cat/tee mapping to shared text, PDF, XLSX, PPTX files | Moderate supporting behavioral tell; individually possible |

No hard contradiction or demonstrated native schema error was established. The score remains below the confidently-synthetic band because much of the endpoint identity and lifecycle evidence is sound, and collection/transformation could explain some artifacts.

## Realism Score by Category

- **Field format accuracy:** 9 — Structured Windows and Mac process fields are detailed and internally consistent in the inspected records.
- **Temporal patterns:** 5 — Repeated exact fractional-second command fork phases are a strong constructed-timing signature.
- **Cross-source correlation:** 8 — Shared process identities, image transitions, and authentication chains are convincing; apparent Mac exit omissions have explicit sequence-gap context.
- **Behavioral realism:** 6 — Diverse application use exists, but repeated cat/tee document handling and repeated command group timing weaken the lived-in appearance.
- **Environmental consistency:** 8 — Windows service parents, Linux session facilities, and differentiated Mac launch paths fit their apparent platforms.

## Recommendations

- If this were synthetic, give each separately initiated shell command its own execution-time variation, including the fork timestamp. Preserve causal fork-before-exec relationships while avoiding repeated exact subsecond phases across commands tens of seconds apart.
- If this were synthetic, model document access with the application or workflow appropriate to the visible operation, reserving cat/tee of binary office documents for an explicit troubleshooting or scripted purpose. Vary the underlying behavior, not merely the filename.
- If this were synthetic, retain the existing strengths: stable process identity, fork/exec separation, plausible authentication sequencing, and explicit sequence gaps where native collection omits events.
