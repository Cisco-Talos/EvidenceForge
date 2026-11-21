# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 79
**Synthetic-Confidence Score:** 64

## Executive Summary

The host evidence is substantially credible in its process identity, lifecycle, and authentication relationships, and I did not demonstrate an impossible visible process lifecycle. However, multiple groups of separate shell-command forks preserve exactly the same microsecond fraction across irregular, whole-second intervals on both Macs, with a related timing pattern in Windows Sysmon; this is a concrete execution-timing fingerprint supporting a qualified synthetic verdict.

## Evidence For Synthetic

- [distribution_texture] In `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson`, lines 35, 38, 41, and 44 record shell forks at `13:48:41.198588000Z`, `13:49:08.198588000Z`, `13:49:43.198588000Z`, and `13:50:02.198588000Z` on November 2. These become separate curl, bash, ls, and id commands, all children of zsh PID 25529. The intervals are 27, 35, and 19 seconds, yet the microsecond fraction is identical. Lines 55, 58, and 61 repeat this structure at `14:37:50.487145000Z`, `14:38:28.487145000Z`, and `14:38:57.487145000Z` for bash, `cat /etc/resolv.conf`, and `cat /etc/hosts`.
- [distribution_texture] The same pattern occurs independently in `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson`, lines 86, 89, and 92: `15:30:55.965208000Z`, `15:31:17.965208000Z`, and `15:31:58.965208000Z`. Separate dscl, find, and du commands fork from zsh PID 88255, with 22- and 41-second gaps and exactly identical microseconds. Across the two files, 10 of 56 forks whose parent image is a shell belong to these three repeated-fraction groups. This is the principal indicator; it is not a claim that activity is suspicious because its narrative is compact.
- [distribution_texture] `WS-MCHEN-01.meridianhcs.local/windows_event_sysmon.xml` gives three separate process creations `UtcTime` values `2026-11-02 14:45:35.733`, `14:46:18.733`, and `14:47:17.733`, for the connector-check download, its execution, and `ipconfig.exe /all`. Millisecond equality is weaker than the Mac evidence, but the uneven whole-second spacing with a retained fractional anchor resembles the Mac clusters. Security 4688 timestamps for these activities are distinct (`14:45:35.8597994Z`, `14:46:18.8548633Z`, `14:47:17.9073367Z`), so the effect is not simply the entire export being rounded to seconds.

## Evidence For Real

- Process lifecycles are coherent in the checks performed. Across 23 eCAR files containing 37,414 rows, I checked references to visible process creations and terminations, including actor references, and found no use before a matching visible creation or after its visible termination. This consistency supports technical realism, although it cannot establish provenance.
- All ten Windows Sysmon files passed corresponding GUID-based checks for own-process, parent-process, and source/target-process references against visible creation and termination. Repeated Event 1 instances of a given image within each host did not show divergent hash strings.
- A concrete Windows match: on WS-MCHEN, Sysmon Event 1 records BITS host PID 7192, parent services.exe PID 5872, `svchost.exe -k netsvcs -p -s BITS`, SYSTEM, and LogonId `0x3e7` at `13:01:29.419`. Security 4688 at `13:01:29.5058694Z` records the same image, command, new PID `0x1c18`, and parent PID `0x16f0`; eCAR records PID 7192/PPID 5872 at epoch milliseconds `1793624489523`.
- APP-INT SSH evidence contains an ordered transport/authentication/session sequence. Its syslog lines 82–85 show connection from `10.10.1.31:50990` at `14:29:07.365583Z`, public-key acceptance for marcus.chen at `14:29:12.645249Z`, PAM opening at `14:29:12.747346Z`, and logind session 183 at `14:29:13.256698Z`. eCAR's login preserves the user, source tuple, and session 183.
- The Mac records distinguish fork from exec and preserve a process lifetime across successive images. MAC-MROSS-01 PID 25527 progresses from inherited launchd to xpcproxy to Terminal; PID 25528 becomes login and forks PID 25529, which becomes zsh. MAC-MROSS-02 instead includes iTermServer and ShellLauncher in its local terminal chain.
- Native Mac file metadata is internally stable in the examined records. Grouping file objects by device/inode found 33 identities on MAC-MROSS-01 and 34 on MAC-MROSS-02, without conflicting size/birthtime pairs for those identities.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory, using the raw entries and local parsing. The endpoint review covered all 23 eCAR streams, all ten Windows Security and Sysmon pairs, Linux syslog and shell-history samples, and both Mac Endpoint Security, Unified Log, and zsh-history sets. The eCAR streams contain 2,574 PROCESS/CREATE and 2,426 PROCESS/TERMINATE rows. Their time range is approximately six hours on November 2, 2026, from 13:00 to 19:00 UTC.

Lifecycle checks used stable process identifiers, not PID alone. A process with a creation outside the window was not counted as defective. I also did not count unlock 4624 Type 7 rows as the initiating creation of an existing interactive session: doing so would incorrectly turn legitimate pre-unlock activity into a causality finding. Native documentation was not consulted outside the permitted evidence directory, so unfamiliar version-specific Mac details are not alleged as schema defects.

### Timing fingerprint

The Mac evidence is stronger than ordinary repeated millisecond timestamps. In the first cluster, four different subprocesses begin at different wall-clock seconds but share `.198588`; their subsequent execs have different fractions. For example, PID 34639 forks at `14:37:50.487145000Z`, then execs bash at `14:37:50.504588000Z`. PID 34723 forks at `14:38:28.487145000Z`, then execs cat at `14:38:28.502088000Z`. Thus the raw file retains timing detail, and the matching fork fractions are not explained by universally coarse timestamp resolution.

The zsh histories identify the same commands at the corresponding epoch seconds. They do not show a surrounding script invocation that explains why independently observed shell forks should be phase-locked to the microsecond across irregular intervals. Automation or a timestamp-transforming collection pipeline remains possible; the data alone cannot exclude either. The repetition across three groups and two hosts nevertheless favors a shared timestamp-construction mechanism. I therefore assign meaningful weight to this distribution artifact without calling it an impossible event or treating it as three unrelated defect classes.

### Windows process and authentication realism

The process trees exhibit plausible functional distinctions. WS-MCHEN and WS-AJOHNSON have PowerShell/SSH and remote-administration activity, while ordinary workstation application launches include browsers, Outlook, VPN clients, and update agents. Server process creation is dominated by service-host, WMI, task-host, COM-host, and console-host activity rather than copying the workstation application mix.

Authentication also varies by host. DC-01 has visible Type 3, Type 5, and Type 10 logons; WS-MCHEN additionally has Type 2, Type 7, and Type 9 entries. Lock/unlock evidence and retained identifiers are compatible with continuing sessions. No missing pre-window logon, process, or closing event was used as a synthetic indicator. Observed Sysmon/4688 count differences were not treated as contradictions because source selection and observation can differ.

### Linux endpoint realism

The supplied Linux logs include SSH acceptance/PAM/logind sequences, sudo command/open/close groups, cron execution, DHCP renewals, and service-specific background entries. APP-INT's SSH tuple and session-number agreement is concrete positive evidence. WS-LNGUYEN's DHCP entries also progress plausibly: a bound message at `13:01:19.740490Z` advertises renewal in 1,885 seconds, followed by the next bound message at `13:32:45.929888Z`, approximately that interval later.

Some NetworkManager rows provide only `disconnected -> prepare` and `ip-config -> activated` transition shapes. I did not score their intermediate omissions as a defect because an export or collection filter could retain only selected message shapes. Likewise, commands that query nonexistent or alternate services are not proof of an impossible environment; administrators routinely make such queries.

### macOS lifecycle and policy interpretation

The native Mac files declare message version 11. I kept native ES observations separate from normalized eCAR evidence and interpreted the multiple exec images of a single PID as one process lifetime. I also kept audit-session identifiers separate from normalized logon identifiers.

MAC-MROSS-01's Unified Log contains the `ASP: Security policy would not allow process` message at `15:42:09.009673Z` for MeetingAssist PID 42008. I found no native successful execution of that PID in the supplied ES sequence and did not infer successful command effects from that message. The eCAR plist creation/removal entries for the endpoint-inventory LaunchDaemon were not treated as proof of either immediate activation or immediate termination. These distinctions avoid manufacturing a policy or launch-service contradiction from different lifecycle stages.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | macOS Endpoint Security | Three irregularly spaced command-fork clusters; 10 of 56 shell-parent forks across two hosts | Principal evidence: repeated exact microsecond fractions despite distinct commands and independently varying exec times |
| distribution_texture | Windows Sysmon | Three WS-MCHEN process creations over 102 seconds share `.733` | Corroborates retained-anchor timing, with lower weight because millisecond collisions are easier to explain |

These are related manifestations of one timing concern, not independent hard contradictions. I found no demonstrated hard contradiction in the lifecycle checks. That limits the score to the low end of the likely-synthetic range.

## Realism Score by Category

- **Field format accuracy:** 9 — Windows and normalized endpoint fields are detailed and internally plausible; no demonstrated native schema contradiction.
- **Temporal patterns:** 6 — Most lifecycle ordering is credible, but repeated microsecond phases across separate command forks are a substantial tell.
- **Cross-source correlation:** 9 — Checked Windows process identities and Linux SSH/session relationships agree with distinct source observation times.
- **Behavioral realism:** 8 — Endpoint tools and service activity vary with apparent workstation, administration, and server use.
- **Environmental consistency:** 8 — The mixed-platform environment is largely coherent; collection scope limits stronger conclusions about source completeness.

## Recommendations

- If this were synthetic, change the timing construction for the three identified Mac shell-command clusters so each actual fork derives its own execution time. Preserve meaningful command sequencing and measured scheduling latency rather than copying one microsecond fraction through integer-second offsets.
- If this were synthetic, inspect the corresponding WS-MCHEN Sysmon command-creation timing for the same retained-fraction mechanism. Keep source-native event time and Security/eCAR observation delays distinct, as the records already largely do.
- If the repeated fractions instead come from a collection transformation or orchestration system, retain its provenance separately so an analyst can distinguish that documented behavior from endpoint clock behavior. The log-visible concern is the fractional-time pattern itself; additional source volume or more attack steps would not resolve it.
