# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 93
**Synthetic-Confidence Score:** 82

## Executive Summary

Most endpoint relationships are convincing: Windows process identities, session ownership, Linux SSH sequences, and macOS fork/exec lifetimes survive direct checks. The decisive exception is a repeated reversal of newly allocated native macOS audit identity versions on MAC-MROSS-02; its timestamps, monotonic clock, sequence numbers, and process start times all establish the order, while the identity allocator runs backward in several blocks.

## Evidence For Synthetic

- [hard_contradiction] `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson`, lines 44–47: a new launchd child PID 29633 is assigned `event.fork.child.audit_token.pidversion=69` at `2026-11-02T14:22:52.776507000Z`, then exec versions 70 and 71. A later new launchd child PID 30060 is assigned version **47** at `14:24:42.387235000Z`. This is not an old process being observed again: both records contain newly forked children with matching new `start_time` values. The same problem recurs at lines 80–82 (new fork version 84, later new fork version 72), 101–105 (95, later 88), and 117–120 (111, later 97). Apple's published XNU implementation allocates fork and exec identity versions from one incrementing host-wide counter, rather than a separate counter per process tree. [Apple fork implementation](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.1.9/bsd/kern/kern_fork.c#L924), [Apple exec implementation](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.1.9/bsd/kern/kern_exec.c#L6630).
- [distribution_texture] The identity values also form compact, gapless inventories of only the displayed new fork/exec identities: all 109 new identities on MAC-MROSS-02 occupy versions 10–118 exactly; all 87 on MAC-MROSS-01 occupy 10–96 exactly. I treat this as corroborating texture of the same identity-allocation problem, not a second independent major defect or a penalty for complete source matching.

## Evidence For Real

- Windows process metadata is internally strong. Across ten Windows hosts, 894 of 895 Sysmon Event 1 records have a Security 4688 record with the same PID, executable path, and command line. For example, `WS-MCHEN-01.../windows_event_sysmon.xml:427` records PID 7192, `mstsc.exe /v:MAIL-FIN-01`, parent explorer PID 6604 and user `MERIDIANHCS\marcus.chen` at `13:12:22.9249055Z`; `windows_event_security.xml:821` records the same child as `0x1c18`, parent `0x19cc`, command, and user at `13:12:23.0079864Z`.
- A systematic Windows GUID check found no visible uses before a recorded creation or after a recorded termination, including source, target, and parent references. Referenced images agreed with the creation record where a visible creation existed; repeated executable/path/version pairs had stable hashes within each host.
- The Windows collection includes several session kinds rather than only attacker-friendly authentication: 405 Type 5, 382 Type 3, 15 Type 10, eight Type 7, seven Type 2, and three Type 9 successful logons. `WS-MCHEN-01.../windows_event_security.xml:21957` and `:25756` show workstation lock/unlock at `18:04:45.7065290Z` and `18:53:45.5926181Z`.
- `DB-PROD-01.../syslog.log:44–47` records connection, password acceptance, PAM open, then logind registration for lina.nguyen; `:66–67` closes the same sshd PID 1048269 and session 277109 around 50 minutes later. Later public-key sessions reuse user-specific fingerprints without reusing the sshd PID.
- macOS process lifetimes distinguish fork from exec and preserve process start time through image changes. `MAC-MROSS-01.../macos_endpoint_security.ndjson:1–7` follows launchd → xpcproxy → Terminal, then a separate login child and shell grandchild. The login target's `st_mode=35181` includes setuid, accompanying its transition from effective UID 501 to 0; the subsequent shell uses UID 501.
- The two Mac terminal implementations differ plausibly. MAC-MROSS-01 uses Terminal and `login -pf`; MAC-MROSS-02 uses iTerm, iTermServer, and `login -fpl ... ShellLauncher --launch_shell`. Browser helper roles and persistent shells are represented separately from short commands.

## Detailed Analysis

### Provenance and method

I read the full neutral briefing `/private/tmp/log-study-6xx3sa0s/host-prompt.md` and examined files only within its supplied `data` directory. I did not open project files, scenarios, implementation files, previous reports, parent inventories, or other reviewers' output. Generic inherited project operating instructions were an environment limitation and were not used as origin evidence. The only external material consulted was public documentation/search results concerning native Apple audit-token behavior; the technical conclusion uses Apple's own published XNU source.

I parsed all Windows Security/Sysmon XML, all endpoint eCAR NDJSON, and both Mac Endpoint Security streams, then inspected individual records and Linux histories/syslog. Commands in logs were treated as inert text. XML citations point to the opening `<Event>` line; NDJSON and syslog citations use physical line numbers. Paths abbreviated with `...` retain the complete host prefix and refer to the named file under the supplied directory.

The displayed activity principally covers `2026-11-02 13:00–19:00 UTC`. Pre-window starts and post-window survival were accepted. I did not score selected-out Sysmon types, sparse Unified Log coverage, absent sources, perfect matching, suspicious-activity linearity, or sanitized names/domains.

### macOS native identity allocation

The Mac streams declare `schema_version=1` and Endpoint Security message `version=11`. I do not infer an exact OS build from that alone, and do not allege unfamiliar version-specific entitlement or serialization fields are wrong.

The high-impact finding concerns an established kernel identity invariant, rather than an assumed application workflow. In the cited XNU source, a new fork receives a version by incrementing shared `nextpidversion`; exec updates identity using that same counter. These are host-wide identities, not per-parent lineage numbers. The observed fork-to-fork reversals therefore stand without relying on how an exec notification describes its source image. [Apple fork implementation](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.1.9/bsd/kern/kern_fork.c#L924), [Apple exec implementation](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.1.9/bsd/kern/kern_exec.c#L6630).

All following rows are from `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson`:

| Line | UTC time | Event and newly assigned identity | Version | Global sequence | mach_time |
|---|---|---|---:|---:|---:|
| 44 | 14:22:52.776507 | fork child PID 29633 | 69 | 43 | 56106546636168 |
| 46 | 14:22:52.787475 | exec target PID 29633, Zoom | 71 | 45 | 56106546899400 |
| 47 | 14:24:42.387235 | fork child PID 30060 | 47 | 46 | 56109177293640 |
| 80 | 15:00:21.710528 | fork child PID 38957 | 84 | 79 | 56160521052672 |
| 82 | 15:23:41.846670 | fork child PID 41771 | 72 | 81 | 56194124320080 |
| 101 | 16:05:46.686677 | fork child PID 45878 | 95 | 100 | 56254720480248 |
| 105 | 16:25:23.065029 | fork child PID 47721 | 88 | 104 | 56282953560696 |
| 117 | 17:12:27.393377 | fork child PID 52334 | 111 | 116 | 56350737441048 |
| 120 | 17:19:29.440742 | fork child PID 53037 | 97 | 119 | 56360866577808 |

These are substantial time gaps with increasing monotonic clocks and global source sequence numbers. Clock adjustment, delivery order, an inherited older parent's token, or an old process surviving the window does not explain a lower version on the newly born child. Repeated counter wrap is not credible for these small orderly value blocks and intervals. I counted 24 fork-child assignments below a previously observed new-identity high-water value; including exec targets, 53 of the 109 new identities fall below a prior high-water value.

The strongest alternative explanation is that an exporter or sanitizer deliberately rewrote audit identity versions without preserving their allocator semantics. That would allow production ancestry for the underlying activity but would still mean the displayed native identity fields are transformed. No such transformation is documented in the supplied briefing; confirmation of it would materially reduce my authenticity confidence.

The issue is localized: MAC-MROSS-01's new versions are chronological. Both Macs passed a separate PID-plus-start-time check for visible source-process use after exit, and repeated `(st_dev, st_ino)` file identities did not switch paths or sizes. Those successful checks are meaningful counterweight, but they do not repair the second Mac's native counter.

### Windows processes, sessions, and correlation

The 895 Event 1 records across the ten Windows hosts are not merely cleanly formatted. Image, creator, principal, command, and child PID relationships agree across independent-looking source representations. The lone record without an exact Security creation match is DC-01 Sysmon Event 1 at `windows_event_sysmon.xml:36136`, PID 3944, dllhost at `14:12:02.1940901Z`; I treat one missing observation as neutral.

Parent/child roles generally fit the visible environment: DCOM svchost parents WmiPrvSE and dllhost; services.exe parents service hosts; interactive explorer parents user tools; administrative mstsc and OpenSSH clients belong to named user sessions. No repeated in-host binary hash instability appeared in the checked path/version pairs. I found no Sysmon activity tied to a LogonId after that same host's visible 4634. Processes and sessions beginning before collection were not classified as missing initiators.

### Linux and macOS session semantics

The Linux logs mix normal periodic cron/anacron maintenance, varied sudo operations, failed authentication, preauth closes, and successful SSH sessions. For example, `DB-PROD-01.../syslog.log:135–138` uses sshd PID 1074759 for marcus.chen's `16:18:37` public-key login and session 278313; `:154–155` closes both around `17:10:16–17`. That is a plausible sustained admin session, not an unpaired one-row login.

The Mac policy line is handled conservatively. `MAC-MROSS-01.../macos_unified_log.ndjson:2` says the policy would not allow MeetingAssist PID 62503 at `15:42:11.450696Z`; the Endpoint Security stream does not show a successful exec target for that app. I did not infer success, child execution, or command effects from the policy message. Likewise, sparse loginwindow/SSH Unified Log extracts were not treated as complete native session logs.

Short-command durations vary, with occasional long cases: MAC-MROSS-01 ES lines 82–83 show `/usr/bin/id` lasting about 88 seconds. Directory-service delay or blocking could explain that individual occurrence, so it did not independently affect the score. Repeated `cat` reads of Office documents on MAC-MROSS-02 are unusual but possible binary inspection; I did not elevate those impressions into an authenticity defect.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the score |
|---|---|---|---|
| hard_contradiction | macOS Endpoint Security audit identities | MAC-MROSS-02; repeated new fork/exec version blocks | New native identities move backward despite later start times, increasing mach clock, and increasing global sequence. This is the decisive indicator. |
| distribution_texture | macOS Endpoint Security audit identities | Both Macs; 87 and 109 new identities | Gapless small identity inventories reinforce the allocation artifact; corroborating only, not counted as a separate major defect. |

## Realism Score by Category

- **Field format accuracy:** 7 — Parsing and most source-native structures are convincing; native audit identity allocation is materially wrong on one Mac.
- **Temporal patterns:** 7 — Lifetimes and session timing hold up, but the Mac identity chronology contradicts native allocation order.
- **Cross-source correlation:** 9 — Strong PID, command, image, logon, and lifecycle consistency in the checked endpoint sources.
- **Behavioral realism:** 8 — Distinct terminal implementations, interactive tools, maintenance, and sustained administration are plausible.
- **Environmental consistency:** 8 — Windows, Linux, and Mac records generally fit their inferred platforms and roles; the main defect is identity construction rather than software placement.

## Recommendations

- If this were synthetic, allocate native Mac audit identity versions in actual chronological fork/exec order using a shared host counter. Preserve the assigned values in subsequent source-process, parent, responsible-process, exit, and normalized EDR references.
- If these fields were intentionally sanitized, document that transformation and preserve the counter's ordering semantics during remapping. The current values invite a justified native-telemetry contradiction finding even when the process trees themselves are sound.
- Test newly assigned fork-child and exec-target identities against event time and monotonic clock, separately from ordinary process references. A check that merely verifies PID lifetime consistency will miss the demonstrated backward allocation blocks.
