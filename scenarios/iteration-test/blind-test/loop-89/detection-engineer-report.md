# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 57

## Executive Summary

The collection is unusually strong on usable schemas and identity correlation: I found no demonstrated impossible process ordering or broken Zeek companion join in the checks performed. My synthetic verdict rests on a measurable Linux PID distribution artifact repeated across ten independent hosts, rather than attack progression, collection completeness, or missing out-of-window events. The score remains in the mixed band because this is a distribution finding, not a hard source-native contradiction.

## Evidence For Synthetic

- [distribution_texture] Ten hosts expose the same pronounced floor and mode in PID advancement for their recurring sysstat CRON jobs. There are 360 such records, yielding 350 consecutive within-host intervals: 65/350 (18.6%) advance by exactly 940 PIDs, 349/350 advance by at least 940, and every host has +940 as its most frequent increment. This spans workstation, laptop, proxy, mail, application, logging, and file-server roles. In `WS-LNGUYEN-01.meridianhcs.local/syslog.log`, lines 5, 10, and 13 have PIDs 2942994, 2943934, and 2944874 at 13:06:00.101059Z, 13:16:00.159470Z, and 13:26:00.300454Z respectively. `WEB-EXT-01.meridianhcs.local/syslog.log`, lines 27, 72, and 117, similarly has 2694710, 2695650, and 2696590 at 13:06, 13:16, and 13:26. Fixed cron cadence itself is normal; the shared numeric allocation signature across heterogeneous hosts is the concern.

## Evidence For Real

- Windows event contents are readily usable for detection. Security 4624/4625/4634, process 4688/4689, Kerberos 4768/4769/4771, file/share 4656/4658/4663/5140/5145, and Sysmon 1/3/5/7/8/10/11/13/22 contain coherent event-specific fields, rather than generic fields repackaged under different IDs.
- Across all three Zeek sensors, all 14,171 examined DNS, TLS, HTTP, SMTP, SMB-file, and SMB-mapping companion records have a matching connection UID and agree on all supplied endpoint tuple fields. Per-sensor conn UIDs are unique among 24,092 connection rows.
- Exact Sysmon GUID checks found no checked dependent event before its visible process creation or after its visible termination, and no disagreement between the PID on a GUID reference and its visible creation record. This includes source/target references for process access and remote thread events.
- The same Windows process is represented consistently in Security and Sysmon: WS-MCHEN taskhostw PID 7208, parent 5904, appears in Sysmon record 525184 and Security record 948728 with correct decimal/hexadecimal representations and the same image and command.
- Native macOS rows distinguish fork, exec, and exit, retain actor versus exec target identities, and increment PID versions through exec transitions. Unified Log writer paths and message representations are distinct from normalized eCAR network rows. No exact macOS audit token was observed acting after its recorded exit.
- Linux SSH evidence has defensible transport-before-auth ordering and source-specific timing. The WEB-EXT SSH session from `10.10.1.35:61284` is visible at the network sensor and endpoint before its accepted-publickey and PAM-open messages.

## Detailed Analysis

### Scope, parsing, and detection usability

I restricted examination to the assigned data directory and briefing. The collection covers roughly 2026-11-02 13:00–19:00 UTC. I parsed all 19,224 Security XML events, all 12,086 Sysmon XML events, the 39,270 eCAR JSON records, Zeek connection/protocol records, and the 310 native macOS Endpoint Security records; I also inspected representative Linux syslog and all five Unified Log rows. This is a schema and correlation assessment, not a claim to have independently validated every native field against every product release.

Representative event checks included more than twenty Windows event types. Security records carry appropriate provider/channel identities; successful audit records use success Keywords and failed logon/preauthentication records use failure Keywords. Process IDs use hexadecimal Security values and decimal Sysmon values where expected. SID, GUID, IP address, port, timestamp, and path representations were parseable and internally coherent. A character-code check confirmed that parsed Windows paths contain ordinary single backslash separators, not accidentally double-escaped path data.

Examples of usable source-native distinctions include Security 5156 decimal `ProcessID`, device-path `Application`, numeric protocol, and resource-string direction; 4688 `NewProcessId` and creator `ProcessId`; Sysmon 10's `SourceProcessGUID`/`TargetProcessGUID`; and Sysmon 8's `SourceProcessGuid`/`TargetProcessGuid`. I did not mistake these case differences between event schemas for malformed data. Event 1102 uses a different payload shape from ordinary EventData records, so absence of its fields from an EventData-only extractor was not scored as missing data.

### Linux PID texture: the material concern

I extracted sysstat CRON entries using the visible RFC5424 application and PID fields, grouped by host, and subtracted each PID from the next PID within that host. All intervals are scheduled about ten minutes apart. Results:

| Host | Records | Intervals | Exactly +940 | Minimum increment |
|---|---:|---:|---:|---:|
| APP-INT-01 | 36 | 35 | 5 | 940 |
| FILE-LNX-01 | 36 | 35 | 6 | 939 |
| LOG-MON-01 | 36 | 35 | 8 | 940 |
| LT-MRIVERA-02 | 36 | 35 | 12 | 940 |
| MAIL-CLIN-01 | 36 | 35 | 6 | 940 |
| MAIL-EDGE-01 | 36 | 35 | 5 | 940 |
| PROXY-01 | 36 | 35 | 6 | 940 |
| WEB-EXT-01 | 36 | 35 | 6 | 940 |
| WS-LNGUYEN-01 | 36 | 35 | 5 | 940 |
| WS-OHADDAD-01 | 36 | 35 | 6 | 940 |
| **Total** | **360** | **350** | **65** | **939** |

There is considerable variation above the floor: increments reach 5545 on MAIL-EDGE-01. That variability argues against describing the whole dataset as uniformly timed. Nevertheless, a shared sharp minimum near 940 and identical modal increment on all ten hosts is consistent with a common background-allocation formula. Identically configured periodic services can produce repeated PID increments in real deployments, so this remains probabilistic evidence; the concern is its prevalence across all observed host roles. No allegation here depends on regular cron execution being abnormal or on every process having been collected.

### Windows process and session joins

Of 916 Security 4688 events, 912 have a visible same-host Sysmon creation candidate by PID; the checked matches agree on process image and creator/parent PID. The remaining four were not treated as failures because selected-source visibility need not be identical.

For a concrete join, `WS-MCHEN-01.meridianhcs.local/windows_event_sysmon.xml` record 525184 at 13:02:42.4797906Z has PID 7208, `taskhostw.exe`, parent PID 5904, and GUID `{7b2a0e3f-89f2-6ae8-5c02-0000d8538e2e}`. Security record 948728 at 13:02:42.6189107Z has `NewProcessId=0x1c28` (7208), creator `ProcessId=0x1710` (5904), the same image, and `CommandLine=taskhostw.exe`. The source timestamps differ plausibly rather than requiring equality.

There are 406 Security 4634 events; 403 have a visible same-host 4624 for the LogonID. Session interpretation must preserve all logons for a given ID rather than overwriting them with the latest unlock. For example, Sophia Martinez's `0xc162b95` on WS-SMARTINEZ-01 has an initial Type 2 logon at 13:47:35.2954872Z, Type 7 unlocks at 15:54:39.1437103Z and 16:40:00.4041626Z, and a Type 2 logoff at 18:09:34.4250160Z. This is not a logon-type contradiction. Likewise, built-in service LogonIDs and sessions already active at the window boundary cannot be treated as newly created by the first visible record.

The Sysmon audit covered 11,305 direct ProcessGuid references, 913 parent references, 770 source and 770 target process-access references, and 11 source and 11 target remote-thread references. Where matching creation or termination evidence was visible, the checks found no impossible lifecycle ordering or PID disagreement. This result does not certify unobserved initiators or terminators.

### Network and SSH correlation

Protocol join denominators were 76 records on zeek-db, 6836 on zeek-core, and 7259 on zeek-dmz. No companion UID was absent from that sensor's conn records, and no joined tuple disagreed. Checked DNS/HTTP/TLS/SMTP timestamps did not precede their corresponding connection start by more than 10 ms or extend beyond its duration by more than 100 ms. The tolerances avoid treating floating-point or collection precision as hard causality errors.

The exact SSH tuple `10.10.1.35:61284 → 10.10.3.10:22` provides a cross-family example. The core sensor records UID `CUpUIpd4aCFfBOFJHys`, epoch start 1793625909.606046 (13:25:09.606046Z), `SF`, and duration 3191.20981 seconds. The DMZ sensor observes the same tuple under its own UID and slightly different timestamp. WEB-EXT eCAR observes inbound transport at 13:25:09.693Z; the Windows client eCAR observes outbound transport at 13:25:10.228Z with `ssh.exe`, PID 5232. WEB-EXT syslog then records sshd PID 2696510's connection message at 13:25:13.106668Z, accepted publickey at 13:25:18.805366Z, and PAM session opened at 13:25:18.852945Z. The visible ordering supports a usable detection sequence.

Repeated X.509 fingerprints were also checked for conflicting certificate identity fields: 199 distinct fingerprints had no conflicting certificate field sets. I did not use sanitized domain choices or DNS-to-public-IP familiarity as authenticity evidence.

### macOS and collection-window safeguards

MAC-MROSS-01's native ES sequence starts with launchd forking PID 41136 at 13:00:06.950823Z, PID version 12, followed by exec into xpcproxy at .953308, version 13, and Chrome at .958279, version 14. Exit at 13:00:29.844683Z refers to that final version. The iTerm path on MAC-MROSS-02 separately represents iTerm2, iTermServer, login, ShellLauncher, and zsh, rather than conflating a terminal application with its shell. This is useful evidence for process-tree detections.

The records declare ES message version 11. I did not assert a native-version defect from unfamiliar added fields, equate an ES notification with an authorization denial, or demand network FLOW events inside native ES. The Unified Log `ASP: Security policy would not allow process` message at 15:41:38.735570Z was not treated as proof that the named process was denied or that its children could not execute. Thin Unified Log coverage and absent particular Sysmon event families were not scored.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Linux syslog CRON PID fields | 360 records on ten hosts; 65/350 PID increments exactly +940; 349/350 at least +940 | Material repeated numeric allocation signature across heterogeneous hosts; supports a synthetic leaning without establishing impossibility |

No hard contradiction, demonstrated contract gap, or demonstrated schema defect was established in the checks performed. Strong successful joins lower the score but are not proof of production origin.

## Realism Score by Category

- **Field format accuracy:** 9 — Examined native event-specific fields parse coherently; no demonstrated malformed schema.
- **Temporal patterns:** 8 — Lifecycle and transport/auth ordering holds in checked identities; recurring PID allocation has a strong shared numeric floor.
- **Cross-source correlation:** 9 — Checked Windows and Zeek joins retain identities and tuples with plausible source timing differences.
- **Behavioral realism:** 8 — Platform-specific execution and operational noise are credible; the ten-host PID texture reduces confidence in organic workload variation.
- **Environmental consistency:** 9 — Windows, Linux, native macOS, and network observations are distinguishable and role-compatible in the inspected examples.

## Recommendations

- If this were synthetic, derive Linux PID consumption from independently varying per-host workload and process/thread churn. Preserve normal cron schedules while avoiding a shared +940 ten-minute allocation floor across every observed host role.
- If this were synthetic, retain the demonstrated native field distinctions, exec identity transitions, sensor-local UIDs, and lifecycle ordering while changing that distribution. No recommendation to add unspecified sources or manufacture out-of-window lifecycle companions is justified by this review.
