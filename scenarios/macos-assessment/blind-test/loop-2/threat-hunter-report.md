# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 67

## Executive Summary

This is a technically useful and substantially coherent six-hour security telemetry slice, but the repeated application-process population and millisecond-level batching on both Macs suggest generated background activity. A separate SMB authentication/closure timing outlier and unusual Linux journal destinations reinforce that assessment, although neither independently establishes synthetic origin. I found no decisive impossible Windows process lifecycle, and the evidence supports “likely synthetic,” rather than certainty.

## Evidence For Synthetic

- **[distribution_texture] Repeated GUI launches accumulate as separate, long-lived processes.** In `NS-MAC-02.northstar.example/ecar.json`, there are 12 Code, 11 IntelliJ IDEA, eight Postman, eight Terminal, and five Sublime Text process creations. All 44 survive until the logout termination batch at 18:44:17–18:44:29 UTC. Seven IDEA creations use the identical `reporting-tools` project command, including lines 356, 377, 397, 407, 411, and 415 between 14:40:30 and 14:46:23. Reopening a project normally need not create another main application process that survives for hours. Multi-instance use or application testing remains possible, but its prevalence across multiple GUI products is a substantial texture issue.
- **[distribution_texture] Independent application launches repeatedly preserve fractional-second timing across whole-second gaps.** `NS-MAC-01.northstar.example/ecar.json` lines 103–105 create Terminal PIDs 17079, 17091, and 17105 at 14:34:59.335, 14:35:05.335, and 14:35:05.336; line 108 starts Postman at 14:35:18.335. Lines 191–193 start Code, IDEA, and DBeaver at 14:50:44.443, 14:50:59.443, and 14:51:19.444. Similar timing occurs on Mac 02: Code/Postman at 13:59:18.637/13:59:52.637, lines 177/183, and IDEA at 14:45:43.013/14:46:23.014, lines 411/415. Automation can produce this pattern; recurrence among ostensibly ordinary GUI activity on both machines is why it influences the score.
- **[contract_gap] One native Samba authentication and closure precede the associated visible transport by much more than the routine clock difference.** `NS-BUILD-01.northstar.example/syslog.log` line 367 records successful NTLMSSP authentication for `nora.ellis-admin` from `10.42.0.21` at 17:19:39.813360; line 368 closes the connection at 17:19:40.582360. The corresponding runas-related SMB transport is `office-span/conn.json` line 1523, UID `CAVA4JSpkplq69cVC8`, `10.42.0.21:60895 → 10.42.0.31:445`, starting at 17:19:41.173824. The target eCAR flow/login appear later at 17:19:41.526/.543, lines 633–634. The native message lacks a source port, so the association is inferential; a separate unobserved connection is an alternative. However, the nearby account, source, and explicit-credential activity make this a meaningful correlation discrepancy.
- **[environment_or_collection_plausibility] One journald process writes to several changing, short journal identity directories.** `NS-BUILD-01.northstar.example/ecar.json` lines 478, 602, 616, and 710 attribute writes by PID 21316, `/usr/lib/systemd/systemd-journald`, to `/var/log/journal/220BEDEF/system.journal`, `/var/log/journal/93130CAF/system.journal`, `/var/log/journal/2D7C223E/system.journal`, and `/run/log/journal/2F4A56F2/system.journal` between 15:44:35 and 18:08:56. Ordinary journald storage uses a stable machine identity directory, conventionally a 32-character hexadecimal ID. Multiple unrelated eight-character identities for the same process are unusual. Custom configuration or sanitization could explain this; I do not treat the paths as a hard contradiction.

## Evidence For Real

- **The environment has a credible mix of activity and outcomes.** The network source contains 2,128 connection records from four local originators, 991 DNS transactions spanning 240 query names, 56 NXDOMAIN responses, A/AAAA/PTR queries, successful and reset TLS connections, rejected/unanswered probes, SMB, SSH, NTP, and a few database connections. Examples include the reset SSH connection in `office-span/conn.json` line 18 and a long SSH flow with capture loss in line 1043 (`missed_bytes=189`). These are concrete variations rather than a success-only environment.
- **The Windows-to-Mac SSH pivot is operationally coherent.** Windows eCAR line 695 starts `ssh.exe owen.patel@NS-MAC-02.northstar.example` at 15:07:15.036. The network connection in `office-span/conn.json` line 699 begins at 15:07:25.724282; Mac 02 eCAR line 434 observes the same inbound tuple at 15:07:26.403, before its successful SSH login at 15:07:29.577, line 438. The resulting shell later starts `uname -a`, lines 454–455.
- **Explicit-credential semantics are modeled sensibly.** Windows Security EventRecordID 245496 identifies `runas.exe` PID `0x1e7c` using the administrator credential. EventRecordID 245497 creates LogonType 9 with local identity `nora.ellis` and outbound identity `nora.ellis-admin`. The child command uses the new logon ID, rather than incorrectly changing its local process principal to the outbound administrator account.
- **Observed identities are stable.** Across the supplied Sysmon process and module records, repeated image paths retain consistent hash strings. Repeated X.509 issuer/serial identities also retain their fingerprints. This supports useful forensic pivots, although matching by itself does not decide authenticity.
- **Most sampled lifecycles and protocol timing are consistent.** The visible Sysmon parent/dependent process references checked did not precede matching visible creation records or follow matching termination records. No DNS, TLS, HTTP, SMB mapping/file, or NTP record with a matching connection UID fell outside its recorded transport interval beyond the small timing allowances used in the check.

## Detailed Analysis

### Scope and collection interpretation

The endpoint evidence spans approximately 13:00–19:00 UTC on 20 October 2026. There are four apparent endpoint roles:

| Host | Address inferred from flows | Apparent role and supplied sources |
|---|---|---|
| NS-MAC-01 | 10.42.0.11 | Developer workstation; eCAR, one Unified Log record, zsh history |
| NS-MAC-02 | 10.42.0.12 | Developer workstation and SSH receiver; eCAR, three Endpoint Security fork notifications, two Unified Log records, zsh history |
| NS-WIN-01 | 10.42.0.21 | Interactive Windows workstation with administration/development tools; eCAR, Security XML, Sysmon XML |
| NS-BUILD-01 | 10.42.0.31 | Linux build/administration host and Samba server; eCAR, syslog, bash histories |

The `office-span` sensor supplies connection, DNS, TLS, HTTP, file, X.509, OCSP, NTP, and SMB records. The endpoint eCAR files contain 713, 1,249, 1,505, and 792 rows respectively; the Windows XML files contain 637 Security and 518 Sysmon events. The Linux syslog has 500 lines.

The source totals are plausible for a selected collection slice. I have not penalized the small Unified Log/Endpoint Security exports, the absence of other endpoint products, or the absence of particular Sysmon event types. I also have not counted connections or processes missing a beginning or ending outside the visible interval as defects.

### SSH: a practical cross-platform pivot

The Windows-to-Mac session is particularly useful because it crosses account namespaces without confusing process ownership. Windows `nora.ellis` runs an SSH client naming remote account `owen.patel`; the receiver records the latter account. That difference is normal and does not imply contradictory attribution.

The source tuple is `10.42.0.21:60672 → 10.42.0.12:22`, UID `CnLtW60Yttw7a21IqZO`, `office-span/conn.json` line 699. Its 1,413.295494-second duration gives a transport end near 15:30:59.020. Mac eCAR lines 582–584 terminate the shell and SSH processes at 15:30:59.897–15:31:00.276, then line 585 records logout at 15:31:04.963. Those small source-level differences are compatible with teardown and reporting delay.

Mac eCAR lines 435–447 distinguish the wrapper, executable changes, forked SSH processes, audit binding, privilege changes, and eventual `/bin/zsh` execution. The separate Endpoint Security file contains fork observations with audit tokens and process start times. I do not equate those notification timestamps with the normalized eCAR arrival/observation times, nor infer an authorization denial from their result wrapper. There is no demonstrated native macOS schema defect in these three records.

### SMB: generally usable evidence, with one timing exception

A routine example is UID `CdiUBoJDv2jfgi0zHl`, `office-span/conn.json` line 41. The TCP connection begins at 13:18:16.252945, tree mapping follows at 13:18:16.368523 (`smb_mapping.json` line 1), and `Reports\inventory.pdf` is opened/written at 13:18:17.126036/.259027 (`smb_files.json` lines 1–2). Linux syslog lines 20–24 name the same user, client, share, server path, and smbd PID 51004. Target eCAR lines 45–50 provide the process and authenticated file-write relationship. That is a strong practical pivot.

Native Samba authentication timestamps are slightly ahead of the sensor's connection starts throughout the normal population. Matching the 51 routine authentication messages to the nearest same-client SMB transport gives leads of 51–108 milliseconds. A small clock offset, sensor timestamp convention, or source timing difference can explain that; I do not score the ordinary offsets as impossible causality.

The administrator case differs materially: its native successful authentication leads the visible transport by 1.360464 seconds, and its native closure leads transport start by 0.591464 seconds. A constant offset consistent with the other 51 sessions does not remove the inversion. The target eCAR login instead follows the matching transport and identifies source port 60895. This suggests that the native Samba message pair was timed from a different activity anchor.

There are two important limits. First, the native messages omit the source port and PID, so I cannot prove that they refer to UID `CAVA4JSpkplq69cVC8`; the association rests on the account/source/time/context. Second, an authenticated SMB connection does not prove that `dir \\NS-BUILD-01\ADMIN$` successfully listed a share. No successful ADMIN$ listing is claimed here.

### Application population and timing texture

The most persuasive distribution issue is the repeated creation of GUI application main processes, coupled with their observed long retention.

On Mac 02, seven separate main IDEA processes use the same `reporting-tools` project command. The creates at 14:40:30.154, 14:41:32.233, 14:44:25.741, 14:45:29.855, 14:45:43.013, and 14:46:23.014 are not process-exit/restart pairs: those identities remain until the 18:44 logout batch. All 44 processes in the five common GUI families listed above have a matching termination in that batch. These records also uniformly carry `process_group_id="1"` and `posix_session_id="1"`; I treat that as descriptive context rather than an independently proven platform defect.

Mac 01 shows a related population: nine Terminal, nine IDEA, eleven Sublime Text, seven Code, and six Postman creates. Three Terminal instances appear within 6.001 seconds at lines 103–105, two just one millisecond apart. Repeated project-opening commands occur across both machines.

The repeated fractional-second patterns strengthen the concern. I counted 13 adjacent PID-1 process-creation pairs across the two Macs whose separation was between one and 90 seconds and within two milliseconds of a whole-second interval. The examples in the evidence list involve different application families. Startup automation, scripted UI testing, or a normalization pipeline could create batches like this, so they are distribution indicators rather than impossibilities. Combined with the persistent duplicate main processes, however, they look more like reusable background activity patterns than independent ordinary application use.

The logout batch itself is plausible. What makes it informative is that it confirms the simultaneous retention of the earlier duplicate application instances. I do not score the mere presence of an orderly logout as synthetic.

### Other hunt leads and evidentiary limits

Several records warrant investigation without establishing an intrusion or synthetic origin:

- Mac 01 eCAR line 32 runs curl to download `manifest.json`; line 34 records that destination. This proves a download action, not execution of its contents.
- Mac 01 lines 376–397 show root `northstar-maintenance`, creation of an assetcheck plist, a later root assetcheck process, and plist deletion. The plist contents and explicit registration are not supplied. A later process with a related name is not enough to prove that the plist caused its launch, and deleting the file does not prove an unload.
- Windows Sysmon EventRecordIDs 607381 and 607460 show `msi_update.exe` and `KB5034441_update.exe` running at Medium integrity from temporary directories. Their names and locations are investigative leads; they are not proof of malicious execution, privilege escalation, or false telemetry.
- Sysmon EventRecordID 607788 records a Defender process creating a remote thread in Explorer. Its start module/function are `ntdll.dll`/`TppWorkerThread`. That event deserves context but is not intrinsically impossible or sufficient to label injection malicious.

The changing journald directories are a separate environmental concern. Four changing eight-character directory names under both persistent and volatile journal roots do not resemble ordinary stable machine-identity storage for one daemon. A custom collector/path sanitization explanation remains possible, which limits the weight of this observation.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the synthetic-confidence score |
|---|---|---|---|
| distribution_texture | Mac normalized endpoint processes | Both Macs; 44 recurring GUI-family instances on Mac 02 confirmed alive until one logout batch | Repeated identical project/application launches accumulate as long-lived main processes across several products |
| distribution_texture | Mac normalized endpoint timestamps | Both Macs; 13 adjacent launch pairs close to whole-second intervals | Repeated shared millisecond phase across different GUI products suggests scheduled/template timing; automation is an alternative |
| contract_gap | Samba syslog, eCAR, network connection | One explicit-credential SMB episode | Authentication and closure precede the likely associated transport by much more than the routine 51–108 ms offset; native tuple omission prevents conclusive linkage |
| environment_or_collection_plausibility | Linux normalized file activity | Four journal writes by one journald PID | Changing short journal identity paths are unusual; custom configuration or sanitization could explain them |

No indicator is classified as a proven hard contradiction. The score reflects multiple concrete but partly explainable patterns, balanced against strong lifecycle and field consistency.

## Realism Score by Category

- **Field format accuracy:** 9 — JSON/XML parse cleanly, native Windows event fields are recognizable, and image/certificate identities remain consistent.
- **Temporal patterns:** 6 — Most protocol and lifecycle timing works, but repeated whole-second GUI batches and the Samba outlier reduce realism.
- **Cross-source correlation:** 8 — SSH, routine SMB, Windows authentication, and process pivots are usable; the administrator Samba message pair disagrees with its likely transport.
- **Behavioral realism:** 5 — Developer/admin actions are plausible individually, but repeated long-lived GUI main-process instances across the same small application pool are conspicuous.
- **Environmental consistency:** 7 — Host roles and account boundaries mostly fit; changing short journald identity paths need explanation.

## Recommendations

If this were synthetic, the following changes would improve it:

- Model application reuse explicitly. For products/projects already open, distinguish a new window or open request from creation of another persistent main process. Retain multiple instances when actual product behavior supports them.
- Derive GUI activity timing from the individual actions. Preserve scheduler precision for real automated tasks, but avoid carrying the same millisecond phase through unrelated user application launches unless the records establish automation.
- Align native Samba authentication and closure with the actual SMB transport interval. Keep event occurrence time separate from collection delay, and preserve a tuple or session identifier in normalized evidence so source-clock effects can be distinguished from separate connections.
- Keep journald storage identity stable for each host and use realistic machine-ID paths. If privacy transformation changes those paths, preserve identity consistency across writes.
