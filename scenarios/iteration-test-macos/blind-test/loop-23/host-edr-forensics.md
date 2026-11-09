# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 86
**Synthetic-Confidence Score:** 64

## Executive Summary

The endpoint evidence has convincing process identity and lifecycle correlation, particularly across Windows sources and macOS fork/exec chains. Native macOS file metadata nevertheless exhibits a pronounced fractional-timestamp fingerprint, with repeated browser startup timing providing secondary support. Concurrent Chrome lifetimes raise a further concern, although unrecorded profile configuration limits that finding.

## Evidence For Synthetic

- [distribution_texture] In both `macos_endpoint_security.ndjson` files, almost every distinct nonzero file-stat fractional timestamp falls between 1 and 999 nanoseconds after a whole second: 68 of 69 on MAC-MROSS-02 and 72 of 74 on MAC-MROSS-01, counting distinct complete timestamp strings separately within each host. MAC-MROSS-02 line 1 `/sbin/launchd` has atime `.000000800`, mtime `.000000091`, and ctime/birthtime `.000000848`; line 2 `/usr/libexec/xpcproxy` has atime `.000000446`, mtime `.000000748`, and ctime/birthtime `.000000321`. Different historical dates, applications, and fields share this extremely narrow submicrosecond band. Preserved whole-second package timestamps are plausible; the pervasive tiny nonzero fractions are the concern.
- [distribution_texture] The first Chrome startup on each Mac has nearly identical helper timing: MAC-MROSS-01 ES lines 19/21/23/25 show the main exec at 13:14:05.707286 and helpers approximately 2.007, 3.003, and 5.000 seconds later; MAC-MROSS-02 lines 24/26/28/30 show the main at 13:27:08.474856 and helpers approximately 1.993, 3.001, and 4.997 seconds later. The same three-child timing template with millisecond variation is a secondary tell, not proof alone.
- [environment_or_collection_plausibility] MAC-MROSS-02 ES records three surviving browser-main processes for the same executable, UID 501, audit session 100001, and `HOME=/Users/maya.ross`: PID 20410 at line 24 (13:27:08.474856), PID 52121 at line 113 (17:10:58.718248), and PID 52240 at line 120 (17:11:39.376776). The latter two use `--new-window` with URLs; none specifies a separate user-data directory. Each has helpers, and all survive until exits at lines 161, 162, and 166 around 18:56:59. Ordinary same-profile Chrome generally forwards these requests to the existing browser. Unrecorded profile configuration or policy could explain the multiplicity, so this receives limited weight and is not a hard contradiction.

## Evidence For Real

- Windows formatting includes detailed provider/channel/record metadata, hexadecimal Security process IDs, decimal Sysmon IDs, coherent GUIDs, and stable hashes for repeated same-image/version observations within each host.
- I scanned 33,455 eCAR rows across the supplied hosts and found no actor-referenced activity timestamped after that actor's visible PROCESS/TERMINATE row. Same-GUID process image/PID references and visible parent identities were consistent in the Sysmon checks performed.
- MAC-MROSS-02 ES lines 1–10 distinguish launchd fork, xpcproxy exec, iTerm2 exec, iTermServer, login, ShellLauncher, and zsh. Successive exec images retain a process lifetime while changing pidversion.
- DB-PROD-01 syslog lines 16–18 contain a sudo command, PAM open, and later close under PID 1044648, including initiating user and numeric UID. SSH records distinguish password authentication at line 81 from public-key authentication at lines 158 and 227, with a stable ED25519 fingerprint for the latter.
- Host roles differ sensibly: the DCs concentrate network/Kerberos evidence, workstations show explorer-launched user applications and lock/unlock activity, and FILE-SRV-01 includes share and file-handle auditing.

## Detailed Analysis

### Scope and method

I examined only the data directory: all host eCAR streams, all ten Windows Security/Sysmon XML pairs, both macOS ES streams, and representative Linux syslog/history records. Sysmon contains 814 Event 1 and 700 Event 5 records plus other selected types. Collection selection, missing out-of-window initiators/closures, domain sanitization, and complete correlation were neutral.

### Windows processes and sessions

WS-AJOHNSON-01 Sysmon record 30297 creates `taskhostw.exe` PID 5204 at 13:06:37.575 under SYSTEM svchost; record 30298 terminates the same GUID/PID at 13:06:53.073. Logon ID `0x3e7`, terminal session 0, and integrity System agree. The same-GUID image/PID checks did not reveal contradictory identities, and the termination checks did not reveal visible later activity by an exited process.

Authentication includes interactive, network, service, RDP, new-credentials, and unlock evidence. Repeated built-in IDs `0x3e4`, `0x3e5`, and `0x3e7` are not duplicate-session defects. Reuse of an interactive identity in unlock evidence is also neutral. Security/Sysmon count differences can reflect collection and were not scored.

### macOS metadata and lifetimes

The strongest issue concerns values inside ES records, not filesystem modification times of the copied dataset. Deduplicating file objects by path/device/inode yields 33 objects on MAC-MROSS-02 and 32 on MAC-MROSS-01. Their four stat timestamp fields produce 132 and 128 observations; 187 of the combined 199 nonzero fractions fall in the first 999 ns of a second. Because ctime/birthtime repeat, I also deduplicated complete timestamp strings per host: the concentration remains 140 of 143 nonzero distinct values. Thus repeated snapshots do not explain the pattern.

The native process evidence otherwise maintains identity carefully. Small differences between ES and normalized eCAR observation timestamps were not scored as defects. Chrome multiplicity is a qualified concern: explicit lifetimes show PID 20410 alive during the two later main execs, and PID 52121 alive when PID 52240 starts. The later mains have helpers and persist for roughly 106 minutes, rather than appearing as short-lived URL handoff launchers. Their exec environments show the same HOME and their arguments show no explicit alternate user-data directory. These logs cannot establish every preference or policy setting; consequently this is an environmental plausibility concern rather than demonstrated impossibility.

### Linux and user activity

Linux records include RFC5424 framing, SSH authentication, PAM/logind, sudo, cron, and varied service messages. Lina's WS-LNGUYEN-01 history includes git, pytest, Docker, editors, and SSH; DB-PROD-01 histories contain database administration. I did not score generic administrative commands, thin collection, or easily reconstructed suspicious activity. No Linux-specific hard contradiction was established in the examined records.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the score |
|---|---|---|---|
| distribution_texture | macOS ES file stat metadata | Both Macs; 140/143 distinct nonzero times in the first 999 ns | Primary fingerprint across unrelated historical values |
| distribution_texture | macOS ES browser startup | First Chrome launch on both Macs | Same three helper starts around +2/+3/+5 seconds; secondary evidence |
| environment_or_collection_plausibility | macOS ES process lifetimes | MAC-MROSS-02; three overlapping Chrome mains | Limited concern about normal singleton/handoff behavior; unrecorded configuration remains possible |

## Realism Score by Category

- **Field format accuracy:** 8 — Detailed native identities and schemas; file-stat fractions show artificial texture.
- **Temporal patterns:** 7 — Lifecycles are credible, but initial browser helper timing repeats closely.
- **Cross-source correlation:** 9 — Identity checks found consistent process references and no eCAR actor activity after visible termination.
- **Behavioral realism:** 8 — Plausible role-specific activity, with qualified Chrome multiplicity concerns.
- **Environmental consistency:** 8 — Roles largely agree with evidence; independent same-user browser-main lifetimes need explanation.

## Recommendations

- If this were synthetic, derive file stat times from plausible filesystem/installation histories and realistic precision, retaining whole-second timestamps where appropriate instead of adding tiny nonzero nanosecond fractions throughout.
- If this were synthetic, vary browser helper startup timing according to process role and activity rather than repeating the +2/+3/+5-second shape.
- If this were synthetic, model same-profile URL/window requests as browser reuse or short-lived handoff. Where independent browser-main lifetimes are intended, represent the alternate user-data/profile configuration that explains them.
