# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 68
**Synthetic-Confidence Score:** 34

## Executive Summary

The host telemetry is mostly production-like: Windows process, logon, Sysmon, Security, and eCAR lifecycles remain internally coherent under detailed spot checks, while Linux SSH/PAM sequences preserve realistic source ports, identities, and modest source-specific timing offsets. I found no impossible visible ordering or source-native contradiction; the main doubts are distributional, particularly an unusually dense remote-administration workload and a broadly reused Linux sudo-user/command pool.

## Evidence For Synthetic

- [distribution_texture] Remote administration is unusually dense for a six-hour slice. `WS-AJOHNSON-01.meridianhcs.local/ecar.json` contains 48 `ssh.exe` process creations and `WS-MCHEN-01.meridianhcs.local/ecar.json` contains 41; `WS-LNGUYEN-01.meridianhcs.local/ecar.json` adds 23 Linux `ssh` launches. Aisha repeatedly opens sessions to APP-INT-01, DB-PROD-01, MAIL-CLIN-01, MAIL-EDGE-01, PROXY-01, and WEB-EXT-01, including five new SSH clients between 17:10:20 and 17:23:52 UTC. This is possible for operations staff, but the repeated connect/use/disconnect texture across so many targets resembles generated admin activity more than a typical person's terminal reuse.
- [environment_or_collection_plausibility] The Linux syslogs reuse nearly the same interactive sudo population across substantially different systems. `admin`, `backup`, `deploy`, `svc_app`, `ubuntu`, and `ops` appear with TTY-backed sudo commands on app, database, mail, proxy, server, and workstation roles. For example, `/usr/bin/systemd-analyze blame` appears once each on APP-INT-01, DB-PROD-01, MAIL-EDGE-01, and PROXY-01, while `/usr/bin/systemctl list-timers --all --no-pager` appears on APP-INT-01, LT-MRIVERA-02, PROXY-01, and WEB-EXT-01. The commands are individually valid, but the cross-role account and diagnostic-command reuse is somewhat pool-like.
- [weak_signal] Windows background software is cohort-consistent but slightly curated. Multiple workstations repeatedly execute the same limited updater/service set (GoogleUpdater, Adobe ARM, DropboxUpdate, Windows Search hosts, taskhostw, and WMI), often with similar small counts. This could reflect a standardized managed image, so it carries little weight by itself.

## Evidence For Real

- Windows process correlation is technically strong without being timestamp-identical. Across nine Windows hosts, 968 of 973 sampled Security 4688 records matched Sysmon Event 1 by PID and image; Sysmon-minus-Security offsets generally ranged from about -21 ms to +22 ms, with both signs represented. On DC-01, `sc.exe` PID 5480 appears at `16:19:58.2415174Z` in Sysmon and `16:19:58.2494160Z` in Security, then Event 4697 records `DeviceSyncSvc` at `16:19:58.4421235Z`.
- Process identities remain stable through dependent artifacts. On FILE-SRV-01, PowerShell PID 5772/ProcessGuid `{1b54004d-7334-65f8-d802-001090d12145}` is created at `17:00:36.5848465Z`, creates `C:\ProgramData\Microsoft\cache_7f3a.zip` in Sysmon Event 11 at `17:00:36.5988878Z`, and terminates under the same ProcessGuid at `17:00:49.6587664Z`. Security 4688/4689 and eCAR independently preserve PID 5772, principal `svc_mhsync`, command line, and lifecycle.
- SSH evidence has credible source-native sequencing. Aisha's Windows SSH client starts at `14:02:16.350Z` in `WS-AJOHNSON-01.../ecar.json`; APP-INT-01 syslog records public-key acceptance at `14:02:20.184308Z`, PAM open at `14:02:20.269574Z`, eCAR login at `14:02:20.712Z`, and PAM/eCAR close at `14:08:00.892Z`. Source IP `10.10.1.35`, source port `50501`, username, and key fingerprint remain consistent.
- The Windows Security-log clearing sequence is source-native and coherent. DC-01 records `wevtutil cl Security` as a WmiPrvSE -> cmd.exe -> wevtutil.exe chain at `17:41:47.6030366Z` through `17:41:48.0133905Z`; Event 1102 follows at `17:41:49.0211714Z` using the expected Eventlog provider and `UserData/LogFileCleared` structure, with EventRecordID reset to 1. Subsequent Security records resume with low record IDs, reaching 439-440 for account cleanup at `17:50:09Z`.
- System-binary hashes are stable within each host and form plausible OS-build cohorts rather than arbitrary per-event values. Windows 10.0.19041 workstations share one set for core binaries, Windows 11/10.0.22621 workstations share another, DC-01 and MAIL-FIN-01 share Server 2022-style metadata (`10.0.20348.1`), and FILE-SRV-01 uses `10.0.17763.1` values.
- Visible lifecycles do not show negative ordering. eCAR process create/terminate pairs were non-negative on all 18 hosts examined, as were matched Windows 4624/4634 sessions. Session duration texture ranges from seconds for network/service activity to hours for interactive or long-lived sessions.

## Detailed Analysis

### Windows process trees and Sysmon/Security correlation

The ordinary Windows trees are credible and role-aware. Interactive chains include winlogon.exe -> userinit.exe -> explorer.exe, service children originate from services.exe, and WMI-driven administrative commands use WmiPrvSE.exe -> cmd.exe -> the requested utility. DC-01's suspicious sequence is especially coherent: SYSTEM/WmiPrvSE launches cmd.exe PID 5408, which launches `net.exe` PID 5424 for `net user svc_mhsync ... /add /domain`; Security events 4720, 4724, 4738, and 4728 then follow between `16:14:50.8930974Z` and `16:14:53.3201434Z`. Later, WmiPrvSE launches service and scheduled-task creation commands, services.exe starts DeviceSyncSvc PID 5512 at about `16:29:10.76Z`, and cleanup uses the same WMI execution style.

Sysmon ProcessGuid values have stable host prefixes and change consistently with process creation, while hashes stay stable for repeated images. Metadata also follows apparent OS cohorts: core files on DC-01 report version `10.0.20348.1`, FILE-SRV-01 reports `10.0.17763.1`, and workstation groups report `10.0.19041.1` or `10.0.22621.1`. Third-party applications generally carry plausible product/company/original-filename metadata; unknown or custom binaries use `-`, which is believable.

The FILE-SRV-01 collection demonstrates strong multi-event ownership. Security Event 4624 at `17:00:34.7318169Z` creates type 3 logon ID `0xf8842ea` for `svc_mhsync`. Subsequent Security, Sysmon, and eCAR records retain that principal while `net view` and `Compress-Archive` run. PowerShell's file-create event occurs after process creation and before its termination, and cmd.exe remains alive until `17:55:59-17:56:00Z`, followed by the type 3 logoff. That is a plausible remote execution/session lifecycle, not merely matching labels.

### Logon and session lifecycle

The Windows hosts contain a believable mix of type 2, 3, 5, 7, and 10 logons according to role. DC-01 is dominated by network and service activity (420 type 3 and 112 type 5 logons), while user workstations have low-volume interactive/unlock activity. Matched 4624/4634 pairs never terminate before their visible start. Some starts or ends are unpaired, but this is expected in a bounded six-hour slice and was not treated as an authenticity defect.

Linux SSH sessions preserve remote address, source port, principal, authentication mechanism, sshd PID, and PAM lifetime. Key fingerprints remain stable per user: Aisha uses the same RSA fingerprint across destinations, Marcus uses a stable ECDSA fingerprint, and Lina's public-key sessions use a stable RSA fingerprint while some destinations also accept password authentication. Source-side process creation precedes target acceptance by a few seconds, target PAM opens tens to hundreds of milliseconds after acceptance, and close times align with eCAR logout events without being artificially identical at every source.

### Linux host texture

The syslogs include more than authentication: rsyslog queues, unattended upgrades, snapd, systemd-resolved degradation, irqbalance, dbus, polkit, cron/sysstat, package maintenance, postfix/dovecot behavior, and local login/su/sudo activity. The half-hour sysstat jobs retain host-specific minute offsets and small scheduling delays; occasional missing observations prevent perfect all-host coverage. PIDs progress in host-specific ranges rather than resetting for each event family.

The weaker point is behavioral population. The same small collection of local operational accounts performs one-off TTY sudo diagnostics on nearly every Linux role. In combination with the high SSH session count, this creates a broader repeated-admin texture than I normally see in a random six-hour production sample. Still, command syntax, PAM open/close relationships, per-host PIDs, usernames, and durations remain plausible, so this is not a contradiction.

### eCAR/EDR semantics

eCAR objects use stable object IDs through process termination, stable actor/source UUIDs for dependent activity, and consistent process/network ownership. No cases were found where an actor's visible creation occurred after its dependent event, nor where `actorID` disagreed with `properties.source_process_uuid`. PROCESS, FLOW, FILE, USER_SESSION, SERVICE, THREAD, MODULE, and REGISTRY records appear in role-appropriate proportions. Endpoint timestamps commonly differ from native Security or Sysmon observations by milliseconds to roughly a second, which is more believable than forced equality.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| `distribution_texture` | eCAR, Sysmon, Security, Linux SSH | Repeated across three admin workstations and six Linux targets | More than 110 SSH client launches in six hours, with frequent short reconnects, looks more generated than ordinary terminal reuse; moderate score impact. |
| `environment_or_collection_plausibility` | Linux syslog | Repeated across nine Linux systems | The same local sudo identities and small diagnostic-command pool recur across workstation, proxy, mail, app, and database roles; moderate-to-low impact because a shared operations image can explain it. |
| `weak_signal` | Windows Sysmon/eCAR | Repeated within workstation cohorts | Similar updater/background-process mixes look curated, but managed enterprise images readily explain the pattern; low impact. |

## Realism Score by Category

- **Field format accuracy:** 9 — Windows XML, Sysmon fields, ProcessGuids, hashes, Security log-clear UserData, RFC5424 syslog, and eCAR structures are source-appropriate in the records inspected.
- **Temporal patterns:** 8 — Causal ordering and source-specific offsets are strong; repeated remote-admin activity is denser than expected.
- **Cross-source correlation:** 9 — PIDs, parent images, logon IDs, source ports, principals, hashes, ProcessGuids, files, and terminations agree without impossible visible ordering.
- **Behavioral realism:** 7 — Role-aware software and activity are convincing, but SSH reconnect density and shared Linux diagnostic behavior feel pool-driven.
- **Environmental consistency:** 8 — OS-build/hash cohorts and host roles cohere; broadly reused Linux local accounts are the main concern.

## Recommendations

- If this were synthetic, reduce the number of independent SSH client launches by modeling longer-lived terminals, multiplexed connections, and per-admin target affinity. Preserve the existing strong source-port and PAM/eCAR lifecycle correlation while introducing fewer reconnects and more individual variation.
- If this were synthetic, narrow Linux sudo identities and command choices by host role. Service accounts such as `svc_app` should rarely receive arbitrary TTY-backed diagnostic sessions, and workstation, proxy, database, and mail hosts should not all draw as often from the same generic admin command pool.
- If this were synthetic, retain the current OS-build-aware PE metadata, stable per-image hashes, ProcessGuid behavior, Security/Sysmon timing offsets, and log-clear record-ID semantics; these were the most convincing production-like features.
