# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 88
**Synthetic-Confidence Score:** 76

## Executive Summary

The dataset has unusually strong endpoint schemas, process identity, hash consistency, and cross-source timing, but a repeated Windows interactive-session defect is difficult to reconcile with genuine endpoint collection: user-context `explorer.exe` instances are repeatedly parented by `services.exe`, and multiple fresh `userinit.exe`/`explorer.exe` chains are emitted under a single unchanged logon ID. Linux and routine Windows activity add substantial realism, but the cross-host recurrence of these session-construction patterns, plus a conspicuously reusable Linux administrative command pool, makes the data likely synthetic.

## Evidence For Synthetic

- `[hard_contradiction]` Seventeen Sysmon Event 1 records on five workstations show a domain user's `C:\Windows\explorer.exe` directly parented by `C:\Windows\System32\services.exe`. Examples include `WS-AJOHNSON-01` at `2024-03-18T12:16:57.5042257Z` (user `MERIDIANHCS\aisha.johnson`, PID 5148, parent PID 4284, LogonId `0x2566b02`), `WS-EBROOKS-01` at `2024-03-18T13:08:09.1081592Z` (user `MERIDIANHCS\evelyn.brooks`, PID 5136, parent PID 3324, LogonId `0xa414c44`), and `WS-PPATEL-01` at `2024-03-18T13:03:11.6668831Z` (user `MERIDIANHCS\priya.patel`, PID 6376, parent PID 5032, LogonId `0xd9313f2`). The corresponding Security 4688 record for the AJOHNSON example independently says `ParentProcessName=C:\Windows\System32\services.exe`, so this is not a one-source rendering artifact.
- `[contract_gap]` Several workstations repeatedly run fresh `userinit.exe` and `explorer.exe` bootstrap chains while retaining one interactive LogonId and without a new Type 2 logon for each chain. On `WS-PPATEL-01`, LogonId `0xd9313f2` has four `userinit.exe` starts at `13:03:10.8911710Z`, `13:21:53.4553135Z`, `13:45:31.8409030Z`, and `15:13:01.9684528Z`, each followed by another Explorer. `WS-MCHEN-01` LogonId `0x6c9f412` similarly has three `userinit.exe` starts at `12:54:02.1583363Z`, `16:11:36.5216413Z`, and `16:58:42.1231419Z`. Ordinary unlocks do not rerun `userinit.exe`; repeated shell reconstruction should have a concrete session transition or failure/recovery explanation.
- `[distribution_texture]` The malformed Explorer/session pattern is replicated with the same shape across unrelated users and hosts rather than occurring as one damaged profile or one unusual service. `WS-EBROOKS-01` alone records nine Explorer starts for LogonId `0xa414c44`; eight are parented by the same `services.exe` PID 3324 between `13:08:09Z` and `14:34:49Z`. `WS-AJOHNSON-01` records five service-parented Explorer starts for LogonId `0x274f517` in about 21 minutes (`15:59:23Z` through `16:20:20Z`).
- `[distribution_texture]` Linux interactive/admin behavior draws heavily from a common small command texture across many systems and users. In the eCAR data, exact command lines such as `tail -20` occur ten times across six hosts, `ps aux` six times across five hosts, `wc -l` six times across three hosts, and `grep -i error /var/log/syslog` five times across four hosts. The repeated pattern of opening a shell, running short generic health commands, and terminating each command after a few seconds is plausible individually but visibly templated in aggregate.
- `[environment_or_collection_plausibility]` Interactive desktop sessions appear on infrastructure systems at a notable rate. For example, `DC-02` shows a Type 2 logon for `lina.nguyen` followed by `winlogon.exe` at `12:51:00.0219291Z`, `userinit.exe` at `12:51:01.2568634Z`, Explorer at `12:51:01.5305122Z`, and encoded PowerShell at `12:51:01.7414961Z`; `DC-01`, `FILE-SRV-01`, and `MAIL-FIN-01` also carry desktop shell activity. This is possible for administrators, but its frequency and similarity across server roles reinforce the session-template concern.

## Evidence For Real

- Windows process creation is internally well correlated. Across the ten Windows hosts, essentially every Sysmon Event 1 record has a Security 4688 counterpart with the same PID and image within less than one second; for example, all 148 process creates on `DC-01` matched, with an average absolute timestamp separation of about 0.158 seconds and a maximum of 0.637 seconds.
- Process lifecycles do not show visible termination-before-creation contradictions. Sysmon ProcessGuid values are unique at creation, no observed parent ProcessGuid is created after its child, and all terminations whose creates are visible occur after those creates. Unmatched early terminations are compatible with processes that began before this six-hour collection window.
- Logon/logoff ordering is coherent within the visible window. No Security 4634 event was found before a visible 4624 carrying the same TargetLogonId. Short Type 3 sessions and longer interactive sessions are differentiated, and workstation lock/unlock evidence exists, including AJOHNSON 4800/4801 records at `13:14:41.5358754Z` and `13:35:13.0368752Z` for LogonId `0x2566b02`.
- Sysmon hashes are stable for the same binary on a host and sensibly shared across host cohorts. For example, `OUTLOOK.EXE` has one four-algorithm hash tuple across six workstations, while core Windows binaries show a small number of consistent build cohorts rather than changing per execution. I found no hash reused for different image paths on the same host.
- Host roles are reflected in Linux telemetry: `FILE-LNX-01` has substantial `smbd`/`smbd_audit` activity, `MAIL-CLIN-01` and `MAIL-EDGE-01` have Postfix and Dovecot records, and `WEB-EXT-01` has Apache-related processes and dense kernel activity. SSH records include accepted authentication, PAM session open, stable sshd PID, and later session close; for example, `APP-INT-01` records Marcus Chen's public-key login from `10.10.1.31:58053` at `15:27:54.755353Z`, PAM open at `15:27:54.805557Z`, and close at `16:04:47.943940Z` under PID 1923860.
- User activity is not wholly interchangeable. `lina.nguyen` uses development tooling (`git`, `npm`, `cargo`, `gcc`, editors) on `WS-LNGUYEN-01`, while Windows users show Office, browser, RDP, SSH, MMC, and administrative tooling in role-shaped combinations. Process durations and event timing contain meaningful jitter rather than fixed intervals.

## Detailed Analysis

### Scope and collection window

The host-level collection covers 21 eCAR files, ten Windows Security/Sysmon host pairs, and eleven Linux syslog files. The visible period is approximately `2024-03-18T12:00:00Z` through `18:00:00Z`. I treated unmatched starts or ends at the window boundaries as potentially pre-window or post-window state and did not score them as defects.

Windows Security volume is role-sensitive: the two domain controllers have 6,664 and 5,928 Security events, dominated by 5156, 4769, 4768, 4624, and 4634, while workstations carry roughly 500–700 Security events. Sysmon includes process create/terminate, network, process access, DNS, image load, registry, remote-thread, and file events. The eCAR records span PROCESS, FLOW, USER_SESSION, MODULE, FILE, REGISTRY, THREAD, and SERVICE objects.

### Windows process trees and interactive-session construction

Normal examples are convincing. `WS-DRAMIREZ-01` shows `winlogon.exe` at `12:11:28.0802694Z`, `userinit.exe` at `12:11:29.8260123Z`, and `explorer.exe` at `12:11:30.0614347Z`, with proper parent PIDs 5708 → 6376 → 6436 and the user shell on LogonId `0x975c5e4`. `FILE-SRV-01` similarly shows a coherent `winlogon.exe` → `userinit.exe` → `explorer.exe` chain for Aisha Johnson from `12:21:40.7299437Z` to `12:21:43.3127086Z`.

The defect is that these correct chains coexist with many impossible or highly implausible alternatives. I counted 17 user-context Explorers directly parented by `services.exe`: six on `WS-AJOHNSON-01`, eight on `WS-EBROOKS-01`, and one each on `WS-MCHEN-01`, `WS-PPATEL-01`, and `WS-SMARTINEZ-01`. These are not merely unknown parents: both ParentImage and stable parent PID point to the Service Control Manager process. The AJOHNSON Security 4688 at `12:16:57.9015167Z` confirms `SubjectUserName=aisha.johnson`, `SubjectLogonId=0x2566b02`, `NewProcessId=0x141c`, `NewProcessName=C:\Windows\explorer.exe`, and `ParentProcessName=C:\Windows\System32\services.exe`.

The same sessions also receive repeated shell bootstraps. AJOHNSON LogonId `0x274f517` has two `userinit.exe` starts and seven Explorer starts; EBROOKS `0xa414c44` has one `userinit.exe` and nine Explorer starts; DRAMIREZ `0x975c5e4` has three `userinit.exe` and five Explorer starts; MCHEN `0x6c9f412` has three and four; PPATEL `0xd9313f2` has four and five. Multiple Explorer instances are possible, but the combination of repeated `userinit.exe`, unchanged LogonId, and recurring `services.exe` parentage is not a credible normal desktop lifecycle. Its recurrence on five independent workstations is the strongest authenticity discriminator.

Outside that family, process parentage is generally strong. WMI providers are children of service-host processes, scheduled PowerShell is parented by `taskeng.exe`, PsExec produces `services.exe` → `PSEXESVC.exe` → `cmd.exe`, and routine user applications are usually descendants of Explorer. No visible parent ProcessGuid starts after its child, and no visible Sysmon termination precedes its matching create.

### Windows logon lifecycles

The source contains a realistic mix of Type 2, 3, 5, 7, 9, and 10 logons. Domain controllers are dominated by network and service logons; workstations include interactive and unlock activity. Type 3 sessions commonly last seconds, such as `DC-01` Aisha Johnson LogonId `0x5380860` from `12:06:14.2778580Z` to `12:06:19.3416080Z`. I found no impossible visible 4634-before-4624 ordering for the same identifier.

Repeated system LogonIds such as `0x3e4`, `0x3e5`, and `0x3e7` are expected Windows well-known sessions and were not treated as defects. Likewise, a 4634 without a visible 4624 at the beginning of the slice was treated as pre-window state. The concern is specifically fresh desktop bootstrap process chains under already-established user LogonIds, not incomplete edge lifecycles.

### Sysmon, Security, and eCAR correlation

Correlation quality is high. PID/image matching found all 148 Sysmon creates against Security and eCAR on `DC-01`; all 93 across all three sources on `MAIL-FIN-01`; and all 106 on `WS-AJOHNSON-01`. Small count differences on a few hosts are consistent with source-level observation loss: `FILE-SRV-01`, for example, has 102 Sysmon creates and 104 Security/eCAR creates. Matched records are separated by randomized subsecond offsets rather than identical timestamps.

The process identity graph also passes basic causality checks. No eCAR event references a process actor whose visible creation occurs later, no duplicate eCAR event IDs were observed, and matching process termination object IDs occur after their creates. Hash sets contain correctly shaped SHA1, MD5, SHA256, and IMPHASH values; they remain constant per image on each host and show plausible cross-host version cohorts.

This strong agreement was counted as realism evidence, not as a synthetic tell. It does, however, establish that the malformed interactive trees are shared event truth: the same bad parent relationship appears in independent endpoint representations rather than being a typo confined to one emitter.

### Linux endpoint evidence

Linux syslog is structurally rich and role-aware. SSH sessions usually include accepted authentication and PAM open/close records with a stable sshd PID. Sudo records have paired PAM opens and closes and name the invoking UID. Workstations include NetworkManager, GDM, desktop services, DHCP, printing, and firmware activity, while servers include appropriate mail, web, SMB, resolver, cron, update, and storage services.

The Linux eCAR process trees are also often convincing. On `WS-LNGUYEN-01`, the visible desktop chain at about `12:22:07Z` is `/usr/lib/systemd/systemd --user` → `gnome-terminal-server` → `-bash`; later `sudo`, development tools, browsers, SSH, and SMB clients retain plausible actor relationships and terminate after creation. On `WS-OHADDAD-01`, a session teardown around `13:41:35Z` terminates the shells, terminal server, and user systemd process before USER_SESSION LOGOUT at `13:41:39.746Z`.

The weaker area is aggregate behavioral texture. Generic commands recur verbatim across unrelated users and hosts, often in compact diagnose-and-exit sequences. Examples include `sudo /usr/bin/systemctl list-timers --all --no-pager` on four hosts and three users, `sudo /usr/bin/iostat -xz 1 3` on four hosts and three users, and `tail -20` on six hosts and three users. These are individually normal administrator commands, so I weighted this below the Windows session contradiction, but the cross-environment reuse is conspicuous.

### Behavioral and environmental realism

There is useful differentiation: developers use compilers, package managers, repositories, and editors; infrastructure admins use SSH, PowerShell, MMC, WMI, service controls, and log inspection; server source volumes reflect host roles. Timing is bursty and jittered, and long-lived browsers coexist with short utilities.

Some server interactive use is plausible for administration, but the number of full desktop chains on domain controllers, file servers, and a mail server is unusual. That alone would be weak evidence in an unfamiliar environment. It matters here because the server sessions reuse the same stylized bootstrap vocabulary as the workstations and because malformed shell parentage is already independently visible on multiple endpoints.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Impact on score |
|---|---|---|---|
| `hard_contradiction` | Sysmon Event 1, Security 4688, eCAR PROCESS | 17 Explorer starts across five workstations | Direct user-shell children of `services.exe` are a strong, repeated process-tree impossibility and the largest score driver. |
| `contract_gap` | Security logon lifecycle, Sysmon/eCAR process lifecycle | Five workstations; repeated within individual LogonIds | Fresh `userinit.exe`/Explorer chains recur without corresponding new interactive session identities. |
| `distribution_texture` | Sysmon/eCAR Windows processes | Repeated across several users and hosts | The same malformed desktop pattern repeats in clusters, making a one-host anomaly implausible. |
| `distribution_texture` | Linux eCAR PROCESS and syslog | Repeated across many Linux hosts/users | A shared pool of exact generic admin commands makes independent user behavior look templated. |
| `environment_or_collection_plausibility` | Windows Security/Sysmon/eCAR | Several infrastructure servers | Similar full desktop activity across DC, file, and mail roles is possible but unusually common. |

## Realism Score by Category

- **Field format accuracy:** 9 — Windows XML, Sysmon fields, eCAR JSON, RFC-style syslog, identifiers, SIDs, GUIDs, PIDs, and hashes are consistently well formed.
- **Temporal patterns:** 7 — Subsecond source offsets, burstiness, and lifecycle ordering are strong, but repeated desktop reconstruction inside unchanged sessions is implausible.
- **Cross-source correlation:** 8 — Process records, identities, hashes, and timing correlate exceptionally well; the score is reduced because the same incorrect session parent truth propagates across sources.
- **Behavioral realism:** 5 — Role-shaped activity is present, but repeated Explorer bootstraps and reusable Linux command sequences are conspicuous synthetic textures.
- **Environmental consistency:** 6 — Host-specific service mixes are convincing, while frequent similarly constructed desktop sessions on infrastructure roles weaken the environment model.

## Recommendations

- If this were synthetic, construct each Windows interactive desktop from one session-owned `winlogon.exe` → `userinit.exe` → `explorer.exe` chain. Never use `services.exe` as the parent of an ordinary user's Explorer; preserve the actual user-session parent identity in Sysmon, Security 4688, and eCAR together.
- If this were synthetic, make shell restart/recovery lifecycle explicit. A genuine Explorer restart should normally be a new Explorer under an appropriate user-session process and should not rerun `userinit.exe`; a new login should receive a new LogonId and corresponding 4624/interactive lifecycle evidence.
- If this were synthetic, reduce cross-user reuse of exact Linux administrative sequences. Condition commands on host role, user specialty, current task, shell history, and prior output, and retain a longer tail of user-specific aliases, paths, options, errors, and follow-up commands.
- If this were synthetic, moderate full GUI logons on domain controllers and other infrastructure servers unless the visible operational context requires them; use remote administration, MMC/RSAT, PowerShell remoting, SSH, or service-control paths where those better fit the role.
