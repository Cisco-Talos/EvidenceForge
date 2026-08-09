# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 84  
**Synthetic-Confidence Score:** 67

## Executive Summary

The endpoint telemetry is technically strong: Windows Security, Sysmon, and eCAR records correlate closely; process and SSH lifecycles are internally ordered; and source-native fields, hashes, record IDs, and role-specific Linux activity are convincing. The decisive defect is repeated implausible Windows process ancestry: 12 OpenSSH client launches on two workstations are attributed to unrelated Firefox, Edge, or Outlook processes whose command lines show ordinary web browsing or mail activity, a cross-source pattern more consistent with faulty synthetic parent selection than organic endpoint behavior.

## Evidence For Synthetic

- `[environment_or_collection_plausibility]` Twelve `ssh.exe` process creations across `WS-AJOHNSON-01` and `WS-MCHEN-01` have unrelated browser or Outlook parents: seven on Aisha's workstation and five on Marcus's. Examples include:
  - `2024-03-18T12:04:21.7092321Z`, `WS-AJOHNSON-01`, Sysmon Event 1: `ssh.exe aisha.johnson@MAIL-CLIN-01...`, PID 5380, parent Firefox PID 5192, whose parent command is `"firefox.exe" -osint -url http://WEB-EXT-01/`.
  - `2024-03-18T15:05:09.9290142Z`, same host: `ssh.exe ...@DB-PROD-01`, parent `OUTLOOK.EXE /recycle`.
  - `2024-03-18T15:41:53.7988755Z`, `WS-MCHEN-01`: `ssh.exe ...@WEB-EXT-01`, parent Edge with `--single-argument http://WEB-EXT-01/login`.
  This is possible at the API level, but no visible protocol-handler or intermediary shell explains it, and its repetition across independent applications and hosts is not normal user-launched SSH ancestry.
- `[contract_gap]` The bad parentage is canonical rather than an isolated rendering error. For the 12:04:21 PID 5380 example, Security 4688 at `12:04:21.7078290Z`, Sysmon 1 at `12:04:21.7092321Z`, and eCAR PROCESS/CREATE at `12:04:22.365Z` all identify Firefox PID 5192 as the parent. The sources agree precisely on an implausible ownership relationship.
- `[distribution_texture]` The anomalous ancestry is systematic: of 67 visible Windows `ssh.exe` creates on the two administrative workstations, 12 (17.9%) use a browser or Outlook parent. A one-off custom handler could be explained; a repeated multi-application pattern on two hosts resembles parent sampling from the user's active process pool.
- `[environment_or_collection_plausibility]` Process-creation volume is thin for apparently comprehensive endpoint auditing. Across nine Windows hosts there are 914 Security 4688 events over six hours, with 911 Sysmon Event 1 records. The six active Windows workstations collectively produce only 543 4688s, about 15 process creates per host-hour, despite active browsers, Outlook, SSH, RDP, update agents, search, and other user activity. The near-total Security/Sysmon agreement implies broad collection, making the low lived-in process churn somewhat difficult to attribute solely to filtering.
- `[weak_signal]` Some workstation interactive-logon patterns look manufactured. `WS-MCHEN-01` records three type-2 logons for `marcus.chen` between `12:27:54Z` and `12:41:21Z` under different logon IDs, while `WS-SMARTINEZ-01` records two type-2 logons for `sophia.martinez` only 14 seconds apart. These are possible, including through secondary logon behavior, but no visible 4648 or process context explains every duplicate console-style session.

## Evidence For Real

- Windows process correlation is excellent. All 914 Security 4688 records have a same-host eCAR or Sysmon counterpart except for a small, explainable observation gap: 911 Sysmon Event 1 records and roughly 906 eCAR creates. For matched Security/Sysmon creates, median timestamp offsets are approximately 1–4 ms on each host, with matching PID, image, user, command line, and parent.
- Hash behavior is coherent. Across all nine Windows Sysmon files, no image path had conflicting Event 1 hash sets, and all 911 observed ProcessGUIDs were unique.
- Windows event-log mechanics are particularly convincing. EventRecordIDs are unique and monotonic in every channel except the expected reset on `DC-01`: Security record `28262029` is followed by Event 1102 at `2024-03-18T17:42:30.4513637Z` with record ID 1, then the next event has record ID 2.
- Process lifecycle ordering is sound. Across 1,344 eCAR create/terminate pairs, none has a negative duration. Among 506 child creates whose parent create is visible, no child predates its parent and none starts after the parent's termination.
- Linux SSH sequences have realistic source-native structure. There are 101 accepted authentications; 96 visible sessions have same-PID ordering from connection/authentication to PAM open and later close. Remaining sessions are chiefly right-censored at the beginning or end of the six-hour window.
- Linux role texture is differentiated. Mail systems emit Postfix/Dovecot activity, `WEB-EXT-01` has substantial kernel/UFW and web-server texture, `DB-PROD-01` shows MySQL operations, and workstation histories contain desktop/network-management activity.
- User behavior is differentiated rather than cloned. Lina Nguyen's history emphasizes Git, Docker, and SSH; Aisha Johnson and Marcus Chen perform cross-server administration; Omar Haddad runs database queries and desktop applications; Priya Patel performs audit/network checks.
- Windows role texture also varies appropriately: DC and file-server hosts are dominated by type-3/type-5 sessions and system-owned processes, while user workstations show type-2/type-7 activity, lock/unlock events, browsers, mail clients, VPN software, and user-owned remote-admin tools.
- Lifecycle boundaries are handled plausibly. Some termination/logoff records have pre-window starts, while late SSH and interactive sessions remain open beyond the dataset. The data does not force artificial closure at the collection boundary.

## Detailed Analysis

### Scope and volumes

The dataset covers six hours, approximately `2024-03-18T12:00Z` through `18:00Z`, across nine Windows and nine Linux hosts with eCAR on every endpoint. Windows Security contains 11,? endpoint records overall, including 914 process creates, 733 process terminations, 1,102 successful logons, and 748 logoffs. The logon mix is environment-sensitive: the domain controller alone has 597 successful logons, predominantly type 3 and type 5, while user workstations have much smaller mixed populations.

The Linux syslogs contain several thousand records with host-dependent density. `WEB-EXT-01` has 1,662 lines, including 966 kernel records, while quieter workstations have roughly 228–243 lines. Bash histories contain 258 timestamped commands across 15 non-empty user histories.

### Windows process trees

Most system ancestry is plausible:

- `services.exe` launches `svchost.exe`, service executables, monitoring agents, Defender tooling, and server applications.
- `SearchIndexer.exe` launches `SearchProtocolHost.exe` and `SearchFilterHost.exe`.
- `csrss.exe` launches `conhost.exe`.
- `svchost.exe` launches task-host, WMI, COM, and scheduled-task-related processes.
- User applications generally descend from `explorer.exe`.

The repeated browser/mail-to-SSH lineage is the major exception. The clearest example is PID 5380 on `WS-AJOHNSON-01`:

- Security 4688 at `12:04:21.7078290Z`: new image `C:\Windows\System32\OpenSSH\ssh.exe`, command `ssh.exe aisha.johnson@MAIL-CLIN-01...`, creator PID `0x1448`, parent image Firefox.
- Sysmon 1 at `12:04:21.7092321Z`: PID 5380, parent PID 5192/Firefox, parent command browsing `http://WEB-EXT-01/`.
- eCAR PROCESS/CREATE at `12:04:22.365Z`: PID 5380, PPID 5192, the same Firefox parent and user.
- Sysmon 22 at `12:04:34.200Z`, Sysmon 3 at `12:04:36.081Z`, and eCAR FLOW at `12:04:36.450Z` then carry that process into a real SSH connection to `10.10.2.26:22`.

Thus, correlation quality makes the semantic error more convincing, not less. Similar ancestry recurs from Firefox browsing `webex.com` or `upload.wikimedia.org`, from Edge browsing a web login page, and from Outlook `/recycle`.

### Process lifecycle and identity

eCAR has 1,344 paired process lifecycles with durations from subsecond utilities to multi-hour applications and services; no terminate precedes create. Unpaired creates and terminations are distributed at both dataset boundaries and among long-lived processes rather than forming obvious same-window contradictions.

Security/Sysmon identity is strong. Every host has unique ProcessGUIDs, and same-image hashes remain constant. Security/Sysmon process-create times differ by only milliseconds, while eCAR generally follows by a subsecond collection delay. This is a realistic relationship among native eventing and endpoint telemetry.

### Windows logons

The 1,102 successful Security 4624 records comprise approximately 744 type-3, 326 type-5, 12 type-10, 11 type-2, and 10 type-7 logons. Type-3 sessions commonly close within seconds to tens of seconds, while interactive and RDP sessions last hours or remain open beyond the window. Workstation lock/unlock sequences use the same logon ID:

- `WS-PPATEL-01`, `14:40:40.626Z`: Event 4800 for logon `0xd8d7b28`.
- `14:43:45.403Z`: type-7 4624 for the same logon ID.
- `14:43:45.976Z`: Event 4801.

The same pattern repeats with varied lock durations on multiple hosts. Service logons remaining open are not inherently defective because services commonly outlive the collection window.

The repeated type-2 sessions on `WS-MCHEN-01` and `WS-SMARTINEZ-01` are less persuasive, especially when the same user obtains multiple console-style logon IDs within seconds or minutes without an obvious secondary-logon chain. I treated this as a weak indicator rather than a contradiction.

### Linux authentication and command behavior

SSH evidence is one of the most realistic areas. On `PROXY-01`, for example, PID 4007605 has public-key acceptance for `priya.patel` at `12:14:43.950760Z`, PAM open at `12:14:44.075025Z`, and PAM close at `12:24:55.192306Z`. Session lengths vary from minutes to hours; methods vary between passwords and public keys; users have stable but distinct key fingerprints; and same-host overlapping sessions occur naturally.

The syslog population has useful environmental noise: `irqbalance`, `systemd-resolved`, `snapd`, `NetworkManager`, `dhclient`, `CRON`, package management, journald, mail daemons, desktop services, and UFW blocks appear in role-appropriate proportions. Bash-history inter-command intervals range from a few seconds to multi-hour gaps. Of 258 commands, 201 are unique; repeated commands are mostly credible administrative staples or repeated SSH targets rather than exact multi-user scripts.

There is one mild cross-distribution oddity: `DB-PROD-01` contains a `yum check-update` history command despite other visible Debian/Ubuntu-style administration such as `/usr/bin/apt`. Since failed or mistaken commands remain in history, this alone is not meaningful evidence.

### Collection and temporal behavior

Timestamps are monotonically ordered within every XML file. Windows channel record IDs behave like native counters, including the audit-clear reset on the domain controller. Source latencies are stable without being bit-identical: Security and Sysmon typically differ by milliseconds; eCAR usually follows by fractions of a second; DNS/network events follow process creation by plausible seconds.

The process-create volume remains unusually sparse relative to the apparent completeness of collection. It is not an impossibility—selection or an endpoint policy may explain it—but it weakens the lived-in feel of the Windows workstations more than absent event families would.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Impact |
|---|---|---:|---|
| `environment_or_collection_plausibility` | Security 4688, Sysmon 1, eCAR PROCESS | 12 SSH creates on 2 workstations | Repeated Firefox/Edge/Outlook parents for ordinary SSH commands are not credible normal ancestry. |
| `contract_gap` | Security/Sysmon/eCAR | Same 12 events | Three independent endpoint renderings preserve the same bad parent identity, indicating an upstream ownership defect. |
| `distribution_texture` | Windows process trees | 12 of 67 SSH creates (17.9%) on the affected admin workstations | Multi-host, multi-application repetition makes a custom-handler explanation unlikely. |
| `environment_or_collection_plausibility` | Windows Security/Sysmon | 914 creates over 54 host-hours | Process churn is low for seemingly broad process auditing and active endpoints. |
| `weak_signal` | Windows Security logons | 2 workstations | Rapid duplicate type-2 sessions lack visible explanatory context but remain technically possible. |

## Realism Score by Category

- **Field format accuracy:** 9 — Windows XML, Sysmon fields, RFC-style syslog, hashes, GUIDs, PIDs, and event-record mechanics are highly convincing.
- **Temporal patterns:** 8 — Lifecycle ordering, boundary censoring, SSH timing, and source latency are strong; process density is somewhat thin.
- **Cross-source correlation:** 8 — Security, Sysmon, eCAR, and Linux session evidence align exceptionally well, although that alignment preserves the parent-ownership defect.
- **Behavioral realism:** 6 — User and host roles are differentiated, but browser/mail applications repeatedly spawning SSH is a significant behavioral failure.
- **Environmental consistency:** 6 — Host roles and daemon populations are good; anomalous Windows ancestry and sparse process churn reduce the lived-in feel.

## Recommendations

- If this were synthetic, model Windows user-launched SSH through a canonical shell or launcher process. Use `explorer.exe` only when appropriate, or create a visible `cmd.exe`, PowerShell, Windows Terminal, or explicit protocol-handler intermediary. Do not select an arbitrary active browser or mail client as parent.
- Add validation that flags unlikely parent-child pairs such as Outlook/Firefox/Edge directly spawning `ssh.exe`, especially when the parent's command line is unrelated to SSH or a registered protocol invocation.
- Preserve the excellent parent identity consistently across Security, Sysmon, and eCAR, but validate semantic plausibility before rendering the shared relationship.
- Increase ordinary Windows workstation process churn or make selective collection visible in the collection profile. Browser subprocesses, updater helpers, office child processes, scheduled tasks, and short-lived utilities should create a more credible volume if 4688 and Sysmon 1 are intended to be comprehensive.
- Tie additional type-2 logons to visible causes such as explicit-credential use, fast user switching, or a process/session transition; otherwise reuse the active console session and represent unlocks as type 7.
