# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 91  
**Synthetic-Confidence Score:** 84

## Executive Summary

The dataset contains unusually strong source-native detail and largely coherent Windows, Linux,
and EDR correlations, but two visible endpoint lifecycle defects outweigh that realism. Most
decisively, every sampled `winlogon.exe` process is assigned terminal session 0 while its direct
`userinit.exe` child is assigned the real interactive/RDP session, and the mail host accumulates
many overlapping instances of executables that represent singleton Exchange services.

## Evidence For Synthetic

- `[hard_contradiction]` The Sysmon process-session model is wrong for every visible
  `winlogon.exe`/`userinit.exe` chain. Across 14 chains on seven hosts, `winlogon.exe` has
  `TerminalSessionId=0`, while its direct child has a nonzero session ID. On
  `WS-AJOHNSON-01`, PID 5976 at `2024-03-18T15:00:29.5013547Z` has session 0, but child PID
  5980 at `15:00:29.7008245Z` has session 4; PID 6008 at `15:20:34.7097858Z` has session 0,
  but child PID 6024 at `15:20:34.9095282Z` has session 5. A process and its login-shell child
  cannot belong to different terminal sessions in this way.
- `[contract_gap]` The same session defect crosses source boundaries. The eCAR creation for
  `WS-AJOHNSON-01` PID 5428 at epoch-ms `1710769169351` carries `session_id=2`, while the
  matching Sysmon Event 1 at `2024-03-18T13:39:29.0251140Z` says
  `TerminalSessionId=0`; its `userinit.exe` child correctly uses session 2. The mismatch is
  therefore not explainable as a missing pre-window initiator or merely different coverage.
- `[contract_gap]` Several remote-interactive chains compound the session error with an invalid
  parent representation: `winlogon.exe` is shown as a direct child of PID 4 with
  `ParentImage=-`. Examples include `WS-AJOHNSON-01` PIDs 5976 and 6008,
  `FILE-SRV-01` PID 6116 at `17:06:19.3817720Z`, and `DC-01` PID 5652 at
  `17:09:56.7432650Z`. Real session initialization should retain the session-manager parent and
  the new session identity.
- `[contract_gap]` `MAIL-FIN-01` repeatedly launches overlapping copies of apparent singleton
  Exchange service executables from the same `services.exe` parent (PID 2376). The six-hour
  window contains 15 `EdgeTransport.exe -service` starts and 11
  `Microsoft.Exchange.Imap4.exe` starts. At the end of the window, ten Edge Transport and seven
  IMAP service processes remain unterminated; many overlap for hours—for example Edge Transport
  PIDs 4148, 3908, 4060, 4076, 3808, and 4080 are concurrently alive by
  `2024-03-18T13:44:57Z`. That is not a credible lifecycle for these service hosts.
- `[distribution_texture]` Host process telemetry is too thin and too concentrated in a small
  recurring pool for what otherwise looks like broad, unfiltered Security/Sysmon/eCAR coverage.
  There are only 930 Security 4688 events and 926 Sysmon Event 1 records across ten Windows hosts
  over roughly six hours—about 15 process creations per host-hour. Server records are dominated
  by repeated `taskhostw.exe`, `WmiPrvSE.exe`, `dllhost.exe`, and `conhost.exe` launches; for
  example, 100 DC-02 process starts use only 19 distinct command lines.
- `[distribution_texture]` Short-lived updater-service behavior repeats across unrelated
  workstations. `AdobeARMservice.exe`, always parented by `services.exe`, starts five times on
  `WS-MCHEN-01` and three times on `WS-DRAMIREZ-01`; all visible instances terminate after only
  10–69 seconds. This is possible as an updater pattern, but the repeated service shape adds to
  the broader lifecycle-template signal.
- `[environment_or_collection_plausibility]` DC-02 contains active desktop-shell artifacts for
  multiple ordinary users despite showing no visible type 2 or type 10 logon in the six-hour
  slice: `explorer.exe` for `aisha.johnson` loads a 7-Zip shell extension at
  `12:18:14.7746580Z`, while another `explorer.exe` for `marcus.chen` performs DNS activity and
  loads the OneDrive shell extension at `12:34:33.9503055Z`. Pre-window sessions are possible,
  so this is only supporting host-role evidence, not a missing-initiator claim.

## Evidence For Real

- Windows event schemas are detailed and internally credible. Security events use appropriate
  hexadecimal process/logon identifiers and event-specific fields; Sysmon records contain
  realistic process GUIDs, four-part hash sets, parent context, signature state, call traces,
  and source-native timestamp precision.
- The apparent Security log clear on DC-01 is modeled convincingly. Event 1102 at
  `2024-03-18T17:41:59.2606262Z` uses the Eventlog provider, carries the SYSTEM subject in
  `UserData`, and is followed by `EventRecordID=1`; later IDs increase from the reset value.
- Cross-source process correlation is excellent without visible command-line contradictions.
  Of 930 Security 4688 records, 923 have matching Sysmon Event 1 PID/image/command-line records
  within approximately 0.04–0.65 seconds. eCAR-to-Sysmon comparison similarly matched 917
  process creations with identical command lines and principals, with only a handful of
  collection gaps.
- Visible process lifecycle ordering is sound outside the specific session/service defects.
  No Sysmon process creation/termination pair is reversed. Sysmon network, module, file,
  registry, process-access, and remote-thread events do not reference a visibly later process
  creation or occur after a visible termination for the same ProcessGUID.
- Hash and identity behavior is convincing. Hashes remain stable for the same image/version,
  while Windows binaries from different OS builds have different version/hash combinations.
  ProcessGUID host prefixes are stable per host and unique across hosts.
- Linux SSH and privilege lifecycles are notably realistic. Forty-one visible successful SSH
  connections follow connection → accepted authentication → PAM open ordering with no reversed
  sequences. Forty-six visible logind session IDs have matched removals with no removal before
  creation, and 78 successful sudo groups follow command → PAM open → PAM close; two denied sudo
  commands correctly omit session-open/session-close records.
- Linux background evidence has credible source-native texture: per-host CRON offsets, kernel,
  irqbalance, rsyslog queue, snapd, NetworkManager, systemd-resolved, SMB, mail, and package-update
  messages are interleaved with user activity rather than appearing as a single generic noise
  stream.
- User behavior is differentiated. `lina.nguyen` uses Git, npm, Docker, Kubernetes, editors, and
  build tools; `omar.haddad` uses pandas and accesses claims-oriented material; administrative
  users perform service, storage, authentication, and network checks. Bash-history spacing is
  irregular, commands are mostly unique, and histories include both short bursts and long gaps.

## Detailed Analysis

### Scope and collection window

I examined only files beneath the supplied data directory. Host evidence covers 21 eCAR streams,
ten Windows Security/Sysmon pairs, eleven Linux-style syslog streams, and per-user bash histories.
The visible Windows files span approximately `2024-03-18T12:00Z` through `18:00Z`. I treated
unmatched starts/ends near those boundaries as neutral unless the same visible identifier showed
an impossible in-window order.

### Windows process trees and terminal sessions

The ordinary process graph is mostly strong. Visible parents precede children, parent GUIDs do
not self-reference, and common chains such as `winlogon.exe` → `userinit.exe` → `explorer.exe`
have sub-second ordering. The defect is that the session value on the parent is systematically
wrong: all 14 visible `winlogon.exe` Event 1 records use terminal session 0 while their linked
`userinit.exe` children use sessions 1, 2, 3, 4, 5, or 7. Representative examples are:

| Host | winlogon PID/time/session | userinit PID/time/session | Parent shown for winlogon |
|---|---|---|---|
| WS-AJOHNSON-01 | 5976 / 15:00:29.501 / 0 | 5980 / 15:00:29.701 / 4 | PID 4, image `-` |
| WS-AJOHNSON-01 | 6008 / 15:20:34.710 / 0 | 6024 / 15:20:34.910 / 5 | PID 4, image `-` |
| DC-01 | 5652 / 17:09:56.743 / 0 | 5656 / 17:09:56.942 / 5 | PID 4, image `-` |
| FILE-SRV-01 | 6116 / 17:06:19.382 / 0 | 6120 / 17:06:19.580 / 7 | PID 4, image `-` |

This pattern is not a normal distinction between a SYSTEM principal and a user principal:
`TerminalSessionId` describes the process session, not the account's logon ID. It also cannot be
explained by the collection boundary because both parent and child starts are visible and share
an explicit ParentProcessGUID relationship. The eCAR record for the local AJOHNSON session makes
the contradiction direct: its matching winlogon process has `session_id=2`, while Sysmon emits 0.

### Windows service lifecycles

Short-lived COM/WMI/task-host activity has varied intervals and believable durations. The
Exchange service population on `MAIL-FIN-01` is qualitatively different. All repeated
`EdgeTransport.exe` and `Microsoft.Exchange.Imap4.exe` processes have the same
`services.exe` parent, yet new instances are created while prior instances remain alive.

For Edge Transport, starts at `13:08:01`, `13:17:18`, `13:17:34`, `13:24:07`, `13:27:56`, and
`13:44:57` overlap; only five of the 15 instances terminate within the window. IMAP shows the
same accumulation, with eleven starts and only four observed terminations. Boundary truncation
can explain a process still running at 18:00, but it cannot explain many same-service instances
being visibly started while earlier ones are still active. The data would be more credible if
these represented a single durable service process plus separately named worker processes, or
if each restart followed a visible termination.

### Security, Sysmon, and eCAR correlation

Security 4688, Sysmon Event 1, and eCAR PROCESS/CREATE are tightly aligned. Matching commands,
PIDs, users, and images agree, and the timing lag is small but not bit-identical: Sysmon normally
precedes Security by tens to hundreds of milliseconds, while eCAR follows Sysmon by a few to
roughly 850 milliseconds. Complete correlation was not scored as synthetic by itself.

Process termination and dependent evidence are similarly coherent. Across Sysmon Event IDs 3,
7, 8, 10, 11, 13, and 22, I found no visible create-after-use or use-after-termination for the
same ProcessGUID. Remote-thread examples preserve source/target identities, including the
`ms-index-service.exe` → `lsass.exe` activity on `WS-AJOHNSON-01` at
`15:45:00.0736289Z`. Security logon/logoff and process-start/process-end pairs also have no
visible reversed ordering.

The main distribution concern is volume. The same collection includes 11,579 Security 5156
events but only 930 process starts across ten Windows hosts. With near-complete 4688/Sysmon/eCAR
agreement, the process stream looks less like random collection loss and more like a deliberately
small behavioral catalog. The server command-line concentration—especially 19 unique commands
among 100 starts on DC-02—reinforces this concern, although filtering could partially explain it.

### Linux endpoint evidence

The Linux evidence is one of the strongest realistic portions. Successful SSH sessions retain a
single sshd PID from connection through authentication and PAM close. systemd-logind session IDs
are consistent, and pre-window closes occur without being misclassified as impossible. Sudo
records use realistic priorities and preserve command/open/close sequencing; denied commands on
PROXY-01 and WEB-EXT-01 correctly stop after the denial.

Background syslog has useful role specificity: SMB audit traffic on the file host, Postfix and
Dovecot on mail hosts, proxy-oriented checks on PROXY-01, and database commands on DB-PROD-01.
The general daemon facility used by Postfix/Dovecot is unusual relative to common defaults but is
configurable, so I treated it as neutral-to-weak evidence rather than a contradiction.

### User and environmental behavior

User activity has more entropy than a simple common command pool: work patterns, tools, target
hosts, and history gaps vary by user. The main environmental concern is desktop activity on a
domain controller. DC-02 has long-lived pre-window `explorer.exe` processes for two named users,
including 7-Zip and OneDrive shell-extension loads. This is possible in a poorly administered or
compromised environment, and the initiating logons may precede the window, so it only modestly
affects the score.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Impact on score |
|---|---|---|---|
| `hard_contradiction` | Sysmon process/session | Dataset-wide across 14 visible login chains | `winlogon.exe` is placed in session 0 while its direct user shell is placed in the actual interactive/RDP session. |
| `contract_gap` | Sysmon ↔ eCAR | Repeated across local and remote session paths | eCAR can carry the nonzero winlogon session while Sysmon emits 0; remote paths also substitute PID 4/unknown image for the session-manager parent. |
| `contract_gap` | Sysmon/Security/eCAR process lifecycle | Repeated on MAIL-FIN-01 | Singleton Exchange service executables accumulate overlapping live instances. |
| `distribution_texture` | Security 4688, Sysmon 1, eCAR PROCESS | Environment-wide | Very low process volume and a narrow recurring server command pool contrast with otherwise broad endpoint coverage. |
| `distribution_texture` | Sysmon/eCAR service processes | Repeated on two workstations | Adobe updater-service executions recur with a similar short-lived shape. |
| `environment_or_collection_plausibility` | Sysmon endpoint activity | Localized to DC-02 | Multiple ordinary-user desktop shells and consumer shell extensions run on a domain controller. |

## Realism Score by Category

- **Field format accuracy:** 9/10 — Windows XML, Sysmon fields, RFC5424 syslog, IDs, GUIDs,
  hashes, and timestamps are generally source-native and parseable.
- **Temporal patterns:** 7/10 — Fine-grained event ordering is strong, but overlapping singleton
  service processes and the thin recurring process pool are conspicuous.
- **Cross-source correlation:** 8/10 — Most PID, command, principal, and lifecycle relationships
  agree; the winlogon session mismatch is a serious exception.
- **Behavioral realism:** 7/10 — User and Linux activity are diverse, while Exchange and updater
  service lifecycles look templated.
- **Environmental consistency:** 7/10 — Host roles are mostly reflected in activity, but DC
  desktop usage and the mail-service population weaken plausibility.

## Recommendations

If this were synthetic, the following changes would most improve authenticity:

1. Make terminal session identity canonical across login/session process bundles. Assign
   `winlogon.exe`, `userinit.exe`, and `explorer.exe` the same nonzero terminal session for local
   and remote interactive logons, and preserve that value identically in Sysmon and eCAR.
2. Model the actual Windows session bootstrap parent chain. Remote-session `winlogon.exe` should
   retain the appropriate `smss.exe` parent identity rather than defaulting to PID 4 with an
   unknown parent image.
3. Treat long-lived services as durable state. Before starting another singleton Exchange
   service executable, terminate the prior instance or model a correctly named worker process;
   add an invariant that rejects overlapping singleton service lifetimes.
4. Increase process-volume and long-tail diversity in proportion to the apparent collection
   profile, especially on domain controllers and servers. Add ordinary service helpers,
   maintenance processes, management agents, and role-specific workers without relying mainly on
   the same WMI/COM/task-host command set.
5. Review updater-service cadence and lifecycle. If `AdobeARMservice.exe` is intended to be a
   durable service, keep it alive; if it is a scheduled helper, use the source-native updater
   executable and parent chain for that behavior.
6. Reduce ordinary-user desktop residue on domain controllers unless visible evidence supports
   an administrative or compromised session. If retained, make the role anomaly explicit in the
   endpoint lifecycle rather than leaving only pre-window shell artifacts.
