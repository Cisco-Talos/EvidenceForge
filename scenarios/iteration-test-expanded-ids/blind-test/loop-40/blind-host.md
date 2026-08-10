# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 66

## Executive Summary

The telemetry is technically strong: Windows Security, Sysmon, and eCAR process records correlate almost perfectly, process and session lifecycles are temporally coherent, and Linux logs contain convincing host-role detail. I nevertheless assess it as synthetic because several dataset-wide textures are difficult to reconcile with organic endpoint activity—most notably repeated Outlook/browser-to-`ssh.exe` parentage across unrelated users and a highly quantized UFW scan population whose TCP windows divide almost perfectly among three values.

## Evidence For Synthetic

- `[environment_or_collection_plausibility]` Thirteen Windows `ssh.exe` launches have browsers or Outlook as their direct parent, spread across three user endpoints and hours of activity. Examples include Firefox → `ssh.exe aisha.johnson@PROXY-01...` at `2024-03-18T12:27:46.9212738Z`, Outlook → `ssh.exe marcus.chen@DB-PROD-01...` at `15:24:44.5085239Z`, and Outlook → `ssh.exe root@WEB-EXT-01...` under `sophia.martinez` at `13:39:57.2807471Z`. A custom URI handler could explain an isolated event, but this repeated behavior across Firefox, Edge, and Outlook resembles synthetic parent selection more than ordinary Windows administration.
- `[distribution_texture]` `WEB-EXT-01/syslog.log` contains 991 UFW blocks whose TCP windows are almost exactly flat across only three values: `65535` 333 times, `14600` 333 times, and `1024` 325 times. Every dominant scanner IP cycles among all three window values at near-even frequencies, while retaining an invariant TTL and packet length. That combination looks like independent selection from a small enumerable pool rather than packets emitted by stable remote TCP stacks.
- `[distribution_texture]` The UFW background is also unusually pool-bound: 985 of 991 blocks come from eight IP addresses, and destination ports come from a short repeated set led by 23 (186), 25 (130), 445 (97), 3389 (85), and 22 (75). Repeated scanning is credible, but the small actor/port vocabulary coupled with the three-value window distribution is strongly generator-like.
- `[distribution_texture]` Of 890 Security 4688/Sysmon Event 1 pairs matched by PID, image, and command line, 888 have timestamp differences within roughly ±21 ms, with approximately half on either side of zero; only two outliers appear at about 117 and 205 ms. This bounded, bidirectional jitter profile across nine machines resembles a deliberately sampled observation offset more than independently timestamped provider pipelines.
- `[distribution_texture]` Windows background-process vocabulary is highly repetitive across dissimilar endpoints. Examples include 29 `services.exe` → `DropboxUpdate.exe /svc` launches, 18 `services.exe` → `powershell.exe ... C:\Scripts\service-health.ps1`, and recurring identical `taskhostw.exe`, `wsqmcons.exe`, updater, and search-host command lines. Enterprise standardization explains some repetition, but the breadth of exact reuse and relatively shallow long tail adds to the synthetic impression.
- `[weak_signal]` Bash histories repeatedly draw exact commands from a shared administrative vocabulary across users and hosts (`cat /etc/fstab`, `ss -tulnp`, `cat /proc/version | cut -d' ' -f1-3`, `journalctl -p err --no-pager -n 10`). The histories do preserve role differences, so this is supportive rather than decisive.

## Evidence For Real

- Process correlation is excellent at the field level. Across nine Windows hosts, 890 of 893 Sysmon Event 1 records match Security 4688 by PID, image, and command line. eCAR also agrees on nearly every corresponding creation.
- Process lifecycles are internally sound. Across 1,700 eCAR process creates and 1,395 terminations, I found no termination preceding its matching creation, no overlapping reuse of a PID, and no actor-dependent event outside the known parent process lifetime.
- Parent-child relationships are mostly source-native and plausible: `services.exe` → `svchost.exe` (103), `svchost.exe` → `taskhostw.exe` (100), `svchost.exe` → `WmiPrvSE.exe` (90), `csrss.exe` → `conhost.exe` (69), and `SearchIndexer.exe` → search filter/protocol hosts.
- Windows logons contain a credible mix of types 2, 3, 5, 7, and 10. Type 3 sessions commonly last seconds, while interactive or remote sessions extend for hours. Workstations include 4800/4801 lock/unlock evidence.
- The DC’s Security-log clear is rendered coherently: `cmd.exe /c wevtutil cl Security` at `17:41:42.0784106Z`, child `wevtutil.exe` at `17:41:42.4774632Z`, Event 1102 as record 1 at `17:41:43.5234846Z`, and subsequent record numbers restart from low values.
- Linux syslog has credible lifecycle texture: paired PAM opens/closes, SSH events, sudo command/open/close sequences, cron, anacron/logrotate, package maintenance, NetworkManager/dhclient, mail-daemon, and desktop-service activity.
- Cron phase differs by host rather than aligning globally. For example, `LT-MRIVERA-02` runs sysstat around `:02/:32`, while `WS-OHADDAD-01` runs around `:07/:37`.
- User behavior is differentiated: Lina Nguyen shows Git, build, Docker, Kubernetes, and SSH activity; Omar Haddad uses pandas, CSV/XLSX discovery, PostgreSQL, browser, and SMB browsing; mail servers show Postfix/Dovecot; the DB server shows MySQL maintenance.
- Hashes remain stable for each image/build while differing across apparent Windows build families. Core binaries such as `svchost.exe`, `taskhostw.exe`, `WmiPrvSE.exe`, and PowerShell have four cross-host hash clusters rather than one universal value.

## Detailed Analysis

### Corpus and coverage

The six-hour window runs approximately from `2024-03-18T12:00Z` to `18:00Z`. I examined host evidence from 18 eCAR files containing 25,535 records, nine Windows Security logs containing 13,985 events, nine Sysmon logs containing 4,362 events, nine Linux syslogs containing 4,166 lines, and 18 bash-history files containing 434 lines.

eCAR is network-heavy—16,057 FLOW records—but still provides 1,700 process creates, 1,395 terminations, 1,259 logins, 866 logouts, 2,555 module loads, 696 registry modifications, 540 process opens, and 457 file operations.

### Windows process trees

Most parent-child pairs are convincing and appropriately role-specific. Server systems show service-hosted processes, WMI, IIS, DFSR, Exchange transport, monitoring, backup, and update activity. User endpoints show browsers, Outlook, Dropbox, VPN, collaboration software, development tools, and remote administration.

The prominent exception is direct GUI-application spawning of OpenSSH. The anomalous set consists of six Firefox → SSH events on `WS-AJOHNSON-01`, one Edge → SSH and five Outlook → SSH events on `WS-MCHEN-01`, and one Outlook → SSH event on `WS-SMARTINEZ-01`. The target hosts vary among proxy, database, application, web, and mail systems, so this is not one repeatable application integration. The Sophia Martinez event is particularly odd because Outlook launches `ssh.exe root@WEB-EXT-01...` while the process user remains `MERIDIANHCS\sophia.martinez`.

### Security/Sysmon/eCAR correlation

Correlation quality is high:

- `DC-01`: 158/158 Security 4688 records match Sysmon Event 1 and eCAR.
- `WS-MCHEN-01`: 128/128 match both.
- `MAIL-FIN-01`: 109/109 match both.
- Most remaining hosts differ by only one or two records, consistent with source observation boundaries.

A representative record on `WS-MCHEN-01` is Security 4688 at `12:04:45.7888215Z` for PID `0x1de0`, `C:\Windows\System32\OpenSSH\ssh.exe`, command `ssh.exe marcus.chen@APP-INT-01...`, followed by Sysmon Event 1 at `12:04:45.7922602Z` for PID 7648 with the same user, image, command line, parent PID 6640, and parent image `explorer.exe`.

The correlations themselves support realism. What raises concern is their timestamp-error distribution: nearly every paired event is confined to a narrow ±20 ms band, and the sign varies symmetrically. That looks more like an applied jitter model than consistent provider/collector latency.

### Process lifecycle

No negative-duration process lifecycle was found. For actor IDs resolvable to a process, I checked dependent module, process-open, flow, file, registry, and related activity; none occurred before the process creation or after its termination.

Unpaired endpoints are explainable at the six-hour capture boundaries. Servers have more persistent creations without termination, while many short-lived Linux processes are paired. For example, `APP-INT-01` has 159 creates, 150 terminations, and 147 same-object pairs; `WEB-EXT-01` has 143 creates, 141 terminations, and 132 pairs. Windows workstations preserve longer-running GUI processes through the end of the window.

### Logon lifecycle

Windows logon distribution fits host roles. `DC-01` has 436 Type 3, 135 Type 5, and five Type 10 successes; `FILE-SRV-01` has 252 Type 3, 69 Type 5, and three Type 10; workstations generally have one Type 2 interactive session, several service and network logons, occasional Type 7 unlocks, and sparse Type 10 remote sessions.

Paired Type 3 durations commonly fall between roughly 1 and 55 seconds, while the maximum paired lifetimes reach 21,025 seconds on the DC and 11,738 seconds on a workstation. The mix is believable. Failure codes are also coherent: workstation failures commonly use `0xc000006d/0xc000006a` for bad passwords, while stale-account failures use `0xc000006d/0xc0000072`.

### Linux host evidence

The syslogs are richer than simple SSH renderings. `MAIL-EDGE-01` includes Postfix SMTP/queue/cleanup/local activity, Dovecot sessions, resolver events, package maintenance, sudo, PAM, and cron. `LT-MRIVERA-02` and Linux workstations include NetworkManager, dhclient, packagekit/fwupd, desktop login, and peripheral services. PAM session IDs remain paired where both endpoints are visible.

Bash histories broadly fit personas and host roles. Lina’s workstation history contains repeated SSH plus Git/build/Kubernetes work; Omar’s contains data-analysis and database commands; the database root history contains a coherent `mysqldump` → size check → gzip → stat → scp sequence. These are strong realism positives.

The weakness is vocabulary reuse. Exact diagnostic commands recur across otherwise separate users and hosts, often as isolated checks rather than extended investigative chains. That is not impossible, but it produces a noticeable shared-template texture.

### System and background activity

Windows includes search indexing, updater services, Windows Update components, Defender scans, Group Policy, monitoring agents, scheduled PowerShell health checks, and workstation lock/unlock events. Linux includes cron, systemd timers, apt/unattended upgrades, logrotate, resolver state, DHCP renewals, and daemon-specific logs.

The external web server’s UFW population is the strongest distribution defect. Eight IPs produce nearly all 991 blocks. Fixed TTL and packet length per source are plausible fingerprints, but each source independently rotates among exactly three TCP window sizes. Across the entire set the three counts are almost equal, which is unlikely to emerge from actual stable scanning stacks.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Impact |
|---|---|---|---|
| `environment_or_collection_plausibility` | Windows Security, Sysmon, eCAR | 13 process creates on 3 workstations | Browsers and Outlook repeatedly parent interactive SSH clients to infrastructure targets. |
| `distribution_texture` | Linux syslog/UFW | 991 blocks on `WEB-EXT-01` | TCP windows are restricted to three values with counts 333/333/325 and are mixed nearly evenly within each dominant source IP. |
| `distribution_texture` | Windows Security/Sysmon | 888 of 890 matched process pairs | Pairwise timestamp offsets are confined to a narrow, nearly symmetric ±20 ms band. |
| `distribution_texture` | Windows process activity | Multiple servers/workstations | Exact scheduled/updater process vocabulary recurs broadly with a limited long tail. |
| `weak_signal` | Bash history | Multiple Linux hosts/users | Repeated exact administrative commands suggest a shared command pool despite useful role differentiation. |

## Realism Score by Category

- **Field format accuracy:** 9 — Windows XML, RFC5424-like syslog, hashes, SIDs, GUIDs, PIDs, and eCAR fields are consistently well formed.
- **Temporal patterns:** 7 — Lifecycles and ordering are strong, but bounded cross-source jitter and enumerable scan texture are noticeable.
- **Cross-source correlation:** 9 — Process identities, commands, actors, and lifecycles align exceptionally well with no impossible ordering found.
- **Behavioral realism:** 6 — Persona differentiation is good, but repeated browser/Outlook-to-SSH parentage materially weakens endpoint plausibility.
- **Environmental consistency:** 7 — Host roles, OS build/hash clusters, and service placement are credible; repetitive process pools and UFW scan construction remain visible.

## Recommendations

- If this were synthetic, SSH launches should originate from plausible terminals or shells (`WindowsTerminal.exe`, `wt.exe`, `powershell.exe`, `cmd.exe`) unless an explicit browser/mail URI-handler or exploitation mechanism is modeled. Do not select any recently active GUI process as a generic parent.
- Model external scanners with source-stable TCP/IP fingerprints. A scanner IP should normally retain a consistent initial-window family, option profile, TTL family, packet length, and tool-specific port strategy; avoid independently sampling three global window values per packet.
- Expand the long tail of background process activity and vary scheduled/updater presence by installed software, OS build, host uptime, and policy rather than repeatedly drawing identical commands across most systems.
- Replace bounded symmetric cross-source timestamp jitter with source-specific latency distributions. Security, Sysmon, and EDR should each have a characteristic ordering, skew, resolution, and occasional queueing tail.
- Expand bash-history generation with stateful, task-driven command chains and more user-specific shell habits, while reducing exact cross-user repetition of diagnostic commands.
