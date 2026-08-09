# Host/EDR Forensics Analyst — Blind Authenticity Assessment

## Verdict

- Assessment: Synthetic
- Verdict confidence: 98/100
- Synthetic-confidence score: 97/100

## Executive summary

The data contains several strong generator fingerprints, including one Windows OpenSSH process
identity reused for numerous overlapping TCP/22 sessions and Linux IRQ numbers changing association
among unrelated devices without a reboot or `irqbalance` restart. Although field formatting and
cross-source tuple alignment are unusually strong, the process, service, login, and device
lifecycles are not operationally possible as presented.

## Evidence for synthetic

- **Hard contradiction — OpenSSH process reuse.**
  `WS-NKAPOOR-01.../windows_event_sysmon.xml` creates PID `7008`, ProcessGuid
  `{aab87a56-61e1-6643-7200-0010e104dde1}`, once at `13:06:41.921Z` with command
  `ssh.exe nina.kapoor@WEB-BO-01...`. That single identity subsequently produces 12 distinct TCP/22
  connections through `16:34:42Z`. Ports `55542` and `62634` connect at `13:06:43Z` and
  `13:15:06Z`; `WEB-BO-01.../syslog.log` shows their SSH sessions overlap because port `55542`
  remains open until `13:35:25Z`, while port `62634` is open from `13:15:08Z` to `13:39:39Z`.
  eCAR assigns both transports to the same PID and actor UUID
  `85132871-84e0-4b55-8580-d1dcb61e49e8`. OpenSSH multiplexing would reuse one transport rather
  than create multiple concurrent TCP connections with different source ports. PID `6968` repeats
  the defect with eight proxy connections.
- **Hard contradiction — unstable IRQ ownership.** In `WEB-BO-01.../syslog.log`, continuously
  running `irqbalance` PID `10271` reports IRQ `154` as `nvme0q1` at `12:06:43Z`, `ens160` at
  `12:18:13Z`, `ahci` at `12:26:37Z`, and `virtio0-input` at `14:28:56Z`. Numerous other IRQs
  similarly rotate among unrelated disk, NIC, and virtual-input devices without a boot or
  device-rebind lifecycle.
- **Hard contradiction — reversed Linux login tree.** `PROXY-BO-01.../ecar.json` records
  `/usr/lib/systemd/systemd --user` PID `232541` at `12:25:56.098Z`, then makes `/bin/login` PID
  `232568` its child, followed by Bash PID `232596`. A per-user systemd manager does not bootstrap
  its own login program; login/PAM precedes the user manager and shell. The matching local session
  also has a later eCAR logout but no eCAR login or PAM/logind login at `12:25:56Z`.
- **Contract gap — unstable Windows LogonGuid.** On `WS-NKAPOOR-01`, LogonId `0x8399fb9`, terminal
  session `3`, has zero LogonGuid for 30 process creates and later changes to
  `{b4a1f7fa-e78c-4da3-ac0f-51a8779b7bfa}` for eight creates starting at `16:01:39Z`, without a new
  logon. The same logon session ends with Security 4634 at `16:35:34Z`; its GUID should not change
  midway.
- **Contract gap — implausible Explorer ancestry.** Sysmon shows three medium-integrity
  `explorer.exe` instances for Nina—PID `7000` at `13:06:19Z`, PID `7680` at `16:01:39Z`, and PID
  `7520` at `16:27:15Z—all parented by SYSTEM `services.exe` PID `5652`. Repeated interactive shells
  should originate from the userinit/Winlogon shell path, not the Service Control Manager.
- **Distribution texture — core-service churn.** `DC-BO-01.../windows_event_sysmon.xml` records 28
  new isolated `svchost.exe -s` instances in under six hours: seven AppXSvc, six wuauserv, five
  Winmgmt, four BITS, three LanmanServer, two Schedule, and one CryptSvc. FILE-BO-01 likewise starts
  LanmanServer four times. This resembles sampling from a service-name pool rather than healthy
  server lifecycle behavior.
- **Distribution texture — scheduled-task fingerprint.** The DC launches `wsqmcons.exe` 15 times
  between `12:10:49Z` and `17:56:20Z`. Multiple workstations also run identical
  `gpupdate.exe /target:computer /force` jobs in synchronized clusters near `14:01Z` and `17:02Z`;
  `/force` is not ordinary background Group Policy refresh behavior.
- **Distribution texture — human session behavior.** Nina opens 33 successful SSH sessions to WEB
  and 16 to PROXY during the six-hour window, frequently overlapping and alternating
  password/public-key authentication. Bash histories are dominated by repeated inventory commands
  such as `lsmod`, `udevadm ... /dev/null`, `ip route`, `journalctl`, and `ps`, reinforcing a
  generated command-pool pattern.

## Evidence for real

- Windows XML uses credible provider GUIDs, event versions, tasks, channels, field layouts, SID
  forms, hexadecimal IDs, and seven-digit `SystemTime` precision. EventRecordIDs are strictly
  increasing on every channel.
- Of 570 Security 4688 events, 565 have a matching Sysmon Event 1 and 564 have a matching eCAR
  `PROCESS/CREATE` within ten seconds. Matched records agree on PID, image, command line, parent
  PID/image, user, and LogonId.
- All 820 observed Sysmon process-GUID identity mappings remain stable across create, network, DNS,
  file, process-access, and termination events. Hashes are stable for repeated executions of the
  same image on a host.
- Windows process termination generally correlates well: 427 of 431 Sysmon Event 5 records have
  matching eCAR terminations, usually within roughly two seconds.
- Linux SSH transport correlation is strong. All 34 WEB and 20 PROXY syslog `Connection from`
  tuples match an eCAR TCP/22 flow with the same source IP, source port, and destination within
  approximately 3.3 seconds.
- Normal SSH server ordering is source-native: connection precedes authentication, PAM session
  opening, systemd-logind session creation, PAM close, and logind removal. Session IDs and ports
  remain stable within each server-side lifecycle.
- Bash-history timestamps align closely with eCAR child processes and preserve pipeline fan-out.
  For example, `journalctl ... | tail -30` creates separate `journalctl` and `tail` children beneath
  the same Bash actor.
- Role texture is differentiated: the file server receives user and machine-account network
  logons; the DC carries Kerberos and directory-service activity; WEB receives internet UFW noise;
  workstation application sets vary by persona.

## Detailed analysis

The decisive defect is process-to-transport cardinality. A Sysmon ProcessGuid identifies a single
process lifetime. PID `7008` is created once and terminated once at `17:04:40Z`, yet Sysmon
attributes 12 separate SSH TCP transports to it. Several are concurrently active according to the
independently rendered server PAM lifecycle. PID `6968` has the same problem across eight proxy
sessions, and PIDs `6640`, `7764`, and `8128` repeat it on smaller scales. Matching eCAR actor IDs
and server source ports eliminate PID-reuse or sensor-join ambiguity: all three source families
preserve the same erroneous ownership.

Windows event correlation is otherwise technically polished. Security 4688, Sysmon Event 1, and
eCAR `PROCESS/CREATE` usually agree exactly on semantic fields while allowing small recording
delays. Process and hash identities are stable, and termination events correlate. That precision
makes the SSH defect more probative: this is not a loose temporal join but a consistently propagated
bad process-lifecycle model.

Interactive-session modeling has additional cracks. Nina's `0x8399fb9` session alternates between
a null and non-null Sysmon LogonGuid without a corresponding new 4624, while multiple Explorer
instances are launched directly by `services.exe`. These are shared identity and ancestry problems
rather than harmless source omissions.

Linux SSH/PAM lifecycle ordering is generally convincing, but the local PROXY session is
structurally reversed. eCAR establishes the per-user systemd manager before `/bin/login`, assigns
login as its child, and never emits the corresponding session login record even though a logout
later references that session. This appears to be a generic session-bootstrap tree assembled in
the wrong order.

The background texture has variety but poor state ownership. Essential Windows services are
repeatedly started as fresh isolated svchost processes, often several times per host, while
task-like binaries occur at pool-driven frequency. On Linux, irqbalance messages vary CPU, IRQ,
and device independently; consequently the same IRQ is assigned to mutually unrelated hardware
during one continuous boot. That state contradiction is more significant than the otherwise
credible RFC5424 formatting.

The environment does exhibit thoughtful realism: host roles differ, firewall noise is concentrated
on the exposed web server, CRON follows stable half-hour schedules, kernel uptime is monotonic, and
SSH transport/auth/session evidence is tightly correlated. These strengths reduce superficial
synthetic tells but do not overcome the lifecycle contradictions.

## Synthetic indicator summary

| Category | Source family | Scope | Impact |
| --- | --- | --- | --- |
| hard contradiction | Sysmon, eCAR, syslog | One OpenSSH PID/GUID owns overlapping TCP sessions | Decisive synthetic indicator |
| hard contradiction | Linux syslog | IRQs rotate among unrelated devices under one PID/boot | Decisive state contradiction |
| hard contradiction | Linux eCAR | `systemd --user -> login -> bash` ancestry | Impossible login bootstrap |
| contract gap | Sysmon/Security | LogonGuid changes within one LogonId | Breaks session identity |
| contract gap | Sysmon | User Explorer repeatedly parented by services.exe | Invalid interactive ancestry |
| distribution texture | Windows endpoint | Repeated core-service and task-like process starts | Strong generator-pool fingerprint |
| distribution texture | SSH/PAM/Bash | 49 SSH opens plus repetitive inventory behavior | Implausible human cadence |
| environment/collection | eCAR/syslog | PROXY local processes/logout without login/PAM evidence | Lifecycle inconsistency |

## Realism scores

| Category | Score |
| --- | ---: |
| Field-format accuracy | 8/10 |
| Temporal patterns | 4/10 |
| Cross-source correlation | 7/10 |
| Behavioral realism | 4/10 |
| Environmental consistency | 3/10 |

## Reviewer recommendations

- Allocate one process PID/GUID/UUID per OpenSSH invocation and bind it to one transport lifetime.
  Model ControlMaster multiplexing only as multiple channels over the same TCP tuple.
- Maintain a per-host IRQ-to-device inventory for the full boot lifecycle; permit reassignment only
  after an explicit device detach/rebind or reboot.
- Build local Linux sessions as getty/sshd -> login/PAM -> user manager and shell, with coherent
  `USER_SESSION` login/logout records.
- Keep Windows LogonGuid immutable for each LogonId and construct interactive shells through the
  Winlogon/Userinit path.
- Track service state before emitting `svchost -s` creates. Do not start LanmanServer, Winmgmt,
  Schedule, or EventLog again while already running; model an explicit stop/crash/restart lifecycle
  when needed.
- Tie SSH frequency and Bash commands to active human work sessions. Reduce overlapping password
  sessions and replace generic inventory pools with task-driven command sequences.

## Isolation statement

The reviewer received only `/private/tmp/eforge-realism-review/branch-enterprise/data`; scenario,
ground truth, code, prior reports, and other reviewers' conclusions were withheld.
