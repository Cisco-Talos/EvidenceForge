# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 90  
**Synthetic-Confidence Score:** 82

## Executive Summary

The dataset contains unusually strong source-native detail, coherent process trees, and excellent lifecycle ordering, but several repeatable artifacts are difficult to reconcile with production telemetry. The strongest indicators are a reused WinSxS identity suffix across incompatible Windows builds, a dataset-wide floor on Windows process lifetimes, inconsistent Sysmon `LogonGuid` values within the same visible sessions, and cloned Linux hardware/software noise across unrelated server roles.

## Evidence For Synthetic

- `[hard_contradiction]` Seven Sysmon datasets use the identical WinSxS identity suffix `_none_7c91d6e7c9f7f1f5` for three different servicing-stack versions: `10.0.19041.3636`, `10.0.20348.2322`, and `10.0.22621.3155`. Examples include `DC-01` at `2024-03-18 12:14:04.691`, `WS-AJOHNSON-01` at `12:04:28.879`, and `WS-MCHEN-01` at `12:28:48.094`. A WinSxS directory identity suffix is derived from the component identity and should not remain constant across these different versions; this looks like a reused path template.

- `[distribution_texture]` Across 781 Sysmon process creations with visible matching Event 5 terminations, not one process lived for less than one second and only two lived for less than two seconds. Among 25 transient command-line utilities—including `whoami.exe`, `net.exe`, `dsquery.exe`, `wevtutil.exe`, `sc.exe`, `wmic.exe`, and `curl.exe`—none terminated in under three seconds. Real endpoint telemetry normally contains a substantial sub-second tail for such utilities.

- `[distribution_texture]` Several obviously bounded utilities have implausibly long lifetimes. On `DC-01`, three `dsquery.exe` processes launched between `15:33:28.975` and `15:33:38.837` remain alive for approximately 982, 837, and 688 seconds. On `WS-AJOHNSON-01`, `whoami /all` runs for 17.879 seconds and three `net.exe` discovery commands run for 12.581–16.033 seconds. This resembles duration sampling rather than native execution-time behavior.

- `[contract_gap]` Visible Windows sessions contain contradictory Sysmon `LogonGuid` attribution. `DC-01` Security Event 4624 at `14:56:57.6543639Z` assigns logon ID `0x54d52cc` GUID `{160dbb9c-b455-4841-aa97-6cf0db7d28b8}`; Sysmon then records `userinit.exe` at `14:56:57.711` and `explorer.exe` at `14:56:57.861` with that logon ID but an all-zero GUID. Later children in the same session use the correct GUID. The same transition repeats on `DC-02` and twice on `WS-AJOHNSON-01`, affecting at least five visible sessions.

- `[environment_or_collection_plausibility]` Seven disparate Linux servers—application, file, monitoring, clinical mail, edge mail, proxy, and external web—share the same broad snap vocabulary, including `microk8s`, `lxd`, `snapd-desktop-integration`, `core20`, and `core22`. Desktop integration and MicroK8s activity appearing across all these headless roles suggests a common synthetic pool rather than host-specific installation state.

- `[distribution_texture]` Linux `irqbalance` records reuse exact machine-specific topology messages across unrelated hosts. For example, `IRQ 64 classified for CPU 3 balancing on mlx5_comp0` appears on six hosts, while identical `nvme0q2`, `virtio0-input`, `ens160`, and Mellanox IRQ mappings recur across multiple systems. Cloned virtual hardware could explain some overlap, but this breadth of identical mixed-device mappings is unlikely.

- `[weak_signal]` The 212 shell-history commands are dominated by a compact diagnostic vocabulary and recurring sequences such as `systemctl`, `journalctl`, `ss`, `grep`, and `systemctl cat`. The behavior remains plausible for administrators, so this is supplementary rather than decisive evidence.

## Evidence For Real

- Process trees are source-native and generally convincing: `services.exe` launches services, `smss.exe → winlogon.exe → userinit.exe → explorer.exe` models interactive sessions, `sshd → bash → utility` models Linux sessions, and user applications originate from plausible shells or desktop processes.

- I found no visible Sysmon child referencing a parent created later, no Sysmon dependent event referencing a later-created process, no termination preceding its matching visible creation, and no eCAR event occurring after its visible actor process had terminated.

- Of 970 Sysmon Event 1 records, 969 have a matching Security 4688 with the same PID, image, command line, parent PID, parent image, logon ID, and user. Matching Security timestamps differ by no more than approximately 0.64 seconds. At least 963 also have a corresponding eCAR process creation within one second.

- Sysmon `ProcessGuid` values have stable host prefixes, encode plausible creation times, and are unique per creation. Hashes remain consistent for the same image and file version, including across hosts running the same build.

- SSH sequences preserve source tuple, authentication method, process ID, user, and ordering. For example, the `10.10.2.30:46054 → 10.10.4.10:22` session appears in Zeek at `17:14:53.555614`, in endpoint FLOW records around `17:14:54`, as an `sshd` connection on `DB-PROD-01` at `17:14:57.326246`, and as an accepted root login at `17:15:11.125773`.

- Linux execution semantics are often excellent. In the `DB-PROD-01` root history, shell redirection appears in the history command but not in the eCAR `mysqldump` argv, and the resulting file creation is attributed to `mysqldump`. The subsequent `gzip`, `scp`, network connection, file read, and receiver-side file creation occur in causal order.

- `DC-01` models Security-log clearing convincingly: Event 1102 at `17:42:33.1802494Z` becomes record ID 1, followed by record ID 2 and a new monotonic sequence. This is a realistic channel-state transition rather than a simple timestamped alert.

- Host roles are reflected in activity: domain controllers carry Kerberos and network-logon volume, file servers carry SMB access, mail systems show Exchange or Postfix/Dovecot activity, and the Linux developer workstation uses Git, npm, Docker, pytest, Cargo, and editors. A typo such as `grroups` in the mail-server history adds some human texture.

## Detailed Analysis

### Windows process and Sysmon behavior

The dataset contains 970 Sysmon process creations across ten Windows hosts. Parent-child relationships are structurally sound, with no visible later-parent violations or duplicated creation GUIDs. Security 4688 and Sysmon Event 1 agree on all compared fields for 969 processes, and the modest timestamp skew is compatible with independent event pipelines.

The process-lifetime distribution is not production-like. Of 781 processes with both visible create and terminate events, zero terminate within one second. Even short commands exhibit a three-second floor: `wevtutil.exe qe Security /c:20 /f:text` lasts 3.062 seconds, `wevtutil.exe gl Security` lasts 3.285 seconds, and a simple `dsquery` on `DC-02` lasts 3.309 seconds. Other commands stretch much farther, particularly the three `DC-01` directory queries lasting 11–16 minutes. The absence of a short-lifetime tail across this volume is a strong generator fingerprint.

The WinSxS paths are more decisive. `TiWorker.exe` appears under:

- `10.0.19041.3636_none_7c91d6e7c9f7f1f5`
- `10.0.20348.2322_none_7c91d6e7c9f7f1f5`
- `10.0.22621.3155_none_7c91d6e7c9f7f1f5`

The file versions and hashes correctly differ by build, but the assembly identity suffix does not. That internal inconsistency is characteristic of a path template in which only the visible version was substituted.

### Logon sessions

Logon-type mixtures are plausible: domain controllers contain service and network logons plus limited remote-interactive sessions, while workstations contain interactive, network, unlock, and service activity. Network sessions generally close in seconds, and remote-interactive sessions last tens of minutes to hours. I found no valid example of a visible logout preceding the initiating login for the same session identifier.

Sysmon logon correlation is inconsistent at session bootstrap. For five visible remote-interactive sessions, Security 4624 supplies a nonzero GUID, but `userinit.exe` and `explorer.exe` receive the zero GUID before later children adopt the correct one. On `WS-AJOHNSON-01`, for example, Security records logon `0x26dad90` with GUID `{11a86a48-4672-48ca-9f42-69aba50171fe}` at `15:01:08.9426803Z`; Sysmon assigns zero to `userinit.exe` and `explorer.exe`, then uses the correct GUID for `OUTLOOK.EXE` only 0.397 seconds later. The repeatability across hosts makes a one-off collection race less persuasive.

### Linux endpoint evidence

Successful SSH sessions follow convincing sequences: connection, accepted public key or password, PAM session open, systemd-logind session creation, activity, PAM close, and session removal. Public-key fingerprints remain stable for each user across hosts. Pre-window closes were not treated as errors.

The shell histories use valid Bash timestamp encoding and show role distinctions. The `DB-PROD-01` extraction sequence is especially convincing because the shell’s output redirection is absent from the executed `mysqldump` argv while the file creation is attributed correctly.

The baseline syslog texture is less convincing. `WEB-EXT-01` records 132 `irqbalance` and 114 `snapd` messages in six hours; `APP-INT-01` records 66 and 56, and `FILE-LNX-01` records 53 and 67. More important than volume is the reuse of identical IRQ topology and snap-package vocabulary across unrelated roles. This looks like host-independent pool sampling rather than telemetry conditioned on installed software and hardware.

### eCAR and cross-source correlation

eCAR lifecycle ordering is strong. Across all hosts, I found no visible actor process created after its dependent event, no termination before creation, and no dependent event after the actor’s visible termination. Windows eCAR process events closely track Security and Sysmon, while Linux records preserve shell, SSH, file, and network ownership.

The staged database archive illustrates the strength of the model: `mysqldump` creates `/tmp/rpt_0318.sql`, `gzip` creates the `.gz`, `scp` reads it and opens `10.10.4.10:46919 → 10.10.2.30:22`, and `APP-INT-01` records receiver-side creation at `17:16:35.914`. These relationships materially reduce the chance of crude synthetic construction, but do not overcome the dataset-wide fingerprints above.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Impact |
|---|---|---:|---|
| `hard_contradiction` | Sysmon process paths | Seven Windows hosts, three OS builds | Reused WinSxS identity suffix across incompatible component versions is a strong template leak. |
| `distribution_texture` | Sysmon process lifecycle | 781 paired processes | No sub-second lifetimes and only two below two seconds; transient utilities share a conspicuous duration floor. |
| `contract_gap` | Security/Sysmon logon correlation | At least five sessions on three hosts | Same visible logon ID changes from zero to the correct `LogonGuid` between bootstrap and later child processes. |
| `environment_or_collection_plausibility` | Linux syslog | Seven disparate server roles | MicroK8s, LXD, desktop-integration, and core snap activity appears across every examined server role. |
| `distribution_texture` | Linux syslog | Multiple servers and workstations | Exact IRQ numbers, device names, CPU assignments, and message strings recur across unrelated hosts. |
| `weak_signal` | Bash history | 19 histories, 212 commands | Repeated diagnostic vocabulary and similar troubleshooting sequences provide limited additional synthetic texture. |

## Realism Score by Category

- **Field format accuracy:** 7 — XML, RFC 5424, Sysmon GUIDs, hashes, Bash timestamps, and eCAR shapes are strong, but the WinSxS path identity leak is significant.
- **Temporal patterns:** 5 — Causal ordering is excellent, but Windows process-duration distributions are conspicuously bounded.
- **Cross-source correlation:** 8 — PID, command, user, tuple, and lifecycle matching are strong; session-bootstrap `LogonGuid` attribution is the main defect.
- **Behavioral realism:** 7 — Host-specific applications and user roles are convincing, although shell and transient-process behavior retain templated texture.
- **Environmental consistency:** 5 — Windows build distinctions are plausible, but Linux snap installations and IRQ topology are insufficiently host-specific.

## Recommendations

- If this were synthetic, derive complete WinSxS component paths from the full assembly identity. Validate that version changes produce the correct identity suffix instead of substituting only the visible version field.

- If this were synthetic, model short-lived Windows processes with a heavy sub-second distribution based on executable class. Utilities such as `whoami`, local `wevtutil` queries, and small directory queries should commonly complete in milliseconds, while genuinely blocking or remote operations can retain a longer tail.

- If this were synthetic, assign a session’s `LogonGuid` before emitting any session-owned process. `userinit.exe`, `explorer.exe`, and all descendants sharing a visible logon ID should render the same GUID as Security 4624.

- If this were synthetic, condition Linux background events on a host-specific installed-package and hardware inventory. Avoid emitting MicroK8s or desktop-integration activity on mail, proxy, file, and monitoring servers unless those packages are explicitly modeled as installed.

- If this were synthetic, generate IRQ records from a persistent per-host device map. Hosts may share virtual hardware families, but exact IRQ numbers, CPU mappings, and mixed device names should not recur broadly without a modeled common platform.

- If this were synthetic, broaden shell-history behavior with more user-specific repetition, corrections, directory navigation, aliases, and command reuse while preserving the strong source-native execution semantics already present.
