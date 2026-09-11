# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 84  
**Synthetic-Confidence Score:** 72

## Executive Summary

The collection is technically sophisticated and often production-like: Windows process, session,
hash, ancestry, RDP, SSH, and eCAR relationships survive extensive exact joins, with convincing
source-native timing and bounded-window lifecycle behavior. I nevertheless assess it as synthetic
because DB-PROD-01 contains a concrete root-shell chronology conflict tied to a visible SSH session,
and the Linux fleet repeats an implausibly uniform hardware/IRQ vocabulary across dissimilar host
roles; narrow RDP timing and mixed eCAR file-identity shapes provide additional, lower-weight support.

## Evidence For Synthetic

- **[hard_contradiction] DB-PROD-01 root commands precede the shell that later executes the same
  history sequence.** `DB-PROD-01.meridianhcs.local/bash_history/root.bash_history` timestamps
  `id` at 17:14:27Z, two `mysql` queries at 17:14:39Z and 17:14:50Z, and `df -h /tmp` at
  17:15:01Z. The corresponding root SSH connection is not logged until 17:14:57.326246Z,
  authentication/PAM open occurs at 17:15:11.125773Z/17:15:11.196032Z, eCAR login occurs at
  17:15:11.432Z, and the session's bash process starts at 17:15:13.178Z. This is not merely a
  missing pre-window initiator: the same history immediately continues with `mysqldump` at
  17:15:19Z, `gzip` at 17:15:46Z, and `scp` at 17:15:55Z, each matching an eCAR process in that
  exact SSH session (`logon_id=0x1185edd0`, `session_id=279038`).

- **[contract_gap] Eight consecutive external root-history commands on DB-PROD-01 lack the process
  evidence that appears for the final three commands in the same sequence.** The unmatched commands
  are `id`, two `mysql` invocations, `df`, two `du` invocations, `file`, and `stat`; unlike shell
  built-ins, each should execute a child process. eCAR begins recording the same sequence at
  `mysqldump` (PID 884730), then records `gzip` (PID 884790) and `scp` (PID 884810), all parented by
  bash PID 884714. In addition, history places `file` and `stat` at 17:15:32Z and 17:15:35Z while
  the foreground `mysqldump` is still alive until 17:15:45.629Z. A concurrent pre-existing root
  shell could theoretically explain the interleaving, but no such shell or command processes are
  visible in an otherwise dense eCAR interval, and it does not explain the coherent command chain.

- **[distribution_texture] Linux hardware telemetry is reused across the fleet with cloned-image
  regularity.** Eleven hosts contain syslog. Exact `irqbalance` text such as
  `IRQ 181 affinity hint keeps vector on CPU 0 (mlx5_comp2)` appears 18 times on 10 hosts. The same
  small topology vocabulary—IRQ 16/24/32/45/64/86/122/137/154/181 paired with `ahci`, `ens160`,
  `ens192`, `nvme0q1`, `nvme0q2`, `virtio0-input`, `virtio1-input`, and `mlx5_comp0/1/2`—recurs on
  servers and endpoint-style hosts. Even LT-MRIVERA-02 reports the identical `nvme0q2`, `ens192`,
  and Mellanox `mlx5_comp*` IRQ assignments, while WS-LNGUYEN-01 and WS-OHADDAD-01 share elements
  of the same inventory. Across syslog, 110 exact message texts occur on at least three hosts; the
  strongest concern is not generic service text but identical hardware identifiers and IRQ numbers.

- **[distribution_texture] RDP transport-to-authentication delays are unusually constrained.** All
  15 visible Security 4624 Type 10 logons join exactly to an inbound eCAR TCP/3389 flow by target
  host, source IP, and source port. Every authentication occurs 4.723-6.357 seconds after that flow
  (median 5.811, mean 5.646, population standard deviation 0.537 seconds). Correct ordering is a
  strength, but the low variance across five target hosts and multiple source systems looks like a
  shared timing profile rather than organically variable RDP/LSA/domain-authentication latency.

- **[schema_or_format] eCAR FILE identities use three incompatible visible shapes without a source
  discriminator.** Of 321 FILE records, 198 use a bare UUID, 119 use a shortened
  `file-00000000xxxxxxxx` form, and four use `file-<UUID>`. The shortened form occurs on six hosts,
  and nine such IDs are reused for multiple records. `objectID` may be an opaque string by contract,
  so this is not treated as a hard validity failure, but mixing three identity namespaces inside the
  same object family weakens source-native consistency and correlation semantics.

## Evidence For Real

- The six-hour window is internally consistent: host telemetry runs approximately 12:00-18:00 UTC
  on 2024-03-18, with natural per-host first/last-event variation rather than a single rigid edge.
  I did not penalize terminations or logouts whose starts predate the window, nor starts that remain
  open at collection end.

- Windows schemas are strong. Across 18,232 Security events and 11,542 Sysmon events, required
  fields checked for Security 4624/4634/4672/4688/4689/4779 and Sysmon 1/3/5/10 were present. Tested
  SIDs, GUIDs, process/port numbers, Sysmon hash tuples, protocols, and `Initiated` values all had
  source-appropriate shapes.

- Exact Windows process joins are convincing. There are 970 Sysmon Event 1 creates and 976 Security
  4688 creates; 969 Sysmon creates match a 4688 on host, PID, image, and a two-second window. For
  those 969, Security trails Sysmon by 35-636 ms. On the eCAR side, 963 of 970 Sysmon creates and
  833 of 839 Sysmon terminations match eCAR by host, PID, image, and time. Matched records have no
  principal, logon ID, PPID, or parent-image disagreements.

- Process identity and ancestry behave correctly. Each Windows host has a distinct stable Sysmon
  ProcessGUID prefix. No visible parent ProcessGUID is created after its child, and all 192 eCAR
  child processes whose parent could be cross-walked to a visible Sysmon process agreed on the
  parent GUID. No matched Sysmon or eCAR process terminates before creation.

- Binary identity is stable. Within each host, repeated Sysmon creates of the same image use one
  hash tuple; across hosts, no image plus file-version pair produced conflicting SHA1/MD5/SHA256/
  IMPHASH sets. This is the behavior expected of shared enterprise binaries rather than independently
  invented emitter values.

- Lifecycle distributions have substantial texture. There are 781 exact Sysmon ProcessGUID
  create/terminate pairs, with unmatched starts and stops consistent with a bounded slice. Across
  eCAR, 1,689 process object IDs have both CREATE and TERMINATE, no negative durations, and durations
  ranging from 74 ms to roughly 5.1 hours. Exact millisecond durations do not show a dominant repeated
  value; common images such as `taskhostw.exe`, `WmiPrvSE.exe`, `dllhost.exe`, `/bin/bash`, and
  `/usr/sbin/sshd` have broad, image-appropriate lifetime ranges.

- The DC-01 Security record-ID discontinuity is source-native, not a defect. Record IDs advance to
  28,261,442, a visible `cmd.exe /c wevtutil cl Security` and `wevtutil.exe` sequence executes, Event
  1102 appears as record 1 at 16:02:33.180249Z, and subsequent Security records restart at 2 and 7.
  Sysmon remains unaffected. This is a convincing clear-log artifact.

- SSH lifecycles are unusually well formed in a technically valid way. All 38 successful visible
  sessions follow connection -> accepted authentication -> PAM open; all 38 join to an inbound eCAR
  TCP/22 flow and eCAR USER_SESSION LOGIN by host, user, source IP, and source port. Connection-to-
  accept spans 5.501-14.684 seconds (median 6.778), PAM open follows accept by 49-176 ms, and all 30
  visible closes follow their opens. Pre-window closes and end-window open sessions were treated as
  legitimate boundaries.

- Bash activity outside the DB-PROD-01 root anomaly is diverse and correlated. The 21 history files
  contain 212 timestamped commands; 177 first executable tokens match an eCAR process within three
  seconds (median eCAR offset 1.161 seconds). Histories are chronological, and no pair of non-empty
  history files reaches 0.20 Jaccard overlap in exact command text.

- Host roles have visible differentiation. FILE-LNX-01 has `smbd`/`smbd_audit`; MAIL-CLIN-01 and
  MAIL-EDGE-01 have Postfix and Dovecot; WEB-EXT-01 has extensive kernel traffic; workstation users
  have distinct application sets. Lina Nguyen's Linux workstation emphasizes Git, Docker, npm, and
  SSH; Evelyn Brooks uses Tableau and office/browser applications; Marcus Chen uses PowerShell,
  OpenSSH, RDP, VS Code, and Postman. This is much richer than one uniform user-process pool.

## Detailed Analysis

### Scope and method

I examined only the supplied `data` directory. The endpoint corpus contains 20 eCAR host files
(32,991 records), Windows Security/Sysmon XML on 10 hosts (18,232 and 11,542 events), syslog on 11
hosts (3,869 records), and 21 bash-history files (212 timestamped commands). I parsed complete files,
grouped events by host and source-native identity, and performed exact or bounded joins on ProcessGUID,
eCAR objectID/actorID, PID, PPID, image path, logon ID, user, source/destination tuple, and timestamp.

For lifecycle tests, a termination/logout without a visible start was classified as a left-boundary
state unless the same identifier had a later visible initiator; a start without termination/logout
was classified as right-boundary state. Only negative matched lifecycles or visible dependent-before-
initiator ordering were treated as contradictions.

### Windows Security and Sysmon semantics

The Security mix is plausible for the visible roles: 11,605 Event 5156 filtering-platform records,
2,072 TGS requests (4769), 749 TGT requests (4768), 802 logons (4624), 419 special-privilege events
(4672), 383 logoffs (4634), 976 process creates (4688), and 825 process exits (4689), plus lower-volume
share access, explicit credentials, account administration, task/service installation, lock/unlock,
and audit-clear evidence. Sysmon is similarly coherent: 7,435 network connections, 1,234 DNS queries,
970 process creates, 839 process terminations, 741 process-access records, 149 image loads, 140 registry
sets, 27 file creates, and seven remote-thread records.

Every checked Sysmon Event 1 included valid process and parent GUIDs, decimal PIDs, image/command/user/
logon/session/integrity fields, and a four-algorithm uppercase hash tuple. Event 3 protocol, direction,
IP, and port fields validated. Security process IDs use the expected hexadecimal notation, while 5156
uses decimal ProcessID and native device-style application paths. The observed 4688/Sysmon/eCAR timing
order and subsecond offsets are credible for three telemetry pipelines on the same host.

For Sysmon lifecycle, 781 ProcessGUIDs have both Event 1 and Event 5. Fifty-eight Event 5 records lack
a visible create, and 189 creates lack a visible Event 5; none has a negative matched duration, no
left-boundary termination's same GUID later reappears as a create, and the long-lived open population
is concentrated where the six-hour cutoff makes it expected. The process trees include believable
long-lived parents (`services.exe`, `svchost.exe`, `explorer.exe`, `sshd`) that began before the slice.

### eCAR process and session identity

eCAR is monotonically timestamped within every host file, has no duplicate event IDs, no hostname/file
placement mismatch, and no invalid TCP/UDP port value. PROCESS CREATE/TERMINATE object IDs pair exactly
for 1,689 lifecycles. There are 94 terminations with pre-window starts and 235 creates still open at the
right edge; none violates ordering. Parent `actorID` relationships never point to a later-created parent.

For Windows processes, the eCAR-to-Sysmon joins also preserve principal, logon ID, PPID, and parent
image. Small source-specific gaps exist—seven creates on each side do not join within two seconds—but
their sparse, nonuniform placement is compatible with collection loss and is not itself synthetic
evidence. The mixed FILE objectID shapes described above are the only recurring eCAR field-level issue
that materially affected my score.

Windows logon/logoff behavior is boundary-compatible. Security logons include service (5), network
(3), interactive (2), remote interactive (10), unlock (7), and new-credentials (9) activity in
host-appropriate proportions. Exact eCAR objectID session pairs produce no logout-before-login case.
Long-lived Type 5 sessions account for much of the apparent login/logoff imbalance on servers; I did
not treat those as missing lifecycle failures.

### RDP

Fifteen visible target Type 10 logons occur on DC-01, DC-02, FILE-SRV-01, MAIL-FIN-01, and
WS-AJOHNSON-01. Each has an inbound eCAR TCP/3389 flow with the exact source IP and source port before
authentication; source endpoints also show the corresponding outbound tuples, and modeled client
hosts contain plausible `mstsc.exe` lifecycles where endpoint process identity is available. No target
authentication precedes transport, and successful sessions use plausible source addresses, principals,
`winlogon.exe`, and Negotiate metadata.

The concern is statistical rather than causal: all 15 transport-to-4624 delays fall in a 1.634-second
band. The exact values are 4.723, 4.780, 4.999, 5.179, 5.216, 5.395, 5.669, 5.811, 5.924, 5.945,
6.030, 6.195, 6.220, 6.240, and 6.357 seconds. This is much tighter than the process-duration and SSH
distributions elsewhere and therefore contributes a moderate synthetic indicator.

### Linux syslog, SSH, and bash evidence

The source-native SSH messages are well shaped: RFC 5424 records use plausible authpriv priorities,
OpenSSH connection text contains both endpoints and ports, public-key fingerprints are syntactically
credible and stable per user, and accepted authentication is followed by PAM and systemd-logind session
creation. Failed logins include invalid-user/authenticating-user distinctions and pre-auth closes.

The endpoint joins are exact. Across 38 successful sessions, every syslog tuple has a corresponding
eCAR inbound flow and USER_SESSION login. Thirty visible sessions close after opening, while the rest
are explainable at the right boundary. eCAR login time is within -0.851 to +1.424 seconds of PAM open,
and eCAR flow precedes accepted authentication by 6.052-16.424 seconds. This is convincing transport,
authentication, and session ownership.

The Linux inventory layer is less convincing. Role-specific applications are present, but the common
baseline appears drawn from one global hardware vocabulary. Pairwise Jaccard overlap of exact
`irqbalance` messages reaches 0.561 between LOG-MON-01 and WEB-EXT-01 and also 0.561 between
FILE-LNX-01 and MAIL-EDGE-01. Standardized virtual-machine templates can explain some overlap, but
identical IRQ numbers, CPU affinities, storage drivers, virtual-input devices, and Mellanox queue names
across server and endpoint-style hosts are too specific to dismiss as generic OS text.

The DB-PROD-01 root sequence is the only observed visible host-level chronology that fails. Its later
commands prove that bash-history epoch values are being used as command-start times: `mysqldump` history
at 17:15:19Z maps to eCAR start 17:15:19.408Z, `gzip` at 17:15:46Z maps to 17:15:46.744Z, and `scp` at
17:15:55Z maps to 17:15:55.988Z. The preceding commands cannot therefore be dismissed as timestamps
with unrelated semantics. A concurrent pre-existing root shell remains a theoretical alternative, but
the collection has neither that shell nor any of its eight external child processes, despite capturing
the immediately following three children and their files/flow. This finding receives the highest weight.

### Process duration and user texture

Executable lifetimes avoid a simple fixed-duration fingerprint. The eCAR population contains broad
right tails for shells, SSH daemons, RDP clients, explorer/winlogon, WMI providers, search processes,
and PowerShell, while short utilities occupy subsecond-to-several-second ranges. Only two of 1,689
paired processes land within 10 ms of a major round duration (both WmiPrvSE at 14,400.001 seconds),
which is too sparse to score independently.

User/application placement is differentiated enough to support realism. Administrative users favor
RDP, OpenSSH, PowerShell, MMC, system tools, SSH, Git, Docker, database clients, and SMB tooling;
nonadministrative workstation users show office, browser, collaboration, VPN, file-sync, and role-
specific software. Exact bash command overlap is low despite shared administrative tasks. These
properties materially reduced the synthetic-confidence score from what the chronology and fleet-
inventory defects alone would imply.

## Synthetic Indicator Summary

| Priority | Category | Affected family | Scope | Score effect |
|---|---|---|---|---|
| P0 | `hard_contradiction` | bash history / SSH / eCAR process-session | DB-PROD-01 root sequence; four commands precede authentication and shell creation | High: visible dependent activity precedes its tied initiator |
| P1 | `distribution_texture` | Linux syslog / host inventory | Fleet-wide; exact IRQ/device topology repeats across up to 10 of 11 syslog hosts | High: hardware-specific repetition is difficult to explain as ordinary shared OS text |
| P1 | `contract_gap` | bash history / eCAR process lifecycle | DB-PROD-01; eight external commands absent before three exact matches in one sequence | Medium-high: selective coverage and foreground timing weaken one otherwise coherent chain |
| P2 | `distribution_texture` | RDP / Windows Security / eCAR FLOW | All 15 successful visible Type 10 logons across five targets | Medium: valid ordering but implausibly narrow 4.723-6.357 s latency band |
| P3 | `schema_or_format` | eCAR FILE | 321 records; three objectID shapes, shortened form on six hosts | Low-medium: inconsistent identity namespace, not proven invalid |

## Realism Score by Category

- **Field format accuracy: 8/10** — Windows, Sysmon, syslog, bash, and most eCAR fields are
  source-appropriate; mixed eCAR FILE objectID shapes are the main exception.
- **Temporal patterns: 6/10** — Most lifecycles and source delays are plausible, but the DB root
  chronology is concrete and the RDP delay distribution is too narrow.
- **Cross-source correlation: 9/10** — Process, ancestry, logon, RDP, and SSH joins are exceptionally
  strong without visible negative lifecycle ordering outside the DB root history sequence.
- **Behavioral realism: 8/10** — User applications, command vocabularies, process durations, failures,
  and role-specific services have convincing diversity.
- **Environmental consistency: 6/10** — Host roles differ appropriately, but the repeated Linux
  hardware/IRQ topology across unlike systems is a broad authenticity weakness.

## Recommendations

1. **Enforce one authoritative shell-session timeline for bash history and process telemetry.** If
   this were synthetic, require `transport <= authentication <= PAM open <= shell create <= command
   start` for every command attributed to an SSH session. Emit history and eCAR process activity from
   the same command object, and serialize foreground processes unless a command explicitly backgrounds
   them. Add a regression covering the DB-PROD-01 pattern, including pre-auth external commands.

2. **Model Linux hardware inventory per host class and render syslog from that inventory.** Give
   laptops, generic virtual servers, database hosts, mail gateways, and monitoring systems distinct,
   internally stable NIC, block-device, IRQ, CPU, NUMA, and accelerator topologies. An `irqbalance`
   message should select only devices actually assigned to that host; avoid globally reusing exact IRQ
   numbers and queue names.

3. **Broaden RDP timing from an empirical, path-sensitive distribution.** Condition transport-to-
   authentication latency on source/target load, DC selection, authentication package, network path,
   reconnect versus new session, and occasional delay/outlier behavior. Preserve the current exact
   tuple joins and transport-before-auth invariant.

4. **Standardize eCAR FILE identity semantics.** Use one documented objectID namespace per eCAR FILE
   contract, or add an explicit identity-source/type field when local file UUIDs, stable path hashes,
   and prefixed external IDs must coexist. Ensure the same file keeps a stable ID without making
   unrelated identity shapes indistinguishable to consumers.

5. **Retain the current high-value realism contracts.** Preserve stable per-binary hashes, distinct
   per-host ProcessGUID namespaces, exact parent cross-walks, bounded-window lifecycle handling, the
   Security-log-clear record-ID reset, and tuple-level SSH/RDP correlation while addressing the
   higher-priority defects above.
