# Host/EDR Forensics — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive  
**Verdict Confidence:** 62/100  
**Synthetic-Confidence Score:** 56/100

## Executive Summary

The host telemetry is unusually coherent and technically strong. Windows Security, Sysmon, and eCAR generally preserve process ancestry, principals, PIDs, logon IDs, hashes, source/destination semantics, and lifecycle ordering. Linux SSH sessions likewise show credible `sshd` authentication, PAM, `systemd-logind`, shell, command, and logout sequences. The DC Security-channel record reset is explained by a visible `wevtutil cl Security` chain and Event 1102, rather than being an unexplained contradiction.

The principal evidence favoring synthesis is distributional: many hosts draw from conspicuously compact, repeated behavioral families; Windows process-access call traces have very low diversity; and external UFW scan traffic is generated from a small set of highly stable source fingerprints while advertised TCP windows vary among only three values. These are meaningful generator-like textures, but none is individually conclusive. No hard lifecycle contradiction was found.

## Evidence For Synthetic

1. **[distribution_texture] Narrow Windows process-access trace pools**

   Across hundreds of eCAR `PROCESS OPEN` records, each Windows host uses only seven or eight distinct `call_trace` strings:

   - `DC-01`: 173 opens, 8 unique traces.
   - `FILE-SRV-01`: 74 opens, 8 unique traces.
   - `MAIL-FIN-01`: 76 opens, 7 unique traces.
   - `WS-AJOHNSON-01`: 37 opens, 7 unique traces.
   - `WS-MCHEN-01`: 44 opens, 7 unique traces.

   Exact traces recur across unrelated source/target pairs. On `DC-01`, for example, the same `ntdll.dll+9EB09|KERNELBASE.dll+2DFFB|sechost.dll+14349` trace appears for `services.exe` opening `svchost.exe`, `MsMpEng.exe`, and `lsass.exe`. Real Sysmon Event 10 populations often contain repeated stacks, but the combination of broad target reuse and a tiny closed pool is generator-like.

2. **[distribution_texture] Repeated generic Windows process families across roles**

   Six-hour windows repeatedly instantiate the same small set of generic commands across workstations and servers:

   - `GoogleUpdater.exe -Embedding`
   - `DropboxUpdate.exe /svc`
   - `AdobeARMservice.exe`
   - `taskhostw.exe` / `taskhostw.exe /Run`
   - `dllhost.exe /Processid:{...}`
   - `wsqmcons.exe`
   - `WmiPrvSE.exe -Embedding` / `-secured -Embedding`

   The per-host counts are varied, which helps realism, but the family composition remains notably uniform. `DC-01` alone creates 14 instances for each of two fixed `dllhost.exe /Processid:{...}` command lines, 13 `wsqmcons.exe`, and 11 `WmiPrvSE.exe -Embedding` instances. This resembles a shared activity palette more than naturally host-specific installed-software populations.

3. **[distribution_texture] UFW scan fingerprints are too discretized**

   `WEB-EXT-01/syslog.log` contains 1,066 `[UFW BLOCK]` records. Most derive from eight recurring sources; for example:

   - `37.75.195.175`: 198 records, always `LEN=48 TTL=110`.
   - `145.78.103.167`: 187 records, always `LEN=52 TTL=118`.
   - `38.186.148.245`: 169 records, always `LEN=60 TTL=118`.
   - `45.33.74.51`: 160 records, always `LEN=52 TTL=50`.

   Stable TTL and packet length per source are realistic, but all 1,066 records select `WINDOW` from exactly `{1024, 14600, 65535}`, with each major source cycling among those values. The combination of fixed per-source TTL/LEN and a three-value global window pool looks parameterized.

4. **[distribution_texture] Linux administrative background is built from a compact common vocabulary**

   Many Linux hosts repeatedly emit the same cron pair:

   - `/bin/sh -c 'command -v debian-sa1 > /dev/null && debian-sa1 1 1'`
   - `debian-sa1 1 1`

   They also share recurring maintenance families involving `systemd-resolved`, `snapd`, `irqbalance`, `sudo`, `su`, and similar commands. These are individually authentic, and cron regularity is expected, but the breadth of shared behavioral vocabulary across mail, proxy, application, database, and workstation roles is a moderate synthetic indicator.

5. **[environment_or_collection_plausibility] Elevated administrative access is very dense**

   Multiple named employees interactively SSH into numerous production-role hosts, while background identities such as `admin`, `ops`, `deploy`, `backup`, `ubuntu`, and `root` generate frequent `sudo`, `su`, or session activity. `APP-INT-01`, for example, shows sessions for `aisha.johnson`, `marcus.chen`, `lina.nguyen`, `admin`, `ops`, `deploy`, `backup`, `ubuntu`, and root-associated actions within six hours. This is possible in a lab or permissive operations environment, but it is unusually broad for sanitized production.

6. **[weak_signal] Near-exhaustive behavioral rendering around selected activity**

   The DB export sequence includes shell history plus eCAR children for `mysqldump`, `du`, `file`, `gzip`, `sha256sum`, `cut`, `ls`, and `scp`, with correlated file create/read and network-flow evidence. This is excellent correlation and is not itself proof of synthesis, but the consistently complete treatment of pipeline children and side effects contributes weakly when combined with the closed distribution pools above.

## Evidence For Real

1. **[contract_gap — absent] No visible process dependency inversion**

   Across all eCAR files, no dependent event referenced an actor process whose visible `PROCESS CREATE` occurred later. No termination occurred before its visible create. For every terminate matched to an in-window create, PID, image, and principal agreed.

2. **[environment_or_collection_plausibility] Window-boundary lifecycle gaps are plausible**

   Terminations and logouts without in-window creates/logins occur near a six-hour collection boundary and are consistent with pre-window processes or sessions. Conversely, visible creates without termination can remain active beyond the window. These were not treated as defects.

3. **[schema_or_format] Windows source formatting is strong**

   Security XML uses credible providers, channel metadata, decimal/hex conventions, SIDs, logon IDs, process IDs, and event-specific fields. Sysmon records include plausible `ProcessGuid`, `ParentProcessGuid`, hashes, file metadata, user, integrity level, and event-specific data. Hashes are stable for the same Windows path/build across hosts: PowerShell on build `10.0.19041.1`, for example, carries the same hash set on multiple workstations, while builds `20348.1`, `17763.1`, and `22621.1` differ.

4. **[contract_gap — absent] Audit-log clearing is causally coherent**

   On `DC-01`, the Security channel decreases from EventRecordID `28262308` to `1`, but this is directly supported by:

   - `cmd.exe /c wevtutil cl Security`
   - child `wevtutil.exe` with `wevtutil cl Security`
   - Security Event 1102 at `2024-03-18T17:42:10.9545349Z`
   - continued records starting from the reset channel sequence

   The associated Sysmon parent GUIDs and PIDs align. This is a realistic reset, not a malformed record sequence.

5. **[contract_gap — absent] Linux SSH lifecycle ordering is credible**

   Example on `APP-INT-01`:

   - `Accepted publickey for marcus.chen from 10.10.1.31 port 49808`
   - PAM session open 46 ms later
   - `systemd-logind` new-session record roughly 0.44 seconds later
   - matching shell/process activity and later session close

   Key fingerprints remain stable per user, and UIDs remain consistent across hosts, compatible with centralized identity management.

6. **[schema_or_format] Bash history semantics are handled correctly**

   Epoch markers precede commands; shell built-ins such as `cd`, `pwd`, `history`, and `exit` do not incorrectly appear as separate executable process creates. Pipeline members do: `sha256sum ... | cut -c1-16` produces separate `/usr/bin/sha256sum` and `/usr/bin/cut` processes with the same shell parent.

7. **[environment_or_collection_plausibility] Host roles shape telemetry volumes**

   `DC-01` is dominated by authentication, Kerberos, SMB, DNS, and system activity; `FILE-SRV-01` has heavy network-logon and file-server behavior; `PROXY-01` has high flow volume; `WEB-EXT-01` has extensive Internet-facing UFW blocks; workstations show browser, updater, search-indexing, VPN, office-access, and interactive activity. This role differentiation strongly supports realism.

8. **[distribution_texture] Timing is not globally uniform**

   Process counts, cron occurrences, session counts, flow volumes, command durations, collection delays, and host activity levels vary. Syslog is time ordered, source timestamps show subsecond texture, and lifecycle companions are not bit-identical across sources.

## Detailed Analysis

### Windows Security and Sysmon

The Windows logs cover realistic source-specific event families: Security 4624/4625/4634, 4648, 4672, 4688/4689, 5156, Kerberos 4768/4769/4771, credential validation 4776, workstation lock/unlock, service installation, account changes, task creation, and Event 1102. Sysmon includes Events 1, 3, 5, 7, 8, 10, 11, 13, and 22 where relevant.

Record IDs are monotonic with plausible gaps except for the explained DC audit clear. Security and Sysmon process identities align closely without requiring identical source timestamps. Parent/child relationships in suspicious activity are particularly strong: `WmiPrvSE.exe` → `cmd.exe /c wevtutil cl Security` → `wevtutil.exe`, with PIDs 2428 → 5940 → 5944 and matching Security/Sysmon/eCAR observations.

The main weakness is population texture, not event correctness. Process access is rendered from very small call-trace pools, while generic Windows maintenance processes recur across machines at rates that feel constructed.

### eCAR Process and Object Lifecycles

eCAR is internally consistent. Across the dataset, visible process creates do not occur after dependent events, and matched process termination records preserve the create-time object UUID, PID, image, and principal. Parent processes either exist earlier in the window or plausibly predate it. Child pipeline processes have the same shell parent rather than incorrectly parenting one pipeline stage to another.

Counts reflect credible boundary conditions. For example, `APP-INT-01` has 103 creates and 92 terminates, of which 91 terminate an in-window create; `WEB-EXT-01` has 139 creates and 136 terminates, 130 matched in-window. This pattern is compatible with both pre-window processes and processes that survive past the end.

File and flow side effects are tied to source processes. The DB export chain creates `/tmp/rpt_0318.sql`, creates the gzip output, reads that output from `scp`, and initiates the outbound TCP/22 flow from `/usr/bin/scp`.

### Authentication and Session Semantics

Windows network-logon and logout volumes are role appropriate: DC and file server telemetry contains hundreds of Type 3 sessions, while workstations have much lower interactive/session counts. Privileged-logon companions and explicit-credential events appear in reasonable contexts.

Linux SSH evidence is well ordered and includes accepted-key records, PAM opens, `systemd-logind` sessions, `sshd` privilege processes, shells, commands, close records, and session removal. Repeated key fingerprints are stable by user. Failed/invalid-user records use coherent remote tuples.

The volume and reach of named administrators is the concern. The same people repeatedly connect to many infrastructure hosts, and permissive root/service-account activity is common. This is feasible, but it resembles a training environment or deliberately populated synthetic enterprise.

### Linux Syslog and Bash History

The RFC5424-like lines are syntactically consistent and chronologically ordered. Service PIDs are stable where expected, while transient job/session PIDs vary. Cron, package management, NetworkManager, DHCP, rsyslog, systemd, PAM, mail, proxy, and firewall messages are role-sensitive.

Bash history is not simply a list of isolated commands: related commands occur in plausible clusters, shell built-ins are treated properly, and pipeline children are visible in endpoint telemetry. Empty root histories on some systems are not treated as evidence either way.

The UFW population is the clearest Linux-side synthetic texture. Its source fingerprints are stable enough to imply recurring scanners, but the packet windows and destination-port choices draw from conspicuously small global pools.

### Timestamps and Host Roles

All examined host sources span approximately 12:00–18:00 UTC on 2024-03-18. Source timestamps are sorted, and related records show plausible small offsets. There were no visible initiators occurring after their dependent host events.

Host-role specialization is convincing: the domain controller, file server, Windows mail server, Linux mail systems, proxy, external web server, application/database servers, and user workstations have materially different traffic and process profiles. The shared generic activity palette reduces authenticity but does not erase this differentiation.

## Synthetic Indicator Summary

| Indicator | Label | Strength |
|---|---|---:|
| Seven-to-eight-value call-trace pools per Windows host | distribution_texture | Moderate |
| Repeated generic Windows process palette across unrelated roles | distribution_texture | Moderate |
| UFW scans use a small source set and exactly three global TCP-window values | distribution_texture | Moderate-to-strong |
| Broad, dense named-user administration across production-role hosts | environment_or_collection_plausibility | Moderate |
| Common Linux maintenance/service vocabulary across most hosts | distribution_texture | Weak-to-moderate |
| Highly complete rendering of selected command side effects | weak_signal | Weak |
| Unexplained visible lifecycle or ordering contradiction | hard_contradiction | None found |
| Material event-schema defect | schema_or_format | None found |

## Realism Score by Category

1. **Windows Security/Sysmon/eCAR schema fidelity:** 9/10  
2. **Process-tree and process/object lifecycle realism:** 9/10  
3. **Authentication and session lifecycle realism:** 8/10  
4. **Timestamp and behavioral distribution texture:** 6/10  
5. **Host-role and environment plausibility:** 7/10  

## Recommendations

1. Expand Windows process-access behavior beyond seven or eight per-host call traces. Derive stacks from executable build, operation, source module, target type, and host patch level rather than selecting from a compact host pool.

2. Increase host-specific software and maintenance profiles. Reduce recurrence of the same updater, COM surrogate, WMI, search, and telemetry commands across servers and workstations unless inventory data explicitly supports them.

3. Model external scan TCP fingerprints as internally coherent scanner/tool profiles. Advertised window, MSS/options, packet length, TTL, rate, and port strategy should vary by campaign or source identity rather than drawing independently from small global pools.

4. Introduce more administrative-policy differentiation: restricted root SSH, bastion-mediated access, narrower user-to-server authorization, service-account noninteractive behavior, and host-specific sudo policy.

5. Preserve the existing lifecycle and cross-source contracts. Process ancestry, source-native timestamps, pipeline child handling, audit-clear behavior, hash stability by build, and SSH/PAM/logind sequencing are major strengths.
