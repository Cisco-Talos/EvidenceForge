# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict (Assessment: Synthetic|Real|Inconclusive, Verdict Confidence, Synthetic-Confidence Score)

- **Assessment:** Synthetic
- **Verdict Confidence:** 80/100
- **Synthetic-Confidence Score:** 64/100 — likely synthetic

## Executive Summary

The host telemetry is technically strong: Windows process identifiers reconcile across eCAR,
Sysmon, and Security logs; process and session lifecycles are ordered correctly; the Security-log
clear sequence on DC-01 is unusually well modeled; and multi-host SSH/SCP activity preserves users,
ports, files, and process ancestry across source-native records. I found no decisive field-level
impossibility or hard lifecycle contradiction.

The synthetic assessment is instead driven by repeated fleet-level texture. Ten Linux systems each
contain exactly eight `dbus-daemon` records and exactly four `systemd-resolved` records despite
different roles and total event volumes. These records are also concentrated into short early-run
windows. Multiple workstations launch competing enterprise access clients—and, in two cases,
overlapping instances of the same client UI—during the same six-hour period. DC-02 additionally
hosts a recurring Java business-integration worker despite being a domain controller. The unusually
verbose, broadly repeated `irqbalance` and `snapd` chatter reinforces the impression of category
quotas and role/catalog mixing.

Those are concrete, log-visible indicators, but they are not impossible in production. A fixed
collection/export cap, a migration between security clients, or an unusually consolidated lab-like
environment could explain parts of the pattern. Accordingly, the score is in the lower portion of
“likely synthetic,” not “confidently synthetic.” Sanitized domains, similar file timestamps,
complete cross-source matching, and absent source types were not treated as synthetic evidence.

## Evidence For Synthetic

1. **Fleet-wide fixed Linux background-event quotas** (`distribution_texture`, high weight).
   Ten of eleven Linux syslog files contain exactly eight `dbus-daemon` records. Independently, ten
   of eleven contain exactly four `systemd-resolved` records. `DB-CORE-01_syslog.jsonl` has eight
   D-Bus records but no resolver records, while `WS-OHARRIS_syslog.jsonl` has six D-Bus records and
   four resolver records. This repetition spans servers and workstations
   whose overall syslog volumes vary widely: `APP-INTEG-01_syslog.jsonl` has 230 records,
   `FILE-LNX-01_syslog.jsonl` 509, `WEB-EXT-01_syslog.jsonl` 1,206, and
   `WS-LNGUYEN_syslog.jsonl` 236. The matching subcategory totals are therefore not a natural
   consequence of equal collection volume.

   The events are also front-loaded. In `APP-INTEG-01_syslog.jsonl`, all eight D-Bus records occur
   from `2024-03-18T12:04:16.471Z` through `12:30:53.640Z`; its four resolver records occur at
   `12:30:19`, `12:34:43`, `12:37:02`, and `13:02:46`, with none later in the six-hour file. In
   `WEB-EXT-01_syslog.jsonl`, all eight D-Bus records occur from `12:13:43.873Z` through
   `12:34:49.465Z`, and the four resolver records occur at `12:04:34`, `12:06:01`, `12:08:46`, and
   `12:09:34`. The D-Bus messages include activations of `org.freedesktop.hostname1`,
   `timedate1`, `locale1`, `login1`, and `resolve1`; exact per-host totals for this demand-driven
   traffic are a stronger tell than mere timestamp similarity. Several hosts also have exactly five
   `anacron` records, adding a weaker quota-like repetition.

2. **Competing and overlapping endpoint access agents**
   (`environment_or_collection_plausibility`, medium-high weight). The same user session often
   launches products normally deployed as alternative enterprise access stacks:

   - `WS-AJOHNSON_Sysmon.xml`: Cisco AnyConnect `vpnui.exe` at
     `2024-03-18T14:01:19.080Z`, Zscaler `ZSATray.exe` at `15:34:13.799Z`, and Palo Alto
     GlobalProtect `PanGPA.exe` at `16:24:07.255Z`, all under the interactive user and
     `explorer.exe`.
   - `WS-PPATEL_Sysmon.xml`: `vpnui.exe` at `15:37:00.495Z`, `PanGPA.exe` at
     `15:42:37.684Z`, and `ZSATray.exe` at `16:59:39.934Z` in the same session.
   - `WS-DRAMIREZ_Sysmon.xml`: Cisco `vpnagent.exe` at `12:09:02.266Z`, Cisco `vpnui.exe`
     at `14:14:17.500Z` and `17:40:14.422Z`, and GlobalProtect `PanGPA.exe` at
     `15:46:20.156Z`.
   - `WS-SMARTINEZ_ecar.jsonl`: `PanGPA.exe` starts at `14:41:41.093Z` with a recorded
     duration of `4159.337` seconds, while another `PanGPA.exe` starts at `15:26:16.914Z`—about
     25 minutes before the first instance's recorded end.
   - `WS-EBROOKS_ecar.jsonl`: Cisco `vpnui.exe` processes start at `16:54:38.414Z` and
     `17:12:44.284Z` with PIDs `5020` and `5256`; neither has a visible termination before the
     dataset ends.

   Co-installation can occur during migrations, and helper processes can legitimately overlap, so
   this is not a hard contradiction. Its repetition across the workstation population is what makes
   it suspicious.

3. **Application middleware placed on a domain controller**
   (`environment_or_collection_plausibility`, medium weight). `DC-02_ecar.jsonl` repeatedly shows
   SYSTEM process PID `5632`, image
   `C:\Program Files\Eclipse Adoptium\jdk-17\bin\java.exe`, with command line
   `"C:\Program Files\Eclipse Adoptium\jdk-17\bin\java.exe" -jar
   C:\ProgramData\Meridian\integration-worker.jar`. It connects from `10.10.2.11` to
   proxy `10.10.3.20:8080` at, among other times, `12:37:39.593Z`, `12:53:18.845Z`,
   `15:21:05.626Z`, `16:29:22.618Z`, `16:41:39.070Z`, and `17:47:12.361Z`. A domain
   controller running a recurring business-integration worker is operationally possible but
   atypical and resembles role-independent application assignment.

4. **Fleet-wide diagnostic-style service chatter**
   (`distribution_texture` and `environment_or_collection_plausibility`, medium weight).
   `irqbalance` contributes 55 records on APP-INTEG-01, 71 on DB-CORE-01, 73 on FILE-LNX-01,
   83 on LOG-COLLECT-01, and 106 on WEB-EXT-01 in only six hours. Examples in
   `APP-INTEG-01_syslog.jsonl` include `NUMA node 0 balancing pass complete, 2 IRQs moved` at
   `12:03:14`, an `IRQ 24 affinity hint` message at `12:09:34`, and another NUMA pass at
   `12:12:15`. `WEB-EXT-01_syslog.jsonl` also contains 107 `snapd` records. Consistently verbose
   internal service messages across dissimilar systems are less typical of default production
   logging and resemble a synthetic background-noise recipe. A fleet-wide verbose configuration
   remains a plausible real-world explanation.

5. **Narrowly similar workstation volume profiles** (`weak_signal`, low weight). Windows
   workstation eCAR FLOW totals cluster at 447–536, while corresponding Security event 5156 totals
   cluster at 398–496. A common endpoint policy and workday can produce this, so this observation
   only modestly reinforces the stronger fixed-quota evidence.

## Evidence For Real

1. **Process and session lifecycle integrity is excellent.** Across every eCAR host file, no
   process with a visible parent was created before that parent's creation or after its termination.
   The checked visible-parent populations included 95 processes on APP-INTEG-01, 42 on DB-CORE-01,
   97 on WEB-EXT-01, 67 on WS-AJOHNSON, and 83 on WS-LNGUYEN. I also found no process object whose
   termination preceded its creation and no session whose logout preceded its login.

2. **Windows identities reconcile across source-native schemas.** Matching eCAR process creation
   to Sysmon event 1 and Security event 4688 within ten seconds produced zero image/principal
   disagreements in the matches. Representative results were DC-01: 152 eCAR creates, 150 Sysmon
   matches, 152 Security matches; DC-02: 118/118/118; FILE-SRV-01: 81/81/81; WS-DRAMIREZ:
   61/61/61; and WS-MCHEN: 90/90/90. Minor unmatched events and non-identical sub-second delays are
   consistent with source collection differences. Complete matching itself was not treated as a
   synthetic indicator; the positive evidence is the correct PID, image, principal, and ordering
   across differing schemas.

3. **DC-01 log clearing has precise process and audit semantics.** In `DC-01_ecar.jsonl`, SYSTEM
   `cmd.exe` PID `5784` is created under `WmiPrvSE.exe` PID `2432` at
   `2024-03-18T17:42:23.625Z` with `/c wevtutil cl Security`; `wevtutil.exe` PID `5800` follows at
   `17:42:23.800Z` and terminates at `17:42:34.789Z`. `DC-01_Sysmon.xml` records the same chain as
   event 1 at `17:42:23.5437677Z` and `17:42:23.7184228Z`, then event 5 for the same process GUID at
   `17:42:34.9432132Z`. `DC-01_Security.xml` records 4688 with hexadecimal PIDs `0x1698` (5784),
   `0x16a8` (5800), and parent `0x980` (2432), then event 1102 at
   `17:42:34.7208375Z`. The Security `EventRecordID` correctly restarts at `1` for 1102 and `2` for
   the subsequent 4689. That sequence is highly source-authentic.

4. **A cross-host Linux SSH session preserves the transport, identity, and shell lineage.** In
   `WS-LNGUYEN_bash_history.txt`, epoch `1710765706` precedes
   `ssh -A lina.nguyen@WEB-EXT-01.meridianhcs.local`. `WS-LNGUYEN_ecar.jsonl` creates
   `/usr/bin/ssh` PID `2947102` under bash at `12:41:46.802Z` and opens
   `10.10.1.21:49654 -> 10.10.3.10:22` at `12:42:01.499Z`. On the destination,
   `WEB-EXT-01_ecar.jsonl` records the exact inbound tuple at `12:42:02.020Z`, login session
   `350498`/logon `0x135f2ec4` at `12:42:09.374Z`, and bash PID `2698447` under sshd at
   `12:42:10.674Z`. `WEB-EXT-01_syslog.jsonl` independently records the connection at
   `12:42:04.322Z`, accepted public key at `12:42:09.628Z`, PAM session open for UID `5302` at
   `12:42:09.804Z`, and systemd-logind session creation at `12:42:10.255Z`.

5. **The DB-to-APP SCP sequence has realistic multi-stage causality.** `DB-CORE-01_bash_history.txt`
   contains `mysqldump`, `gzip`, and `scp` entries ending at epoch `1710782122`.
   `DB-CORE-01_ecar.jsonl` shows `mysqldump` PID `1088927` creating `/tmp/rpt_0318.sql` at
   `17:14:56.566Z`, `gzip` PID `1088993` creating `/tmp/rpt_0318.sql.gz` at
   `17:15:16.883Z`, and `scp` PID `1089028` opening
   `10.10.4.10:45291 -> 10.10.2.30:22` at `17:15:26.375Z`. `APP-INTEG-01_ecar.jsonl` records the
   reciprocal tuple at `17:15:27.209Z`, root session `378785` at `17:15:33.574Z`, and creation of
   `/tmp/.cache/rpt_0318.sql.gz` at `17:16:06.586Z`. A subsequent APP-INTEG-01 `smbclient` process
   opens port 445 to FILE-LNX-01 at `17:19:05.039Z`; the source read and target write are only four
   milliseconds apart (`17:19:06.449Z` and `17:19:06.445Z`).

6. **Credential and process ownership are not naively conflated.** In `FILE-SRV-01_ecar.jsonl`, six
   file reads around `17:00:47.976Z`–`17:00:49.858Z` have top-level principal `marcus.chen` but a
   source process principal `aisha.johnson`, explorer PID `6376`. `FILE-SRV-01_Security.xml`
   corroborates Marcus as the authenticated SMB subject while identifying source IP `10.10.1.35`,
   Aisha's workstation, and logon ID `0xf88477d`. This is plausible alternate-credential behavior,
   not an identity mismatch.

7. **Executable hash behavior is internally coherent.** Within each host/image/version grouping,
   Sysmon event 1 hashes do not change. Shared image/version combinations generally retain the same
   hashes across hosts. The observed `MpCmdRun.exe` differences occur where file version is `-`,
   consistent with different Defender platform builds rather than random per-event hash invention.

## Detailed Analysis

**Windows process trees and EDR correlation.** The data uses source-appropriate PID forms—decimal
in eCAR and Sysmon, hexadecimal in Security 4688—and preserves conversions, parent relationships,
images, users, and termination identities. Sysmon process GUIDs remain stable through create and
terminate records. Event 7 module loads and event 10 process access records attach to existing
processes rather than floating independently. The DC-01 Security-log-clear chain is the strongest
example because it combines WMI ancestry, command execution, process exit, the 1102 audit record,
and the expected Security record-number reset.

**Session lifecycles.** Windows and Linux login/logout ordering is coherent. Network sessions are
typically short, while interactive shells persist long enough to own their child commands. Some
source files expose only one side of a lifecycle—for example, APP-INTEG-01 syslog includes close
evidence for the SCP reception without the full opening sequence even though eCAR has it. This is a
collection gap, not a contradiction, and it was not scored as synthetic.

**Linux host behavior.** The SSH, PAM, systemd-logind, process, flow, bash-history, and file records
compose convincingly in the examined sessions. The weakness is not individual record syntax; it is
the fleet texture. Exact D-Bus/resolver category counts across systems with sharply different roles
and event totals, coupled with repeated service-message pools and concentrated time windows, look
more like bounded category generation than organically accumulated host telemetry.

**User behavior.** Interactive commands, remote administration, file staging, and alternate
credential use form plausible activity chains. The strongest behavioral anomaly is the endpoint
access-client population: AnyConnect, Zscaler, and GlobalProtect appear together on multiple users,
with duplicate GUI processes sometimes overlapping. A real migration can explain this, but the
repeated distribution across users weakens that explanation.

**System and environment consistency.** Host roles are broadly reflected in activity—SMB server
records on FILE-LNX-01, web-facing kernel/network volume on WEB-EXT-01, and heavy authentication
traffic on domain controllers. The Java integration worker on DC-02 is the main role violation.
Fleet-wide verbose `irqbalance`/`snapd` output and exact small-category totals further suggest that
background activity was composed from reusable role catalogs.

**Schema and format.** I found no high-confidence schema or formatting tell. Security XML,
Sysmon XML, syslog, bash history, and eCAR records use plausible field types, identifiers, and
source conventions. I also found no `hard_contradiction` in the examined process/session chains and
no `contract_gap` strong enough to score independently. The verdict therefore rests on
distribution and environmental plausibility rather than malformed records.

## Synthetic Indicator Summary

| Indicator | Category | Weight | Concrete basis |
|---|---|---:|---|
| Exact eight D-Bus and four resolver records on ten Linux hosts | `distribution_texture` | High | Same small totals across 230–1,206-record files and dissimilar roles; records concentrated early |
| Multiple competing access agents and overlapping duplicate clients | `environment_or_collection_plausibility` | Medium-high | AnyConnect, Zscaler, and GlobalProtect co-launched on several workstations; duplicate PanGPA/vpnui instances |
| Java integration worker running as SYSTEM on DC-02 | `environment_or_collection_plausibility` | Medium | Repeated `integration-worker.jar` proxy traffic from a domain controller |
| Broad, verbose irqbalance/snapd chatter | `distribution_texture` | Medium | 55–106 irqbalance records per server and 107 snapd records on WEB-EXT-01 in six hours |
| Similar workstation flow/filtering volumes | `weak_signal` | Low | eCAR FLOW 447–536 and Security 5156 398–496 across six Windows workstations |
| Impossible process/session ordering | `hard_contradiction` | None found | No terminate-before-create, logout-before-login, or visible child-outside-parent lifecycle found |
| Missing required sibling evidence | `contract_gap` | None scored | Observed omissions can be explained by source-local collection gaps |
| Malformed source-native fields | `schema_or_format` | None found | PID forms, GUIDs, hashes, record IDs, XML fields, and syslog conventions are coherent |

## Realism Score by Category (Field format accuracy, Temporal patterns, Cross-source correlation, Behavioral realism, Environmental consistency, each 1-10)

| Category | Score | Rationale |
|---|---:|---|
| Field format accuracy | 9/10 | Source-native fields, PID forms, GUIDs, hashes, and XML/syslog structures are convincing; no decisive format defect found. |
| Temporal patterns | 8/10 | Attack/admin chains and lifecycle ordering are strong, but small Linux background categories are quota-like and front-loaded. |
| Cross-source correlation | 10/10 | Process, session, transport, user, and file identities reconcile across eCAR, Sysmon, Security, syslog, and bash history. This completeness was not treated as synthetic by itself. |
| Behavioral realism | 7/10 | Process trees and user workflows are persuasive; repeated competing and duplicate access clients reduce plausibility. |
| Environmental consistency | 5/10 | Host roles mostly fit, but DC-hosted middleware, access-agent mixing, and uniform background-service recipes weaken fleet coherence. |

## Recommendations

1. Remove fixed per-category Linux event budgets. Generate D-Bus, resolver, anacron, irqbalance,
   and snapd activity from host state and service demand, allowing true zero-inflation and broad
   per-host count variance.
2. Model organization-wide endpoint policy. Select one primary VPN/SSE stack per workstation or
   explicitly encode a migration cohort and prevent overlapping singleton tray/UI instances unless
   a restart or upgrade explains them.
3. Enforce host-role placement constraints so business middleware does not land on domain
   controllers without an explicit exception visible elsewhere in the environment.
4. Tune syslog verbosity per distro, service configuration, and host role; routine debug-like
   irqbalance and snapd messages should not recur at similar intensity across the fleet by default.
5. Preserve the current canonical identity and lifecycle behavior. The cross-source PID, session,
   transport, file, credential, and log-clear correlations are the dataset's strongest authenticity
   features.
