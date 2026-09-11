# Host/EDR Forensics Analyst — Authenticity Assessment
## Verdict
**Assessment:** Real
**Verdict Confidence:** 72
**Synthetic-Confidence Score:** 32
## Executive Summary
The endpoint corpus is more consistent with sanitized or selectively exported production telemetry
than with readily identifiable synthetic telemetry. The strongest result is not narrative
completeness; it is that detailed, source-native contracts survive direct testing. Across 971
matched Windows process starts, eCAR, Sysmon Event 1, and Security Event 4688 agree on PID, image,
parent PID/image, command line, principal, and logon ID. No visible Sysmon dependent event occurs
before the matching ProcessGuid creation or after its termination, and no eCAR child or dependent
action occurs after a visible parent exit. Linux SSH, PAM, systemd-logind, sudo, process, and shell
records likewise preserve their expected ordering.

There are several concrete reservations. Five Windows unlock observations reuse an existing logon
ID and terminal session but receive a new eCAR USER_SESSION objectID, unlike the stable objectID used
for session logout. Four workstation-labeled hosts also show overlapping successful local Type-2
sessions for the same user without visible support that explains why a second local desktop was
created. Finally, process-event volume is low and unusually convergent across disparate Windows
roles, and the Security-versus-Sysmon process timing envelope is strikingly bounded. These are
contract, environmental, and distribution concerns, but none is an impossible event ordering or a
source-native format failure. On balance, the data falls in the rubric's “mostly realistic” band.

## Evidence For Synthetic
1. **[contract_gap] Unlocks split one logical session into multiple eCAR objects.** On
   `WS-MCHEN-01`, eCAR line 45 creates the successful Type-2 session with logon ID `0x6c6a067`,
   session ID `1`, and objectID `015e306f-...`. Lines 429, 843, and 1039 record Type-7 unlocks with
   the same logon ID and session ID but assign three new USER_SESSION objectIDs. The same pattern
   appears on `WS-AJOHNSON-01` (lines 439 and 1370) and `WS-DRAMIREZ-01` (lines 74 and 967).
   Security correctly represents each unlock as Event 4624 Type 7 against the existing logon ID,
   and 4800/4801 use that same ID. Because eCAR already has a unique event `id`, changing the
   `objectID` for an unlock is semantically awkward: process create/terminate and session
   login/logout use objectID as a durable object identity. This repeated inconsistency is the
   strongest synthetic indicator, though it may reflect a real product-specific normalization
   choice rather than fabricated raw telemetry.

2. **[environment_or_collection_plausibility] Repeated overlapping local interactive sessions on
   workstation hosts.** `WS-AJOHNSON-01` starts aisha.johnson Type-2/session-3 at 12:13:58 and then
   Type-2/session-2 at 14:27:19; session 3 remains visible until 14:40:28. `WS-DRAMIREZ-01` starts
   diego.ramirez sessions 3 and 1 only eight minutes apart (12:11:29 and 12:19:45), with neither
   ending before the second begins. `WS-EBROOKS-01` starts sessions 3 and 2 at 16:11:57 and
   16:32:38, and `WS-SMARTINEZ-01` starts sessions 5 and 2 at 13:05:24 and 13:26:49. Multiple local
   desktops can occur through fast-user switching or unusual host policy, but repeating it for the
   same user across four workstation-named systems is not ordinary fleet behavior. No supporting
   disconnect or user-switch evidence explains the overlaps.

3. **[distribution_texture] Windows process coverage is sparse and compressed across unlike
   roles.** Over the approximately six-hour visible window, eCAR records only 61-152 process starts
   per Windows host. Security 4688 counts are similarly low: 155 on `DC-01`, 120 on `DC-02`, and
   62-124 on the six conventional Windows workstations. In the same exports, Security 5156 volume
   ranges from 398 on a workstation to 4,367 on `DC-01`, so the low process population is not simply
   a generally tiny corpus. A filtered endpoint export can explain this—and EventRecordID gaps do
   show that unseen records exist—so this is not treated as a missing-companion contradiction.
   Still, the narrow process-rate band across domain controllers, servers, and user endpoints is
   more regular and thinner than expected from unfiltered process auditing.

4. **[distribution_texture] Cross-provider process timing has a conspicuously controlled
   envelope.** For all 971 process starts jointly visible in Sysmon 1 and Security 4688, Security's
   TimeCreated follows Sysmon's UtcTime by 36.8-647.2 ms; the fleet-wide median is 138.6 ms, no pair
   is within 20 ms, and each host median lies in the narrow 111-157 ms range. A consistent ordering
   is technically plausible because the providers publish at different points in process startup.
   The absence of very small, negative, or long-tail deltas across every host nevertheless looks
   more like a bounded timing model than naturally noisy capture. This is a low-weight indicator,
   not a causality failure.

5. **[weak_signal] One binary identity is reused across distinct Defender platform directories.**
   Sysmon Event 7 on `WS-PPATEL-01` lines 1472-1479 places `MpClient.dll` under
   `Platform\4.18.24010.12-0` but assigns SHA256
   `D1C4EE0A...984687F`; the same digest appears for `MpClient.dll` under
   `Platform\4.18.2301.6-0`, including `WS-AJOHNSON-01` lines 4910-4916 and
   `MAIL-FIN-01` lines 10417-10423. A component can remain byte-identical between package releases,
   so this is not a hard contradiction. Coupled with `FileVersion`, `Description`, `Product`,
   `Company`, and `OriginalFileName` all rendered as `-` for this signed Microsoft DLL, it is a
   small content-catalog smell.

No **hard_contradiction** was substantiated. No repeatable **schema_or_format** failure was found:
the XML parses, provider/event metadata is source-appropriate, RFC 5424 syslog parses cleanly, and
JSON records are structurally consistent.

## Evidence For Real
1. **Process identity and tree agreement is exceptionally strong without visible contradictions.**
   I matched 971 Windows starts by host, PID, and image. Every match agrees across eCAR, Sysmon 1,
   and Security 4688 on command line, user, logon ID, parent PID, and parent image. Sysmon
   ProcessGuids use a stable host-specific first component and change per process; no ProcessGuid
   has multiple visible Event 1 starts, changes PID/image, produces a dependent event before its
   start, or produces one after Event 5. eCAR has no actor-before-create or actor-after-termination
   violations, and its `source_pid`, `source_process_uuid`, `source_image_path`, and
   `source_principal` agree with the referenced actor process.

2. **Process lifetimes have realistic boundary behavior.** There are pre-window terminations and
   processes still active at collection end rather than a forced mass teardown. Visible matched
   process lifetimes vary from sub-second command helpers through multi-minute tools and long-lived
   interactive/browser processes. Exact millisecond durations are not repeated at a suspicious
   scale. Parent processes remain alive through visible child creation, including sudo-to-root,
   SSH shell, PowerShell/cmd, and remote-administration trees.

3. **Windows Security and Sysmon field semantics are highly credible.** Security events use the
   expected providers, channels, versions, tasks, keywords, hexadecimal PIDs/logon IDs, IPv4-mapped
   IPv6 source addresses, access-mask strings, WFP direction tokens, and `\device\harddiskvolumeN`
   application paths. Sysmon events use decimal PIDs, host-stable ProcessGuid morphology, native
   field-name differences such as `SourceProcessGUID` in Event 10 versus `SourceProcessGuid` in
   Event 8, and sensible signed/hash metadata. Inbound Sysmon 3 rows place the remote tuple in
   Source fields, the local server in Destination fields, set `Initiated=false`, and attribute the
   event to the local responder process; outbound rows reverse those semantics correctly.

4. **Logon and remote-session lifecycles are coherent.** Non-built-in Security logon IDs do not
   log off before their visible 4624. Type-3 sessions close quickly where appropriate, while Type-2
   and Type-10 sessions persist. RDP Type-10 logons are followed by 4779 disconnect and eventual
   4634 using the same LogonID—for example, the `DC-01` aisha.johnson session `0x53a7099` spans
   12:25:34, 12:49:39, and 13:01:55. Workstation lock/unlock sequences preserve both logon and
   terminal session IDs in Security 4800, 4624 Type 7, and 4801.

5. **The audit-log-clear sequence is notably source-native.** On `DC-01`, eCAR lines 5363 and 5370
   show `cmd.exe /c wevtutil cl Security` creating `wevtutil.exe`. Security then emits Event 1102 at
   17:42:34.720 with the Microsoft-Windows-Eventlog provider and correctly uses `UserData` /
   `LogFileCleared`, including SYSTEM subject fields. Its EventRecordID is 1, and the next visible
   Security event has EventRecordID 2, while Sysmon continuity is unaffected. This is a technically
   precise piece of host behavior that would be easy to render incorrectly.

6. **Linux authentication evidence is internally and operationally plausible.** All 3,825 syslog
   lines parse as ordered RFC 5424 records. Across 41 accepted SSH daemon PIDs, every visible
   successful session has `Connection from` before `Accepted password/publickey`, then PAM session
   open; systemd-logind creates a terminal session afterward. Visible closes occur in the reverse
   lifecycle order. Failed attempts have connection/failure/preauth-close semantics without a PAM
   session. Of 71 sudo PID groups, successful commands have command, PAM open, and PAM close in
   order; the only command-only groups are explicitly `command not allowed` denials, for which no
   PAM session is expected.

7. **Shell history behavior includes non-obvious but credible details.** Histories use native
   `#epoch` markers, preserve full shell pipelines while eCAR shows the resulting individual child
   processes, and contain host/user-specific administration and development activity rather than a
   single shared script. Empty root histories are not unexplained gaps: `APP-INT-01` eCAR lines
   795-796 show root executing `history -c` and truncating `/root/.bash_history`, while
   `WEB-EXT-01` line 4116 records `shred -u /root/.bash_history`. The latter could still be rewritten
   from Bash's in-memory history unless HISTFILE was separately disabled, but the endpoint record
   provides a direct, plausible reason for the missing artifact.

8. **Environmental identity is stable without obvious template leakage.** Host IP ownership is
   consistent in every eCAR flow: for all 24,590 FLOW/CONNECT records, outbound source and inbound
   destination addresses resolve to the host's single observed local IP. Linux UIDs remain stable
   for the same centrally managed user across hosts, Windows SIDs remain stable across Security
   events, and no event ID, UUID, PID, logon ID, or source-native field contains an overt generator
   label.

## Detailed Analysis
The reviewed corpus contains 33,663 eCAR records across 21 endpoints; 18,687 Windows Security
events and 11,812 Sysmon events across ten Windows systems; 3,825 Linux syslog records across eleven
Linux systems; and per-user Bash histories. Network records were consulted only when required to
test host-side flow direction and SSH/RDP endpoint contracts. Filesystem timestamps, parent
directories, manifests, ground truth, and prior reports were not used as evidence.

For process analysis, eCAR PROCESS/CREATE and PROCESS/TERMINATE records were indexed by objectID,
with actorID references checked against visible parent creation and termination intervals. The
same events were joined to Sysmon 1/5 and Security 4688/4689 by host, PID, image, and nearest event
time. There were no negative visible lifetimes, duplicate visible terminations, actor PID/principal
mismatches, or cross-source process-field disagreements among the 971 matched starts. Counts not
paired inside the slice occur on both edges of the window and do not form later-initiator
contradictions, so they were treated as ordinary bounded-window state.

For Sysmon lifecycle testing, Event 3, 7, 8, 10, 11, 13, and 22 process references were checked
against Event 1 and Event 5 by ProcessGuid. Across all ten hosts, no dependent reference occurs
before a visible matching Event 1 or after a visible Event 5. Source and target facts remain stable
for Event 8 and Event 10, including PID, image, user, and call-trace ownership. Module/file/registry
events retain a live actor and do not outlive the owning process.

For session analysis, Security 4624/4625, 4634, 4672, 4779, 4800, and 4801 were grouped by logon ID,
and corresponding eCAR USER_SESSION events were checked by logon ID, session ID, objectID, user,
and time. Security lifecycle behavior is strong. The main weakness is normalization of Type-7
unlock as a fresh eCAR LOGIN object instead of a state transition on the already existing session.
The separate issue of overlapping same-user Type-2 sessions is possible but insufficiently
explained by the visible endpoint evidence.

For Linux, syslog was parsed by timestamp, host, app name, PID, and message. SSH daemon PIDs were
validated as state machines, sudo commands were checked for authorization/PAM lifecycle, and
systemd-logind session creation/removal was ordered against PAM. eCAR shell/process parentage and
principal transitions were checked for the corresponding sessions. Normal command pipelines split
into multiple child processes correctly; sudo children transition to root while retaining the
calling process as actor; SSH responder transport precedes authentication; and shell termination
does not exhibit impossible parentage.

The corpus also has convincing negative-space behavior. Not every process or session closes before
the collection cutoff, not every source observes every process, and Sysmon module-load filtering is
selective. These are realistic gaps rather than forced completeness. Conversely, the low process
volume and fleet-wide timing regularity remain worth scrutiny because they appear at dataset scale,
not merely in one attack chain.

## Synthetic Indicator Summary
| Indicator | Label | Scope | Strength | Effect on verdict |
|---|---|---:|---|---|
| New eCAR objectID for unlocks that reuse an existing Windows logon/session | contract_gap | 5 unlocks on 3 hosts | Medium | Material; strongest synthetic signal |
| Overlapping same-user Type-2 sessions on workstation-labeled systems | environment_or_collection_plausibility | 4 hosts | Medium | Material but not impossible |
| Sparse, convergent Windows process counts across unlike host roles | distribution_texture | Dataset-wide | Low-medium | Raises synthetic probability; filtering is a viable alternative |
| Uniformly bounded Security-after-Sysmon process timing | distribution_texture | 971 pairs, 10 hosts | Low | Model-like texture, technically plausible |
| Same MpClient.dll hash under two Defender platform-version directories | weak_signal | Several hosts, 2 paths | Low | Possible unchanged component; little weight |
| Impossible visible process/session/SSH ordering | hard_contradiction | None found | None | Strongly favors real |
| Invalid XML, JSON, RFC 5424, or Windows event schema | schema_or_format | None found | None | Favors real |

## Realism Score by Category
| Category | Score | Justification |
|---|---:|---|
| Field format accuracy | 9/10 | Native Windows provider metadata, event versions/tasks, SID/LUID/PID forms, WFP fields, Sysmon GUID/hash fields, RFC 5424 framing, PAM messages, and Bash history syntax are consistently credible. Minor concern: sparse PE metadata and one cross-version Defender hash reuse. |
| Temporal patterns | 9/10 | No visible dependent-before-initiator or post-termination use; process, RDP, SSH, sudo, PAM, logind, and audit-clear ordering is coherent. The 36.8-647.2 ms Security/Sysmon timing envelope is unusually bounded. |
| Cross-source correlation | 10/10 | All 971 matched process starts agree on the tested identity and parentage fields; logon IDs, users, responder flow direction, SSH sessions, and process ownership correlate without a contradiction. Completeness itself was not scored as synthetic. |
| Behavioral realism | 8/10 | User/admin commands, pipelines, privilege transitions, long/short process lifetimes, history cleanup, failed authentication, service activity, and remote administration are operationally plausible. The recurring same-user overlapping console sessions reduce the score. |
| Environmental consistency | 7/10 | IP, SID, UID, host-role, and local/remote endpoint identities remain stable. Thin and convergent Windows process volume plus repeated unexplained workstation Type-2 overlap prevent a higher score. |

## Recommendations
1. Preserve one eCAR USER_SESSION objectID for the lifetime of a Windows logon ID. Represent Type-7
   as an unlock/resume state transition, or explicitly document and validate why a LOGIN event gets
   a new object while its actor points to the original session.

2. Prevent a second same-user Type-2 session on workstation-class systems unless the data also
   contains source-native evidence for fast-user switching, a separate desktop, or a collection
   artifact that explains the overlap. Add an invariant covering concurrent local-session capacity
   by host role/OS policy.

3. Increase per-role and per-user variance in process creation volume, especially for domain
   controllers and active workstations. If the files intentionally represent a filtered export,
   preserve log-visible collection-policy clues so low 4688/Sysmon 1 counts have a defensible
   production explanation.

4. Broaden source-timing tails and allow occasional near-simultaneous process observations where
   source semantics permit. Continue enforcing causal order, but avoid a fleet-wide fixed-looking
   36-647 ms provider envelope.

5. Tie Sysmon PE metadata and hashes to exact binary content/version. Verify that a component
   placed under different Defender platform versions is intentionally byte-identical; otherwise
   emit version-appropriate hashes and native version-resource fields.

6. Retain the existing strengths: durable process identity, parent-lifetime protection,
   source-native EventRecordID reset after Security-log clearing, responder-side flow semantics,
   SSH/PAM/logind ordering, sudo denial behavior, and active-at-cutoff lifecycle handling.
