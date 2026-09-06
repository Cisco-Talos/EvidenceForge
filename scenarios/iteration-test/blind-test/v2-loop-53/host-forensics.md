# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 72  
**Synthetic-Confidence Score:** 61

## Executive Summary

The endpoint evidence is technically coherent and substantially more realistic than a simple
event-template corpus, but it contains one repeated source-native command-line escaping defect and
a dataset-wide timestamp-ordering texture that are difficult to explain as ordinary production
telemetry. I therefore assess the data as synthetic, with only moderate confidence: process and
session lifecycles, Windows schema details, host differentiation, and cross-source identities are
convincing enough to keep the synthetic-confidence score at the low end of “likely synthetic.”

## Evidence For Synthetic

- **[schema_or_format] Literal JSON-style escaping appears inside Windows command lines.** On
  `MAIL-FIN-01`, 23 Security 4688 records and the same 23 Sysmon Event 1 records contain command
  lines such as `"C:\\Program Files\\Microsoft\\Exchange Server\\V15\\Bin\\EdgeTransport.exe" -service`
  or the equivalent IMAP path. The corresponding `NewProcessName`/`Image` is the normal
  `C:\Program Files\Microsoft\Exchange Server\...` path. This is not a UNC prefix: every directory
  separator in the command line is doubled. The defect is visible from
  `2024-03-18T12:01:05.5225931Z` onward and recurs 14 times for `EdgeTransport.exe` and nine times
  for `Microsoft.Exchange.Imap4.exe`. It also propagates into 23 eCAR PROCESS/CREATE records and 13
  Exchange-attributed eCAR FLOW records, which makes it look like an escaped configuration string
  became canonical event truth rather than a command line captured from a Windows process.

- **[distribution_texture] Every matched process start follows the same cross-source clock order.**
  Across all 947 PID-matched Security 4688/Sysmon Event 1 pairs, Sysmon is earlier than Security;
  the observed offset is 35–648 ms, with host medians between 119 and 166 ms. Across 944 matched
  Sysmon/eCAR process starts, eCAR is always later than Sysmon by 2–887 ms. Individual ordering is
  plausible, but zero reversals across ten Windows hosts and nearly one thousand independent starts
  is a conspicuously controlled timing envelope. Production event occurrence times from separate
  providers typically show more provider-, load-, buffering-, and clock-path variation than a
  universal three-stage sequence.

- **[distribution_texture] Linux command histories draw repeatedly from a narrow diagnostic
  vocabulary across unrelated people and systems.** Exact commands such as
  `tail -f /var/log/syslog &`, `systemd-analyze blame | head`,
  `sysctl -a 2>/dev/null | grep net.ipv4.ip_forward`, `iostat -x 1 3`, and
  `ls -lt /var/log | head` each recur in three different history files. Examples span Aisha Johnson,
  Marcus Chen, Priya Patel, and Omar Haddad on application, mail, logging, proxy, database, and
  workstation hosts. These are individually believable commands, and the histories do show some
  role specialization, so this is a moderate pool-reuse signal rather than a contradiction.

- **[weak_signal] Repeated application launches use compact, highly stable module/metadata
  signatures.** Chrome launches repeatedly expose the same three highlighted modules
  (`chrome_elf.dll`, `libEGL.dll`, and `libGLESv2.dll`), Firefox launches the same small trio, and
  Outlook repeatedly exposes `OLMAPI32.DLL` and `mso.dll`. A selective Sysmon configuration can
  legitimately produce this view, so the missing modules are not being scored. The weak signal is
  the highly repeatable, small per-application signature across different hosts and launches, which
  resembles a curated evidence bundle more than naturally varying filtered telemetry.

## Evidence For Real

- Process lifecycle ordering is sound in the visible window. Across Security 4688/4689 and Sysmon
  1/5, I found no PID for which a visible termination precedes its visible creation. Unmatched starts
  and exits occur at both collection boundaries and were not treated as defects.

- All compared Security 4688/Sysmon Event 1 pairs use the same process image for the shared PID;
  there were zero image mismatches. eCAR parent references were also internally strong: every
  linked child process checked had a matching parent object, PID, image, and earlier creation time.

- The `WS-AJOHNSON-01` credential-access sequence is forensically credible. Sysmon Event 1 at
  `2024-03-18T15:45:21.4324060Z` records PID 6092,
  `C:\Windows\System32\ms-index-service.exe`, High integrity, LogonId `0x26db80d`, and an
  Explorer parent. Security 4688 at `15:45:21.6828924Z` agrees on PID (`0x17cc`), user, parent,
  command line, and high mandatory label (`S-1-16-12288`). Sysmon Event 10 then shows access to
  LSASS with `GrantedAccess=0x1FFFFF`, Event 8 records a remote thread with TID 18688, and Sysmon 5,
  Security 4689, and eCAR TERMINATE close PID 6092 about eleven seconds after creation.

- The remote administration sequence on `DC-01` is detailed and correctly ordered. At
  `2024-03-18T15:59:50.193Z`, eCAR records `C:\Windows\PSEXESVC.exe` creation by System/PID 4;
  at `15:59:50.460Z` it records service `PSEXESVC`; at `15:59:51.050Z`, `services.exe` starts PID
  5360; the process loads plausible core modules and spawns `cmd.exe /c whoami && hostname`; the
  PSEXESVC process terminates at `16:00:34.927Z`. The ownership and timing are operationally
  plausible rather than merely name-matched.

- The Linux SSH lifecycle is coherent across endpoints. `WS-LNGUYEN-01` creates
  `/usr/bin/ssh` PID 1470423 at `2024-03-18T13:03:52.080Z` and opens
  `10.10.1.21:40102 -> 10.10.4.10:22` at `13:04:11.066Z`. `DB-PROD-01` records the inbound side
  at `13:04:10.627Z`, a successful Lina Nguyen SSH login on the same tuple at `13:04:20.184Z`, and
  logout using the same session object, source port, logon ID `0x116699af`, and session ID `277025`
  at `14:00:23.572Z`.

- Windows session behavior is varied and bounded-window aware. The logs contain service, network,
  interactive, remote-interactive, unlock, and new-credentials logons. Paired Type 3 sessions range
  from seconds to longer-lived connections, while Type 2 and Type 10 sessions can run for hours.
  There are no visible same-LUID logoffs before their visible logons. Reuse of `0x3e4`, `0x3e5`,
  and `0x3e7` is confined to the well-known service identities and was not treated as an error.

- `DC-01` models a Security-log clear with source-native detail rather than a generic marker.
  `cmd.exe /c wevtutil cl Security` and child `wevtutil.exe` start at
  `2024-03-18T17:42:13`; Event 1102 appears at `17:42:17.0673740Z` under the
  `Microsoft-Windows-Eventlog` provider with the expected `LogFileCleared` UserData and SYSTEM
  subject, and the Security `EventRecordID` resets from 28260993 to 1/2. Subsequent process exits
  are still visible with the reset record sequence.

- Sysmon hash handling is internally credible. I found no SHA1, MD5, SHA256, or IMPHASH value
  reused across two distinct image paths. Common Windows binaries vary by visible OS family
  (10.0.17763, 10.0.19041, 10.0.20348, and 10.0.22621 metadata), while repeated instances within a
  build remain stable.

## Detailed Analysis

**Scope and collection shape.** The permitted directory contains 21 host eCAR streams, ten Windows
Security logs, ten Sysmon logs, and timestamped bash histories on Linux systems. The visible window
is approximately six hours on 2024-03-18, generally 12:00–18:00 UTC. I counted 18,045 Security
events, 4,977 Sysmon events, and 32,542 eCAR records. I did not use file mtimes, directory naming
outside the data tree, absent selected Sysmon types, sanitized domains, or mere correlation
completeness as authenticity evidence. No source-native syslog file is present in the permitted
data; that limits Linux source-native assessment but is not itself evidence of synthesis.

**Windows process creation and termination.** The Security logs contain 951 Event 4688 process
starts; Sysmon contains 947 Event 1 starts. Shared PID/image pairs are consistent. Hosts with more
server activity (`DC-01`, `DC-02`) show substantially more process starts than quieter endpoints,
and parent-child combinations are generally credible: `services.exe -> svchost.exe`,
`svchost.exe -> taskhostw.exe`, `SearchIndexer.exe -> SearchProtocolHost.exe`,
`winlogon.exe -> userinit.exe -> explorer.exe`, and `csrss.exe -> conhost.exe`. There is also
host-appropriate software such as Exchange transport/IMAP services, Defender, Veeam, Office,
Chrome, Firefox, Slack, Power BI, Postman, DBeaver, and endpoint update clients.

Visible lifecycle boundaries behave well. No Security or Sysmon termination precedes a creation
for the same PID, and the more suspicious process families carry the same identity through process
access, remote-thread, module, file, flow, and termination evidence. Differences between start and
exit counts are concentrated in long-lived processes and at the six-hour edges, so I did not score
them as lifecycle gaps.

The principal process-format defect is confined but unmistakable. The Exchange `Image` field uses
normal paths, while the captured `CommandLine` uses doubled separators throughout. Because the
same malformed value appears independently in Security, Sysmon, and decoded eCAR properties, the
issue is not XML or JSON display escaping at rest; it is present in the parsed field value. In a
real event, quotation marks may surround a path, and a UNC path may begin with `\\`, but a local
drive path would not normally be recorded with every internal separator doubled across 23 service
starts. This is the strongest reason for the synthetic verdict.

**Session lifecycles.** Domain controllers show the expected concentration of Type 3 network and
Type 5 service logons, while user endpoints contain Type 2 interactive sessions and occasional Type
7, 9, and 10 activity. `DC-01`, for example, contains 302 successful logons: 171 Type 3, 130 Type 5,
and one Type 10. `FILE-SRV-01` contains 75 Type 3, 46 Type 5, and one Type 2. Workstation counts are
lower and centered on their named user. Paired Type 3 durations include short 2–60 second service
transactions as well as a few long sessions; interactive and remote-interactive examples extend for
hours. The visible ordering is valid, and unmatched sessions are compatible with a bounded window.

The exact eCAR object reused for SSH login/logout is a particularly good detail. On the Lina Nguyen
DB session, the receiver's transport precedes authentication by roughly 9.6 seconds, and the logout
retains the source tuple and session identifiers nearly 56 minutes later. Similar root-owned
`sshd: user [priv]` processes and user-owned shell/command processes reflect Linux privilege
boundaries reasonably well. Sudo-launched commands execute as root while retaining the originating
user's logon/session ID, which is plausible and was not misclassified as a principal mismatch.

**Sysmon and eCAR semantics.** Sysmon fields are generally source-native: Event 1 includes process
and parent GUIDs, decimal PIDs, logon identity, integrity level, hashes, and current directory;
Event 8 distinguishes source/target process and users and includes a formatted start address;
Event 10 contains access masks and call traces; Event 11 contains both observation and creation
times; Event 13 uses `SetValue` plus typed details; and Event 22 includes process-attributed DNS
results. The credential-access example demonstrates that these fields are not merely populated but
are carried coherently into eCAR PROCESS/OPEN and THREAD/REMOTE_CREATE objects.

The main temporal concern is statistical rather than causal. A single sequence in which Sysmon
precedes Security and eCAR follows is credible. The concern is that this order holds without one
exception across every matched process on every Windows host, with broadly similar offset ranges.
That resembles an explicit source-timing planner. I found no dependent process event occurring
before its initiator, so this is not a hard ordering contradiction; it is a repeated timing texture
that materially raises synthetic confidence.

**User and system behavior.** The user-facing evidence is differentiated. Lina Nguyen's workstation
contains development and data tooling (`emacs`, Git, Make, Python, SSH to the database); Omar
Haddad runs database-oriented discovery; finance/user workstations launch Outlook and productivity
applications; administrative users inspect services, logs, storage, and network state. Background
Windows evidence includes Defender scans, update clients, WMI providers, COM surrogates, Search
Indexer children, scheduled-task hosts, DNS, Kerberos-facing activity, service starts, and routine
registry writes. This creates a lived-in appearance.

The weakness is reuse of exact shell diagnostics across otherwise unrelated sessions. The reuse is
not so extensive that every history looks cloned—many commands occur only once, and role-specific
sequences exist—but the long tail is thinner than I would expect from independent operators. I
therefore weighted it as a moderate distribution indicator, not as proof.

**Overall weighing.** The record set passes the most important host-forensics coherence tests: PID,
GUID, image, principal, logon ID, parent, and lifecycle relationships are consistently usable, and
the rare attack-adjacent chains have believable endpoint mechanics. The repeated local-path escaping
artifact is nevertheless difficult to reconcile with captured Windows telemetry, and the universal
provider ordering adds a dataset-wide generated texture. Together they move the assessment just
into “likely synthetic,” while the many realistic details prevent a high-confidence synthetic score.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Score effect |
|---|---|---|---|
| `schema_or_format` | Security 4688, Sysmon 1, eCAR PROCESS/FLOW | 23 Exchange starts in each Windows source; malformed value propagated into 36 eCAR records | High: literal doubled local-path separators are the clearest generation/escaping artifact. |
| `distribution_texture` | Security, Sysmon, eCAR process starts | Dataset-wide across 947 Security/Sysmon and 944 Sysmon/eCAR matched starts | High-medium: the provider order never reverses and remains in a controlled offset envelope. |
| `distribution_texture` | Bash history | Repeated exact diagnostics across three unrelated histories per command | Medium-low: suggests a shared command pool, but individual commands and role-specific sequences remain plausible. |
| `weak_signal` | Sysmon module loads | Repeated, compact per-application module signatures | Low: compatible with selective collection and not persuasive independently. |

## Realism Score by Category

- **Field format accuracy:** 7/10 — Most Windows and eCAR fields are well formed, but the repeated
  doubled-separator Exchange command lines are a material source-native defect.
- **Temporal patterns:** 6/10 — Individual lifecycles and causal ordering are sound; universal
  cross-provider ordering is too controlled.
- **Cross-source correlation:** 9/10 — PIDs, images, GUIDs, users, logon IDs, source tuples, and
  lifecycle objects agree without concrete contradictions; completeness itself was not scored.
- **Behavioral realism:** 7/10 — Host roles, user tools, remote administration, credential access,
  and maintenance behavior are credible, with some shared command-pool texture.
- **Environmental consistency:** 8/10 — OS-build metadata, services, software placement, account
  types, and server/workstation behavior are mostly consistent with a mixed enterprise fleet.

## Recommendations

- If this were synthetic, preserve raw command-line strings without applying JSON/YAML escaping a
  second time. Add a source-level assertion that local drive paths in parsed Windows command-line
  fields do not contain doubled internal separators, while explicitly allowing leading UNC `\\`.
  Verify the corrected value simultaneously in Security 4688, Sysmon Event 1, and eCAR descendants.

- Replace universal source-order offsets with source-native occurrence semantics. Security and
  Sysmon should derive their event time from the same underlying process start, with only behavior
  justified by the providers themselves; ingestion or collection delay should be represented
  separately from occurrence time. Add a distribution test that detects a perfect ordering relation
  across hundreds of otherwise independent events.

- Expand shell-command choice using persona, host role, prior command context, installed software,
  and session purpose. Preserve common commands, but reduce exact reuse of longer diagnostic
  pipelines across unrelated users and systems and introduce more user-specific aliases, options,
  paths, typo corrections, and task-continuation sequences.

- Keep the existing canonical lifecycle and identity discipline. Regression tests should retain the
  observed strengths: no termination before creation, exact PID/image agreement where both Windows
  providers observe a process, valid parent ownership, stable hashes for the same binary build, and
  receiver-side SSH authentication/close evidence tied to the original tuple.

- Continue validating rare source-native chains, especially service creation, Security-log clearing,
  LSASS access, remote threads, and sudo/SSH transitions. These are the records most likely to expose
  synthetic defects, and in this dataset they are among the most convincing evidence for realism.
