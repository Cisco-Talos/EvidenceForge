# Detection Engineer — Authenticity Assessment

## Verdict

- Assessment: Synthetic
- Verdict Confidence: 74
- Synthetic-Confidence Score: 66

## Executive Summary

The dataset is highly sophisticated and operationally useful. Windows, Sysmon, eCAR, Zeek, ASA, Snort, proxy, SMTP, web, and Linux records generally obey source-native schemas, preserve identifiers, and maintain credible transport, process, authentication, and file lifecycles.

The deciding evidence is a repeated Windows RDP lifecycle contradiction: two separate Type 10 logons each produce two nearly simultaneous `userinit.exe → explorer.exe` initialization chains under one `winlogon.exe`, one Logon ID, and one successful logon. This is characteristic of duplicate generation ownership, not a normal single-session startup. A secondary concern is repeated baseline texture in which the same generic Linux identities perform successful interactive sudo activity across many unrelated host roles.

No broad schema failure was found. Most evidence strongly resembles sanitized production telemetry, so the verdict is “likely synthetic,” not confidently synthetic.

## Evidence For Synthetic

1. **[hard_contradiction] Duplicate RDP session-initialization trees**

   `WS-AJOHNSON-01` records one Event 4624 Type 10 logon at `2024-03-18T15:20:00.6981893Z`, Logon ID `0x2700aee`, from `10.10.1.99:60400`, with `winlogon.exe` PID `0x19cc`. That single session then creates:

   - `userinit.exe` PID `0x1a04` at `15:20:01.9791796Z`
   - `userinit.exe` PID `0x19e0` at `15:20:01.9821796Z`
   - `explorer.exe` PID `0x1a14` from `0x1a04` at `15:20:02.1391781Z`
   - `explorer.exe` PID `0x19fc` from `0x19e0` at `15:20:02.1441786Z`

   All four processes carry the same Logon ID. There is no second 4624 or second `winlogon.exe` to justify two independent initialization trees.

   The same artifact recurs on `WS-MCHEN-01`: one Type 10 logon at `15:13:33.0689697Z`, Logon ID `0x6db5d40`, is followed by two `userinit.exe` children of PID `0x236c` and two corresponding `explorer.exe` children within 18 milliseconds. Repetition on two hosts strongly suggests two generation paths emitted the same lifecycle.

2. **[distribution_texture] Reused interactive-administration template across Linux roles**

   Across the Linux syslogs, 65 sudo command episodes use the same small identity set—`admin`, `backup`, `deploy`, `ops`, `svc_app`, and `ubuntu`—across application, database, mail, proxy, web, and workstation roles. All 65 have the same successful three-stage shape: command record, `pam_unix` session opened, session closed.

   Exact examples include:

   - `backup` restarting `systemd-resolved` on `APP-INT-01` at `13:25:35Z`
   - `svc_app` running `lsof -i -P -n` on `DB-PROD-01` at `12:50:10Z`
   - `svc_app` interactively checking `sshd` on `WS-OHADDAD-01` at `13:57:27Z`
   - `deploy` and `ubuntu` issuing unrelated diagnostic commands on numerous server classes

   Centralized administration could explain shared identities, but interactive PTYs for service-like accounts and the uniform success lifecycle across unrelated roles look pool-generated.

3. **[environment_or_collection_plausibility] Duplicate ownership is localized rather than a collection duplicate**

   The duplicate RDP chains use distinct PIDs and valid parent-child links, while the surrounding Security record sequence contains only one 4624 and one transport session. This is not a duplicated XML record or whole-event replay; it is duplicated semantic construction of the endpoint session.

4. **[weak_signal] Baseline command selection is unusually interchangeable**

   Administrative users repeatedly draw from a common pool of `systemctl`, `journalctl`, `find`, `apt`, `ss`, and filesystem checks with little role specialization. This is plausible in isolation, but reinforces the repeated-template signal.

## Evidence For Real

1. **Source-native schema fidelity is strong**

   Windows Security and Sysmon event versions, tasks, field sets, path syntax, hexadecimal PIDs and Logon IDs, SIDs, provider GUIDs, and thread/PID alignment are credible. Sysmon Event IDs 1, 3, 5, 7, 8, 10, 11, 13, and 22 have internally consistent schemas.

2. **Windows lifecycle integrity is otherwise excellent**

   Across 4,152 Sysmon records, no visible dependent event preceded its matching visible process creation, and no matching termination preceded creation. Orphan terminations are compatible with pre-window processes. Event 1102 on `DC-01` is correctly represented with `UserData/LogFileCleared`, resets `EventRecordID` to 1, and is preceded by `wevtutil cl Security`.

3. **eCAR identifier and lifecycle consistency is strong**

   Across 25,305 eCAR records, event IDs are globally unique. No dependent event with a visible process actor precedes that actor’s creation, no dependency follows its visible termination, and no same-PID process lifetimes overlap.

4. **Network protocol contracts are unusually good**

   The 11,663 Zeek connections have unique UIDs. DNS, DHCP, HTTP, SSL, SMTP, files, PE, OCSP, and X.509 companions reference valid parent records and occur inside their connection intervals. Packet/byte accounting has no minimum-header violations, and S0 connections have no response packets.

5. **Collection imperfections are modeled credibly**

   A Citrix download on the client-proxy leg has 135,185,374 response-body bytes at `zeek-core` but 135,152,606 at `zeek-dmz`. The latter records exactly 32,768 missing file bytes and 32,770 connection `missed_bytes`, explaining the vantage difference rather than silently contradicting it.

6. **IDS evidence is rule-feasible**

   All 69 `snort-core` alerts and all 136 `snort-perimeter` alerts match a same-sensor Zeek tuple within 0.073 seconds. This supports practical validation of DNS-TLD, PE download, scan, STUN, TLS, and policy signatures.

7. **Firewall lifecycle is credible**

   ASA contains 4,137 TCP build records and 4,136 corresponding teardowns, with no orphan teardown, duplicate connection ID, or teardown-before-build. One open connection at the window boundary is normal.

8. **Mail correlation is source-authentic**

   Message ID `<notices-b9dac45a-8235363@benefits-serviceportal.com>` and queue ID `00F92F1A3C` persist from Zeek SMTP through Postfix `smtpd`, `cleanup`, `qmgr`, per-recipient delivery, and removal. Recipient splitting between local delivery and relay is coherent.

9. **Attack detections are operationally viable**

   Defenders can detect and correlate Events 4720, 4724, 4728, 4697, 4698, and 1102; `WmiPrvSE.exe → cmd.exe → net.exe/sc.exe/schtasks.exe`; `PSEXESVC`; encoded PowerShell; `wevtutil cl Security`; RDP Type 10 logons; SMB collection; archive creation; database dumping; SCP transfer; and associated network flows.

## Detailed Analysis

### Event and schema semantics

The XML and JSON records are largely usable without normalization repairs. Windows event field names and source-specific values are credible, and Zeek uses appropriate UID/FUID relationships. HTTP CONNECT behavior, proxy control-byte versus tunnel-byte accounting, TLS resumption, certificate-chain references, SMTP transaction depth, and DHCP request/ack records are coherent.

The main schema-level weakness is not field formatting but semantic duplication in the RDP process lifecycle.

### Temporal and lifecycle behavior

Transport generally precedes dependent authentication. For example, the RDP connection from `10.10.1.99:60400` to `10.10.1.35:3389` begins in Zeek at `15:20:00.038448Z`, before the target 4624 at `15:20:00.6981893Z`, and remains established for 3,528.279617 seconds.

Process creation, file access, flow initiation, and termination ordering are otherwise well controlled. The duplicated RDP shell initialization is conspicuous precisely because the rest of the lifecycle handling is consistent.

### Cross-source evidence

Zeek, Snort, ASA, proxy, endpoint, SMTP, and host logs generally agree while retaining plausible source latency and loss. Matching is not treated as synthetic evidence; the dataset earns realism credit because it includes differing sensor timestamps, distinct sensor UIDs, packet loss, source-specific byte scopes, and source-native identifiers.

### Detection feasibility

High-value rules can be written against native records without relying on narrative knowledge:

- Correlate 4720 followed by 4728 for the same account.
- Alert on 4697/4698 whose binary or task action follows remote WMI execution.
- Detect `wevtutil cl Security` with Event 1102.
- Detect encoded PowerShell launched as SYSTEM.
- Correlate Type 10 logons with Zeek TCP/3389 and source-host endpoint FLOW records.
- Correlate `mysqldump`, archive creation, SCP, and destination file creation.

### Environment plausibility

Host roles, subnet placement, explicit proxying, DC services, mail routing, file sharing, and sensor placement are broadly credible. The most questionable environmental feature is the ubiquitous pool of generic Linux administrators and service-like identities performing interactive diagnostics on almost every host class.

## Synthetic Indicator Summary

| Indicator | Label | Weight |
|---|---|---:|
| Two separate Type 10 sessions each create duplicate `userinit.exe → explorer.exe` trees under one logon | `hard_contradiction` | High |
| Same six Linux identities repeatedly perform successful PTY sudo activity across unrelated roles | `distribution_texture` | Medium |
| Service-like accounts such as `svc_app` receive interactive TTYs and run generic diagnostics on servers and workstations | `environment_or_collection_plausibility` | Medium |
| Broad reuse of a small interchangeable administration-command pool | `weak_signal` | Low |
| No broad Windows, Zeek, firewall, SMTP, or IDS schema failure | `schema_or_format` | Evidence against synthetic |

## Realism Score by Category

| Category | Score |
|---|---:|
| Schema and source-format fidelity | 9/10 |
| Temporal and lifecycle coherence | 7/10 |
| Cross-source correlation | 9/10 |
| Environment and behavioral plausibility | 7/10 |
| Detection-rule feasibility | 9/10 |

## Recommendations

1. Make one component the sole owner of RDP interactive-session initialization. Assert exactly one `userinit.exe` and one initial shell per `winlogon.exe` and Logon ID unless a second explicit logon exists.
2. Add regression checks grouping 4624 Type 10, `winlogon.exe`, `userinit.exe`, and `explorer.exe` by target Logon ID.
3. Specialize Linux administrative identities and commands by host role. Avoid routine interactive PTYs for service accounts unless explicitly justified.
4. Introduce failed or interrupted sudo episodes, longer-lived sessions, and role-specific maintenance patterns to reduce the repeated success-template texture.
5. Preserve the current network accounting, sensor-specific loss, queue-ID propagation, source-native timing, and lifecycle correlation; these are the strongest authenticity features.
6. Retain the existing detection-rich evidence around account creation, privilege assignment, WMI/PsExec, persistence, log clearing, staging, and transfer, while testing that each activity has one canonical lifecycle owner.
