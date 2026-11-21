# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 34

## Executive Summary

The endpoint evidence is mostly production-like: Windows process identities and binary hashes are stable, observed process dependencies respect visible lifetimes, and Linux SSH transport precedes authentication in the matched cases. Unusual macOS executable-size metadata and a narrow Linux background-message distribution leave some concern about constructed telemetry, but neither establishes a hard contradiction without additional platform or collection context. I cannot reliably choose real versus synthetic from this slice alone; the score reflects mostly realistic evidence with limited, explainable artifacts.

## Evidence For Synthetic

- [weak_signal] The macOS Endpoint Security executable metadata has an unusual relative size profile. In `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson`, line 15 at `2026-11-02T13:07:47.657869000Z` reports `/usr/bin/uname` with `st_size=4586636`; line 134 at `18:12:26.915824000Z` reports `/bin/ps` with `st_size=7205747`. By comparison, line 51 at `14:24:12.976390000Z` reports `/usr/bin/ssh` with `st_size=360661`, and line 1's launchd executable is `290721` bytes. The same sizes recur on MAC-MROSS-02. This looks more like a generic metadata pool than the size relationships I normally encounter for these utilities, but I did not inspect matching OS binaries and do **not** call the values impossible. Equal sizes across hosts are not themselves suspicious.
- [environment_or_collection_plausibility] A few background daemons account for a large fraction of several Linux syslogs: DB-PROD-01 has 81 irqbalance and 61 multipathd messages out of 246 rows (57.7% combined); APP-INT-01 has 68 irqbalance and 63 snapd messages out of 278 (47.1%); LOG-MON-01 has 91 irqbalance and 58 snapd messages out of 285 (52.3%). For example, DB-PROD-01's `syslog.log` repeats `sdb: remaining active paths: 1` at `13:08:55.391550Z` and `13:11:28.202984Z`, and `sda: add missing path` at `13:16:51.410930Z` and `13:21:34.166271Z`. This is a somewhat conspicuous background texture, not a missing-source allegation. Verbose daemon settings, storage issues, or filtering could explain it; the influence on the score is small.

## Evidence For Real

- Windows process metadata is internally coherent across the visible native records. I parsed 990 Sysmon Event 1 records across ten Windows hosts. No image path had multiple hash sets within a host, and no shared complete hash set advertised conflicting file versions across the examined process creates. For known visible parents, child records agreed with the parent's PID, image, command line, and user.
- The Windows process trees include credible service and user distinctions. On WS-MCHEN-01, Sysmon creates BITS-hosting `svchost.exe` under `services.exe` as SYSTEM at `13:01:29.419`, GlobalProtect's `PanGPA.exe` under the user's explorer at `13:07:36.733`, and Chrome under explorer with a subsequent Chrome child at `13:15:29.590` and `13:15:30.003`. SearchProtocolHost activity is owned by SearchIndexer rather than arbitrarily attached to explorer.
- The sources show credible differences in rendering and observation times. WS-MCHEN-01's BITS instance has Sysmon PID `7192`, parent PID `5872`, and Security 4688 hexadecimal PIDs `0x1c18` and `0x16f0`, with matching image and command line. Its Sysmon system timestamp is `13:01:29.4219996Z`; Security records creation at `13:01:29.5058694Z`.
- Of 52 Linux SSH accepted-authentication entries matched to an inbound eCAR FLOW by remote IP, remote port, and destination port 22, none had the first matching FLOW after acceptance. Syslog records associated with visible eCAR process PIDs also showed no initiation/termination inversion exceeding a two-second allowance in the checks performed.
- macOS evidence distinguishes forked process identity from successive executable images. MAC-MROSS-01 PID 25527 progresses from inherited launchd to xpcproxy and then Terminal; subsequent login and zsh processes are separate. MAC-MROSS-02 models iTerm2, iTermServer, login, ShellLauncher, and zsh rather than copying the Terminal tree.
- The Mac policy evidence is not falsely represented as execution success. MAC-MROSS-01's Unified Log records an ASP policy warning for MeetingAssist PID 42008 at `15:42:09.009673+0000`; the supplied ES exec records do not show that application successfully executing. I did not infer a successful child or command effects from that message.
- The Linux evidence contains distinct mail-server, Samba, desktop, SSH/PAM, cron, sudo, and administrative-command activity. The mix of PostgreSQL/MySQL administration, application troubleshooting, security review, and user-specific shell histories has more variety than a single generic endpoint command stream.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory. It contains 23 host eCAR files totaling 38,311 records, ten Windows Security/Sysmon host pairs, eleven Linux syslogs, and two macOS ES/Unified Log host pairs, with accompanying shell histories on relevant hosts. The visible endpoint window is approximately `2026-11-02 13:00–19:00 UTC`.

I parsed the Windows XML and endpoint JSON records, inspected actual event bodies, counted event families and daemon distributions, checked known-parent metadata and same-binary hashes, and compared visible starts/ends with dependent evidence. These are bounded consistency checks on this slice, not proof of exhaustive endpoint coverage. I did not use filesystem timestamps, domain validity, absent Sysmon event types, attack narrative neatness, or the completeness of matching as synthetic indicators.

### Windows process identity, schema, and parentage

The native Event 1 counts range from 50 on WS-DRAMIREZ-01 to 163 on DC-01. Security 4688 counts agree closely, with a few source-specific differences that do not themselves establish an error. PID/image joins for the observed pairs found no conflicting image assignments.

The visible Sysmon schema versions are differentiated sensibly: Event 1 and 3 use version 5, Event 5/7/10 use version 3, Event 8/11/13 use version 2, and Event 22 uses version 5. I found no blanket event-version substitution or malformed XML. Versioned Microsoft executable metadata also differentiates host populations: 17763 on FILE-SRV-01, 20348 on the DCs and MAIL-FIN-01, 19041 on several workstations, and 22621 on WS-MCHEN-01 and WS-PPATEL-01.

For each visible Sysmon ProcessGuid, I compared matching Event 1 and Event 5 system timestamps with dependent records carrying that same ProcessGuid. There were no dependent events more than one second before the observed create or after the observed terminate. This check does not cover every specialized source/target GUID field, and it does not imply that missing starts or ends are defects. An equivalent eCAR object/actor identity check also produced no such inversions beyond one second. No pair of visible eCAR CREATE lifetimes reused a PID with overlapping intervals in the check performed.

ProcessAccess data has repeatable call stacks for repeated operations. For example, DC-01 WmiPrvSE PID 2432 accessing svchost PID 2352 with mask `0x1000` uses the same ntdll/KERNELBASE/combase trace at `13:22:02.262`, `13:30:07.567`, and later times. Different core OS build populations did not share exact complete traces in the parsed set. Repetition here is compatible with executing the same code path; I did not penalize it as excessive correlation.

### Windows logon interpretation

The logon-type mix is host-sensitive. WS-MCHEN-01 has fifteen Type 3, ten Type 5, two Type 9, two Type 7, and one Type 2 Event 4624 records. DC-01 has 141 Type 3, 123 Type 5, and four Type 10 records; DC-02 has 149 Type 3, 126 Type 5, and one Type 10. These distributions distinguish domain/service activity from user workstations.

Reserved built-in logon IDs recur in service events, and unlock events reuse an existing interactive identity. Those are not fresh unique session initiators for a naive timestamp join. I therefore did not label earlier SYSTEM process activity as occurring before a later repeated `0x3e7` service logon, or activity before a Type 7 unlock as pre-authentication execution. Similarly, an initial logout near the slice boundary on a Mac can close a pre-window session.

### Linux sessions, commands, and system activity

The syslogs have parseable RFC5424-like envelopes and stable daemon PIDs where expected. Accepted SSH entries include source address/port and authentication method; related PAM/logind evidence and normalized endpoint processes are present in sampled sessions. Matching source tuples across Linux accepted-auth entries and FLOW records did not demonstrate authentication before transport.

DB-PROD-01 illustrates a plausible local lifecycle: an existing agetty process PID 29349 execs login at eCAR time `1793624582618`, followed by Maya Ross's local login at `1793624593636` and bash PID 1366667 at `1793624594886`. Later sudo PID 1366977 launches `/usr/sbin/service mysql status` as root through a separate child PID 1366978. The normalized source principal and child principal distinguish the invoking user from the resulting root command.

Shell histories contain commands with realistic shell syntax, redirection, pipes, service units, and user-specific interests. Examples include Lina Nguyen's build and database commands, Omar Haddad's pandas/data checks, and Priya Patel's audit/authentication review commands. I did not require every history entry to appear as one executable create because built-ins, pipelines, collection filtering, and normalized process representation affect that relationship.

The daemon-heavy distribution noted above is the principal Linux reservation. It could describe a deliberately selected collector configuration. WEB-EXT-01's 838 kernel rows mostly provide another counterexample to a uniform per-host source mix, and their wall-clock versus kernel-uptime-derived boot anchor varies by only about 0.237 seconds, compatible with observation timing rather than random independent uptime values.

### macOS process, audit, and policy evidence

The supplied ES objects declare schema version 1 and message version 11. MAC-MROSS-01 contains 47 fork, 54 exec, and 46 exit records; MAC-MROSS-02 has 55 fork, 65 exec, and 54 exit records. The disparity between fork and exec counts is expected when a process successively changes images.

On MAC-MROSS-01, ES lines 1–3 show PID 25527 fork at `13:07:32.811343000Z`, exec to xpcproxy at `13:07:32.820534000Z`, and exec to Terminal at `13:07:32.835499000Z`. The PID persists while pidversion changes, and the original start time remains the fork time. The eCAR representation retains the object identity across MODIFY/exec rows and explicitly represents the service identity drop. I did not confuse the responsible audit token with the direct parent or a Windows logon ID with a native audit session.

The remote-access samples similarly distinguish sshd startup, sshd-session, sshd-auth, and the eventual zsh. MAC-MROSS-02 records accepted keyboard-interactive/PAM auth at `14:24:35.206464+0000`; a corresponding zsh exec follows at `14:24:35.428147000Z`. MAC-MROSS-01 records public-key acceptance at `16:02:10.700230+0000`, followed by zsh at `16:02:10.821883000Z`.

The executable-size concern remains limited. File identities did not collide across different observed paths on a host; repeated path metadata stayed stable; and inspected block counts were allocation-aligned. I cannot establish that unusual sizes represent an invalid native schema or impossible code signature without the corresponding binary/OS artifacts, which were outside the supplied evidence.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| weak_signal | macOS ES executable stat metadata | Both Macs; examples include uname, ps, ssh, launchd | Unusual relative executable sizes modestly raise concern; no impossibility established and matching binaries were unavailable. |
| environment_or_collection_plausibility | Linux syslog | DB-PROD-01, APP-INT-01, LOG-MON-01; quantified daemon shares above | Concentrated repetitive background health chatter warrants caution; verbose settings or collection filtering remain credible explanations. |
| No established hard contradiction | Windows, Linux, macOS endpoint evidence | The lifecycle, identity, and source comparisons described above | Keeps the score in the mostly-realistic band; consistency supports plausibility but cannot establish provenance. |

## Realism Score by Category

- **Field format accuracy:** 8 — Native envelopes, differentiated event versions, PID formats, and audit structures are credible; Mac executable sizes remain a limited metadata concern.
- **Temporal patterns:** 9 — Checked visible process lifetimes and SSH transport/authentication ordering are coherent, with plausible source observation offsets.
- **Cross-source correlation:** 9 — Examined Windows identities and Linux/native endpoint correlations agree without demonstrated ownership or lifecycle contradictions.
- **Behavioral realism:** 8 — Distinct user and host-role activity, service parentage, shell syntax, and terminal implementations are credible.
- **Environmental consistency:** 7 — Host OS/software populations are differentiated, but some Linux daemon distributions and Mac binary metadata require collection/build context to fully judge.

## Recommendations

- If this were synthetic, derive macOS executable stat metadata from the actual declared platform binaries, preserving agreement among exact file identity, size, code identity, and allocation metadata. The uname/ps/ssh size examples are the concrete fields to verify first.
- If this were synthetic, calibrate Linux health-message shares and daemon verbosity against the intended collector policy, particularly the irqbalance/multipathd-heavy DB-PROD-01 stream and irqbalance/snapd-heavy APP-INT-01 and LOG-MON-01 streams. Preserve genuine noisy-daemon profiles when that is the intended environment rather than simply adding more unrelated logs.
- Retain the observed process identity, fork/exec, source-specific timing, and SSH transport/authentication discipline. None of the checks reported here justifies weakening correlation or introducing random lifecycle errors to make the data appear messier.
