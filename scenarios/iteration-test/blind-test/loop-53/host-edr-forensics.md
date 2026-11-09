# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 80
**Synthetic-Confidence Score:** 43

## Executive Summary

The endpoint evidence is substantially plausible: process identity, Windows process lifecycles, session ownership, and the distinction between macOS fork and successive exec images generally survive direct examination. Linux background logging has a conspicuous concentration in small recurring daemon-message vocabularies, but I did not establish an impossible same-identity lifecycle or a verified native-format contradiction; those texture concerns support a mixed assessment rather than a confident synthetic verdict.

## Evidence For Synthetic

- [distribution_texture] Linux server background noise repeatedly concentrates in very small message sets. `WEB-EXT-01.meridianhcs.local/syslog.log` contains 121 irqbalance rows, all drawn from four fully identical message bodies for IRQ 86/CPU 2/`mlx5_comp1`, with counts 41, 30, 25, and 25. Examples are lines 10, 49, 58, 76, and 77; the identical balancing-pass sentence occurs at both 13:12:14.969162Z and 13:12:30.438744Z. `DB-PROD-01.meridianhcs.local/syslog.log` similarly has 68 irqbalance rows from four bodies for IRQ 16/CPU 0/`ahci`. Repetition is natural for daemon logs, so this is a moderate texture concern, not a contradiction.
- [environment_or_collection_plausibility] The relative background-source distribution is unusual across different server roles: irqbalance plus snapd contribute 114/221 APP-INT syslog records, 159/262 LOG-MON records, and 99/217 PROXY records. On DB-PROD, irqbalance plus multipathd contribute 123/212 records. A deliberately narrow collector or unusually verbose daemon settings can explain this; no settings are supplied. The concern is this specific volume/distribution pattern, not the absence of other source families.
- [weak_signal] The two macOS shell histories repeatedly revisit the same diagnostic vocabulary over the visible workday. MAC-MROSS-01 history lines 4–6, 8–12, 15–16, and 18–20 cover `pwd`, `ls`, `du`, `df`, `ps`, `find`, `ifconfig`, `dscl`, `sw_vers`, and `id`; MAC-MROSS-02 repeatedly uses nearly the same commands. These are two machines used by the same named account, so legitimate troubleshooting is a strong alternative. This receives little weight and does not establish origin.

## Evidence For Real

- Windows process identities are internally stable. Across all ten Sysmon files, the 948 visible Event 1 creations and 789 Event 5 terminations did not reveal a same-GUID activity record before its visible creation or after its visible termination when compared using source `UtcTime`. Matching references also maintained PID and image identity, including parent and process-access fields.
- Hashes remain consistent for repeated executions of the same image path within each examined Windows host. This supports usable binary identity; it does not prove the binaries' provenance.
- A concrete three-source example agrees closely: WS-MCHEN PID 6792, SearchProtocolHost.exe, appears in Sysmon Event 1 at 13:00:31.980, Security 4688 at 13:00:32.0907714Z, and eCAR PROCESS/CREATE at 13:00:32.082Z. Its Sysmon GUID is preserved through termination at 13:14:45.553; Security records termination at 13:14:45.3276865Z. Files/starting lines: Sysmon 105 and 539, Security 126 and 862, eCAR 5.
- macOS records distinguish a forked process from new executable images in the same PID. MAC-MROSS-01 native ES lines 1–7 show launchd → xpcproxy → Terminal, then Terminal → login → zsh; PID 42171 persists across the xpcproxy/Terminal execs while pidversion advances. MAC-MROSS-02 uses an appropriately different iTermServer/login/ShellLauncher/zsh chain, native ES lines 3–12.
- Linux SSH evidence has specific transport, authentication, PAM, and logind relationships. DB-PROD syslog lines 193–196 show a connection from 10.10.2.30:51026, accepted root authentication, PAM open, then a new logind session, at 18:14:42.266145Z through 18:14:51.456154Z. eCAR later attributes the associated dump/compression/transfer processes to the root shell rather than a generic unrelated parent.
- The visible environments differ meaningfully. The web server has 936 kernel rows among 1,342 syslog records; the Linux file server has 162 smbd and 146 smbd_audit rows among 604; mail hosts carry Postfix/Dovecot activity. The distribution is not identical across all hosts.

## Detailed Analysis

### Inputs, provenance, and method

I read the complete supplied neutral briefing at `/private/tmp/log-study-_yn9uggi/host-prompt.md`, inventoried files only under `/private/tmp/log-study-_yn9uggi/data`, and analyzed those records using system `python3` with `/private/tmp` as the working directory. I did not read project files, scenarios, TODO/worklogs, previous assessments, neighboring review outputs, or source code for the task project. Generic inherited environment instructions were not treated as evidence of origin. Embedded command lines were parsed as inert text and never executed.

Endpoint inputs comprised 37,051 normalized eCAR rows across 23 hosts; 19,553 Windows Security XML events and 12,119 Sysmon XML events across ten Windows hosts; 4,191 Linux syslog rows across eleven hosts; and 304 macOS Endpoint Security rows, five Unified Log rows, plus shell histories across two Mac hosts. I inspected representative native records in depth and performed full-file aggregate/identity checks. Network-family files were inventoried but not used as substitutes for native endpoint evidence. All cited file names below are relative to the supplied data directory; XML line references identify the opening `<Event>` line.

Public references were limited to Apple/Microsoft documentation searches with actual `domains` restrictions and direct raw upstream irqbalance/snapd source URLs. The additional GitHub-domain searches returned no results. Specific references actually consulted are identified below. No task-project public pages or prior-assessment information was accessed or exposed.

### Windows process and session evidence

The Windows sources contain substantial ordinary process/service activity, not just suspicious executions. Examples on WS-MCHEN include SearchIndexer children, service-hosted tasks, Windows servicing, Outlook, browsers, management consoles, SSH clients, RDP clients, and user-launched tools. Process identity checks used GUIDs rather than PID alone, avoiding false positives from PID reuse. Microsoft's documentation specifically identifies the GUID as the correlation mechanism and Event 5 as process termination. [Microsoft Sysmon documentation](https://learn.microsoft.com/en-au/sysinternals/downloads/sysmon)

The process-lifecycle scan tested each record's ProcessGuid and, where present, SourceProcessGUID and TargetProcessGUID against visible Event 1 and Event 5 boundaries using `UtcTime`. It found zero before-create or after-terminate violations. A separate scan compared ProcessId/Image, ParentProcessId/ParentImage, and source/target access identities with their corresponding visible creation records; it found zero identity mismatches. Per-host image-path/hash sets had no conflicting Event 1 hash values. These results are evidence against obvious lifecycle fabrication, not an authenticity guarantee and not a claim that all process activity was collected.

Security contains 873 successful logon events, 437 logoffs, 20 failed logons, and paired workstation lock/unlock events (eight each). The visible logon-type mix includes interactive, network, service, RDP, unlock, and new-credentials semantics where appropriate. WS-MCHEN has Type 9 activity alongside explicit-credential use, while DCs have much larger network/service logon volumes. A scan of non-well-known LUIDs found no visible use before the first non-unlock 4624 or after a visible 4634. I excluded fixed built-in service identities and did not misinterpret an unlock event reusing an existing LUID as a new session creation. Missing starts or closes at window boundaries received no penalty.

### Linux behavior and daemon texture

The SSH example above has a plausible accepted-authentication/PAM/logind sequence, and its process evidence includes a privilege-separated sshd parent and the user shell. Shell histories preserve quoting, pipes, globbing, aliases, builtins, and commands that need not each correspond to a separate executable process. I therefore did not demand a one-to-one history/process match.

The main reservation is the background message population. On WEB-EXT, all irqbalance records reduce to four exact bodies, with a stable IRQ, CPU, and device; the same four sentence forms recur with other host-specific constants on DB-PROD and WS-LNGUYEN. WEB-EXT also contains 128 snapd rows, with recurring generic refresh/check/hook/task messages. On DB-PROD, 55 multipathd rows repeatedly draw from messages about adding missing paths or one/two remaining paths for `sda`, `sdb`, or `dm-0`. Such daemon repetition can be real, particularly under verbose settings or a recurring fault. The combination of narrow message vocabularies and their substantial shares of multiple server logs is the strongest reason the synthetic-confidence score rises into the mixed range.

I attempted a limited upstream vocabulary check against irqbalance `irqbalance.c` and `classify.c`, and snapd `daemon.go`, `overlord/state/taskrunner.go`, and `overlord/snapstate/autorefresh.go`. The specific sampled log phrases were not validated by those inspected current files. That limited negative result is **not** proof of invented native messages: the installed versions, patches, and complete logging implementation are unknown. I did not score a schema defect from it. [irqbalance main implementation](https://raw.githubusercontent.com/Irqbalance/irqbalance/master/irqbalance.c), [irqbalance classification implementation](https://raw.githubusercontent.com/Irqbalance/irqbalance/master/classify.c), [snapd daemon](https://raw.githubusercontent.com/canonical/snapd/master/daemon/daemon.go), [snapd task runner](https://raw.githubusercontent.com/canonical/snapd/master/overlord/state/taskrunner.go), [snapd auto-refresh](https://raw.githubusercontent.com/canonical/snapd/master/overlord/snapstate/autorefresh.go)

### macOS native and normalized evidence

Native ES exports declare schema_version 1 and message version 11, with fork/exec/exit event types 11/9/15. I treated this as an exported ES representation, not as a Windows or Linux schema. Apple distinguishes the message's acting process from the exec target and exposes audit tokens, original/current parent, group/session IDs, responsible identity, and executable code-signing state separately. The records preserve those distinctions in the sampled local and remote sessions. [Apple es_message_t](https://developer.apple.com/documentation/endpointsecurity/es_message_t), [Apple es_process_t](https://developer.apple.com/documentation/endpointsecurity/es_process_t), [Apple es_event_exec_t](https://developer.apple.com/documentation/endpointsecurity/es_event_exec_t?language=o_9)

For MAC-MROSS-01's SSH receiver, native ES lines 67–80 show PID 64370 advancing through xpcproxy, sshd-keygen-wrapper, sshd, and sshd-session images; separate helper children appear, and PID 64375 eventually execs zsh. Native line 80 has auid/euid 501, audit session 100002, and POSIX process-group/session 64375. Those numbers are not confused with the normalized eCAR logon identifier `0x894682e`. Native lines 84–86 close the shell and server processes at 16:17:59.585257Z through 16:17:59.997772Z. The local Terminal-derived shell remains a separate process/session.

Some eCAR timestamps lag these native records by roughly one to several seconds. The normalized schema does not establish that its timestamps are unbuffered kernel occurrence times, and its own process lifecycle remains ordered. I did not promote collection/normalization latency into an impossible-event finding.

MAC-MROSS-01 Unified Log line 2 reports a security-policy refusal involving MeetingAssist at 15:41:46.254163Z. I found no matching successful ES exec for that executable. I did not infer that a prompt meant denial or that a denied attempt created a successful child. Conversely, I did not demand a complete policy-event export when only selected native event types are supplied.

The macOS histories' repeated diagnostic commands are a weak texture signal, mitigated by the same named user operating both hosts. Long-lived SSH commands with zero elapsed-time history fields were not scored as a contradiction because shell history write/import options are not supplied. Short visible process gaps, missing pre-window ancestors, missing post-window exits, complete matches, and sparse Unified Log coverage were all treated as neutral by themselves.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Linux syslog/irqbalance | WEB-EXT: 121 rows, four exact bodies; DB-PROD: 68 rows, four bodies | Moderate concern about narrow recurring texture; legitimate daemon repetition remains plausible |
| environment_or_collection_plausibility | Linux syslog source proportions | APP-INT, LOG-MON, PROXY, DB-PROD | Moderate concern about unusually large shares of low-level daemon chatter across differing server roles |
| weak_signal | macOS zsh histories | Same named account on two hosts | Small contribution; repeated diagnostic pool has a strong troubleshooting explanation |

No hard contradiction or demonstrated native-schema defect was established. The score reflects the listed texture and distribution reservations, balanced against strong endpoint identity/lifecycle evidence.

## Realism Score by Category

- **Field format accuracy:** 9 — Native/normalized distinctions are maintained; no verified field-shape defect found.
- **Temporal patterns:** 8 — Source-local process/session lifecycles hold; daemon texture is more questionable than causality.
- **Cross-source correlation:** 9 — Sampled Windows Security/Sysmon/eCAR identities agree, and macOS exec identity is preserved.
- **Behavioral realism:** 7 — User and service activity is plausible, with repetitive diagnostic/background vocabularies.
- **Environmental consistency:** 8 — Hosts have role-specific source mixtures, although daemon logging proportions merit explanation.

## Recommendations

- If this were synthetic, model Linux daemon message production from explicit daemon states and configured verbosity, so repeated balancing, refresh, and path-management messages reflect a coherent activity/fault lifecycle. The targeted concern is the four-body irqbalance population and its share of server background logs.
- If this were synthetic, calibrate daemon-source proportions against a comparable collector profile for web, database, monitoring, and proxy roles. Preserve realistic repetition; do not add arbitrary extra sources simply to increase coverage.
- If this were synthetic, broaden user diagnostic activity only where the modeled role and actual visible tasks justify it; preserve the shared account's legitimate repeated routines across its two Macs.
- Preserve the existing distinctions between process lifetime, exec image, audit session, normalized logon ID, and POSIX job-control state. They are among the most convincing endpoint characteristics in the supplied data.
