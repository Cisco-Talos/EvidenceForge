# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 76
**Synthetic-Confidence Score:** 62

## Executive Summary

The endpoint evidence is generally convincing, with coherent Windows process identities and realistic macOS fork/exec transitions. I lean synthetic because Linux console logins repeatedly use a questionable persistent-getty process model, together with a systematic split between native console-session opening and closing evidence. These are bounded concerns, not proof that the broader dataset is impossible; the strongest Windows and macOS checks passed.

## Evidence For Synthetic

- [contract_gap] **Linux getty/login identity model:** Ten `/bin/login` creation records across six Linux hosts identify `/sbin/agetty` as a separate parent process. On `APP-INT-01.meridianhcs.local/ecar.json`, PID `36047`, actor UUID `6189a838-5ba3-4d32-879a-ecf53d99a742`, parents login PID `3374484` at `2026-11-02T13:02:20.742Z` and login PID `3376990` at `13:09:15.034Z`. Ordinary `agetty` hands control to login by exec, preserving the PID, rather than remaining a reusable parent that launches independent login processes. Reuse of the exact parent identity makes this more concerning than merely observing an ancestor name. This finding assumes the reported direct PPID/image fields represent the ordinary named programs, rather than undocumented custom wrappers or ancestor rewriting.
- [contract_gap] **Console close evidence changes by account class:** Linux syslog contains 18 `pam_unix(login:session)` opening messages, comprising eight root and ten named-user openings. Its five console-session closing messages are all for root. Five of the named-user login processes have visible eCAR terminations inside the window, yet none has a matching native login/PAM close. For example, APP-INT login PID `3376990` opens Aisha's session at `13:09:16.845613Z`, terminates in eCAR at `16:25:30.742Z`, and has eCAR local session `181` logout at `16:25:33.797Z`, without a corresponding native close or `Removed session 181` line. This is a limited-weight lifecycle/collection concern, not an assertion that every process exit must produce PAM cleanup: filtering or abrupt termination could explain individual cases.

## Evidence For Real

- Windows source-native process relationships remain coherent under systematic checks. Across all ten Sysmon XML files, visible process GUIDs did not change image names, dependent records did not precede their matching creation `UtcTime`, and references to visible parents/source/target processes did not occur after their visible termination `UtcTime`.
- Sysmon hashes have correct algorithm lengths. Within each host, repeated Event 1 creations at a given image path retained consistent hash strings. I did not find a same-host, same-path hash drift that required an unseen update explanation.
- The Windows logs contain differentiated activity rather than one universal process tree: Marcus's workstation has SSH, MMC, RDP, Postman and administrative shells; Sophia's has Outlook, conferencing and storage/sync applications. Domain controllers have substantially more authentication and network evidence than the workstations.
- The macOS records distinguish a process lifetime from executable changes. On MAC-MROSS-01, PID `25527` transitions from launchd's fork image to `xpcproxy` and then Terminal, while retaining a start time and changing execution identity. MAC-MROSS-02 has a different iTerm2/iTermServer/login/ShellLauncher chain. These are meaningful platform-specific distinctions.
- SSH examples include connection, accepted authentication, PAM session opening, logind registration and later closing evidence, with differing public-key/password outcomes and session lengths. For APP-INT's Aisha connection from `10.10.1.35:54705`, the native sequence starts at `13:59:51.858219Z` and closes at `14:21:48.262233Z`.
- Linux account UIDs are stable across the examined PAM messages, including `lina.nguyen=5302`, `aisha.johnson=2528`, `marcus.chen=4119`, `priya.patel=3843` and `maya.ross=2176`.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory. The endpoint portion contains 23 host directories with eCAR records, ten hosts with Windows Security/Sysmon XML, eleven with Linux syslog, and two with macOS Endpoint Security and Unified Log exports. The endpoint slice lies on November 2, approximately 13:00–19:00 UTC. There are 37,971 eCAR records, including 2,718 PROCESS/CREATE, 2,568 PROCESS/TERMINATE and 154 PROCESS/MODIFY records.

I parsed the endpoint files, inspected actual records, checked GUID/object references and visible lifecycle ordering, compared native and normalized examples, and inspected shell histories. Missing initiators at the start of the slice and surviving state at the end were not counted against authenticity. I did not use domain names, filesystem copy timestamps, intrusion narrative shape, missing Sysmon types or completeness of correlation as synthetic indicators.

### Windows processes, identities and logons

The Windows representation is substantially stronger than the two Linux concerns. An example from `WS-MCHEN-01.meridianhcs.local/windows_event_sysmon.xml` is AdobeARMservice PID `6852`, GUID `{7b2a0e3f-8b5c-6ae8-b100-0000d578c07b}`, created at `UtcTime=2026-11-02 13:08:44.049`. Its parent is services.exe PID `5872`, its token is `NT AUTHORITY\SYSTEM`, LogonId is `0x3e7`, and integrity is System. Security 4688 at `13:08:44.2162094Z` reports hexadecimal NewProcessId `0x1ac4`, the same image and parent. eCAR reports PID `6852`, PPID `5872`, SYSTEM and the same image at `13:08:44.196Z`. The subsecond timestamp differences are plausible source timing, not a contradiction.

The source-native XML uses appropriate provider/channel distinctions, hexadecimal Security process identifiers and decimal Sysmon identifiers. No invalid MD5/SHA1/SHA256/IMPHASH lengths appeared in the examined hash fields. The systematic Sysmon checks found no conflicts between a GUID's visible creation image and later image-bearing events, and no visible target/source/parent references after a matching termination.

Logon evidence includes service, network, local interactive, remote interactive, unlock and new-credentials types. Marcus's workstation has types 2, 3, 5, 7 and 9; domain controllers have predominantly network/service activity plus a small number of RDP logons. MAIL-FIN has an Aisha RDP session `0xd73e919` from `10.10.1.35:61215`, opening at `14:00:11.8152429Z` and closing at `14:38:05.1466698Z`. Matched visible 4624/4634 records retained username and logon type and closed after opening. I did not interpret repeated well-known service LogonIds as independent ordinary user-session identities.

### Linux console model and lifecycle coverage

The direct-parent issue is repeated rather than isolated. APP-INT, DB-PROD, FILE-LNX, MAIL-CLIN, MAIL-EDGE and PROXY collectively contain ten `/sbin/agetty`-parented `/bin/login` creations. DB-PROD reuses parent PID `29350`, UUID `03c8eda6-52ea-486a-8522-7b1cd9328639`, for maya.ross login PID `1366445` at `13:01:18.028Z` and marcus.chen login PID `1373719` at `13:56:52.880Z`. Native syslog corroborates the distinct login PIDs with PAM openings at `13:01:20.849002Z` and `13:56:55.903876Z`.

A normalized product can represent exec as a new process observation, but that does not normally require changing the OS PID or preserving the exec predecessor as the direct parent. An undocumented normalization rule could account for this; without such a rule, the repeated model is more consistent with an incomplete representation of Linux console execution semantics.

The closing asymmetry is related but distinct. Of the ten named-user console login processes, five visibly terminate inside the slice. Besides APP-INT's Aisha process, DB-PROD's maya.ross login ends at `14:29:57.826Z`, DB-PROD's marcus.chen login at `15:30:10.314Z`, FILE-LNX's priya.patel login at `15:53:56.150Z`, and MAIL-EDGE's aisha.johnson login at `16:27:47.725Z`. None has a corresponding `login PID ... session closed` message. Root console openings and closes are both represented, and SSH and sudo closes are also represented. This is why I consider the asymmetry worth reporting rather than simply demanding an absent source.

The evidence does not establish graceful exits, audit completeness or the absence of a user-based collection filter. I therefore give the closing asymmetry less weight than the process-identity model and do not label either a demonstrated source-format impossibility.

### Linux SSH and background activity

The native SSH examples have usable process/session identities and credible ordering. APP-INT's Aisha public-key session uses sshd PID `3394691`, a stable RSA fingerprint, logind session `187`, PAM open at `13:59:52.807326Z` and later PAM close at `14:21:48.262233Z`. Other activity includes password authentication, failed preauthentication and a brief root transfer session. The failed `svc_mgmt` attempt shows failure and preauth closure without evidence of an authenticated shell.

Sysstat recurs 36 times in the six-hour slice on several Debian-like hosts. That count is consistent with a ten-minute scheduled task and is not itself synthetic evidence. Paired cron shell and debian-sa1 process lifetimes vary around their short expected runtime. The shell histories contain role-relevant work and ordinary checks; I did not score the presence of typos or suspicious commands as proving either origin.

### macOS execution, sessions and policy

The two Endpoint Security exports contain 147 and 177 records respectively and declare message version 11. They include fork, exec and exit observations. I evaluated their process roles and internally visible transitions without asserting unfamiliar version-specific schema details as defects.

MAC-MROSS-01 PID `25527` forks at `13:07:32.811343Z`, execs xpcproxy at `13:07:32.820534Z`, then Terminal at `13:07:32.835499Z`; its login and zsh descendants follow. MAC-MROSS-02 instead launches iTerm2, a versioned iTermServer, login, ShellLauncher and zsh. Native process PID-version/executable/start-time identities and executable device/inode/size/mode combinations did not conflict in my checks. Local terminal and remote SSH trees are visibly different.

MAC-MROSS-01's `15:42:09.009673Z` kernel message says policy would not allow MeetingAssist PID `42008`. I did not infer a successfully created MeetingAssist child or its effects from that message. Similarly, Unified Log's SSH acceptance messages were treated as authentication observations, not as Linux PAM events or complete session transcripts. The small Unified Log export was not penalized merely for being small.

### Weight of evidence

The Windows and macOS evidence counters a high synthetic-confidence score. The score of 62 reflects a likely synthetic Linux console model with a related lifecycle coverage asymmetry, not a dataset-wide claim of impossible time ordering or broken hashes. A documented ancestor-remapping convention and a demonstrated account-based syslog filter would materially weaken the conclusion.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| contract_gap | Linux eCAR with syslog PID corroboration | Ten named-user console login creations on six hosts; exact getty parent identities reused on multiple hosts | Main reason to lean synthetic: separately allocated login PIDs and reusable getty parents conflict with ordinary exec-in-place behavior. Custom software/normalization remains an alternative. |
| contract_gap | Linux console PAM/logind versus eCAR | Ten named-user native openings, no named-user native closes; five corresponding login processes visibly terminate; root native closes exist | Modest additional weight: account-class lifecycle asymmetry within the visible collection. Filtering or abrupt exits prevent treating it as conclusive. |

## Realism Score by Category

- **Field format accuracy:** 9 — Parseable native sources, valid hash widths, coherent identifiers and no demonstrated macOS version-specific format defect.
- **Temporal patterns:** 9 — Checked visible process references respect lifetimes; activity and short-lived task timing vary plausibly.
- **Cross-source correlation:** 8 — Strong Windows and SSH alignment, with a bounded Linux console closing asymmetry.
- **Behavioral realism:** 7 — Role-specific tool use and good macOS execution detail, reduced by the repeated getty/login process model.
- **Environmental consistency:** 8 — Platform-specific sources and stable identities are convincing; console lifecycle behavior needs explanation.

## Recommendations

- If this were synthetic, represent ordinary Linux getty-to-login handoff as an executable transition retaining the OS PID and correct parent identity. If a wrapper or observer intentionally rewrites ancestry, expose that fact instead of presenting the reusable object as the direct `/sbin/agetty` parent.
- If this were synthetic, carry the same console-session lifecycle through eCAR and native PAM/logind evidence when a normal close occurs. For the five visible named-user login terminations, model whether each exit is graceful, abrupt or selectively uncollected, rather than consistently retaining openings while only root console closes appear.
