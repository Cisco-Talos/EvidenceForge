# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 87
**Synthetic-Confidence Score:** 71

## Executive Summary

The endpoint evidence is structurally convincing, with coherent Windows process identities and unusually careful macOS fork/exec distinctions. My synthetic verdict rests principally on repeated, precisely anchored macOS timing templates and an implausibly narrow nanosecond distribution in executable metadata, supplemented by a same-shell SSH concurrency inconsistency; I did not establish a dataset-wide impossible process lifecycle.

## Evidence For Synthetic

- [distribution_texture] Both Mac Endpoint Security streams repeatedly preserve the exact fractional second across separate command launches tens of seconds apart. For example, `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson:32,35,38` forks three commands at `13:48:59.544726000Z`, `13:49:29.544726000Z`, and `13:50:19.544726000Z`. This is repeated across other batches and both hosts, rather than being one isolated pasted command sequence.
- [distribution_texture] The Chrome startup scaffold is reproduced on both Macs: helper forks occur exactly 2, 3, and 5 seconds after the browser fork, preserving every fractional digit. See Mac 01 Endpoint Security lines 17,20,22,24 and Mac 02 lines 22,25,27,29. Six inventory launches also end exactly 2.000000 seconds after their initial fork. These are concrete duration/phase templates, not a complaint about complete evidence.
- [distribution_texture] Executable `stat` timestamps occupy an extremely narrow subsecond band: across the first observation of each unique executable path, all 112 timestamps on Mac 01 and all 120 on Mac 02 have fractional nanoseconds between 0 and 999. Examples include `/sbin/launchd` `st_mtimespec=2026-03-14T03:55:49.000000091Z` and `/usr/libexec/xpcproxy` `st_mtimespec=2026-03-24T00:18:47.000000748Z` at Mac 01 Endpoint Security lines 1–2. This combines effectively whole-second dates with tiny nonzero tails across access, modification, change, and birth timestamps and across unrelated executables.
- [contract_gap] Mac 01's one visible local shell, PID 42200 on `/dev/ttys000`, launches plain interactive SSH to WEB-EXT-01 at `16:11:03.930768Z` and plain SSH to DB-PROD-01 at `16:22:15.020695Z`, while the first SSH remains alive until `17:07:19.159075Z`. It also launches local `sw_vers` and `id` during both SSH lifetimes. Endpoint Security lines 95,100,104,107,109,112 and zsh-history lines 14–17 establish these facts. Backgrounding or suspension could explain concurrency, so I treat this as a medium-strength inconsistency rather than a demonstrated impossibility; the recorded history lacks background operators or job-control commands and the launches share the same shell, TTY, and process group.

## Evidence For Real

- Windows Sysmon process identities pass direct visible-window lifecycle checks: across all ten Windows hosts, I found no same-GUID event before its visible creation or after its visible termination, and no visible child creation before its visible parent creation or after that parent's termination. This is positive evidence of coherent host state, not evidence against authenticity because matching is complete.
- Repeated Windows executable image/version combinations retain consistent hashes within each host. Different hashes across hosts were not treated as errors because differing software versions or installations can explain them.
- The Windows population is differentiated by role: DC-01 contains thousands of authentication/filtering records, while workstations have far fewer; Aisha's workstation visibly launches management tools and RDP clients. Security includes service, network, interactive, remote-interactive and unlock logons rather than a single generic session type.
- The Mac streams distinguish a forked copy of a process image from a later exec of the same PID, with changing `pidversion`; they also distinguish Terminal's `login` path from iTerm's server/ShellLauncher path. These details are materially more realistic than independent synthetic process-create rows.
- Linux syslog contains SSH acceptance, PAM session opening, logind retirement, sudo invocations with associated PAM events, denied sudo attempts, cron and service noise. For example, APP-INT-01 syslog lines 60–61 pair SSH public-key acceptance and PAM opening for the same sshd PID 2939047.

## Detailed Analysis

### Scope and method

I inventoried only the supplied data directory, parsed all Windows Security/Sysmon XML, inspected both macOS Endpoint Security streams and their Unified Log, history and eCAR companions, and examined Linux syslog/history samples. I also checked actor ordering throughout all 23 eCAR files: a referenced actor with a visible process creation was never used before that creation, and an actor with a visible termination was never subsequently used. Those checks concern visible identities; absent pre-window processes and post-window termination are neutral.

All file references below are relative to `/private/tmp/log-study-20261105-r22/data/`. XML citations use the first line of the relevant event or a named field line; NDJSON and history citations use physical record lines. I did not use filesystem timestamps, private domains, missing Sysmon families or source completeness to infer origin.

### Windows process and session evidence

There are 864 Sysmon Event 1 records across ten Windows hosts. The parent/child mix includes service-host tasks, WMI providers, indexing workers, explorer-launched applications, and remote-session bootstrap chains. As a concrete record, `WS-AJOHNSON-01.meridianhcs.local/windows_event_sysmon.xml:57–74` describes taskhostw PID 5204 under svchost PID 4356, SYSTEM identity, logon ID `0x3e7`, and a normal System32 working directory. The matching Security process record exists with `NewProcessId=0x1454` and the same parent PID `0x1104`.

Direct GUID checks found zero impossible orderings in every Windows Sysmon file. Process hashes are stable for the same image/version within a host. These results limit how strongly I can characterize the entire endpoint corpus as defective.

Session mix also fits a mixed enterprise. DC-01 has 149 Type 3, 144 Type 5 and three Type 10 successful logons in its Security file. Aisha's workstation has Type 2, 3, 5, 7, 9 and 10 activity. The machine network logon at `DC-01.meridianhcs.local/windows_event_security.xml:6651` has account `MAIL-FIN-01$`, source `::ffff:10.10.2.27:63360`, logon ID `0x5386f6a`, followed by a same-identity Type 3 logoff at line 6911 about 24 seconds later. The presence of workstation lock/unlock evidence is credible. I did not penalize long-lived service sessions or logoffs whose initiating logon predates the slice.

### macOS timing texture

The most persuasive fingerprint is a repeated precision pattern. On Mac 01, shell command fork groups share fractional seconds `.544726`, `.509978`, `.464621`, `.396827`, `.130662`, and `.829754`, despite integer-second gaps between launches. On Mac 02, analogous groups include `.012559`, `.174069`, `.881358`, `.161049` and `.598465`. Individual exec transitions then acquire small independent delays, which makes the invariant batch anchor particularly conspicuous: the fork schedule is far more rigid than the execution delay.

One script or pasted sequence can produce regular command timing, so these groups alone are not a hard contradiction. Their repetition alongside identical Chrome helper offsets on two independently timed desktop launches materially strengthens the distribution finding. Mac 01's browser fork at `13:14:05.704405Z` produces helper forks at `13:14:07.704405Z`, `13:14:08.704405Z`, and `13:14:10.704405Z`. Mac 02 repeats precisely the same offset pattern from `13:27:08.460259Z`.

The inventory lifetime pattern is another independent anchor: Mac 01 Endpoint Security lines 28–31, 62–65 and 120–123, and Mac 02 lines 31–34, 94–97 and 125–128 each show exactly two seconds from fork to successful exit, although the intermediate exec delays vary. A managed inventory job is plausible, but six identical full lifetimes for the short `sw_vers` executable, without a visible timing wrapper in its argv, are suspicious.

### macOS file metadata

I deduplicated executable snapshots by path within each Mac and inspected four stat times per path. Mac 01 contributes 28 paths and 112 times; Mac 02 contributes 30 paths and 120 times. Every fractional component is less than 1,000 nanoseconds. The count includes exact zeros and repeated metadata, so it is not 232 independent statistical trials. Nevertheless, the same narrow distribution is present in many unrelated native and third-party executables and all four timestamp kinds, including access time.

This is an unlikely texture for unmodified filesystem metadata. Whole-second timestamp preservation during packaging can explain zero fractions, and a custom exporter or sanitization transformation could conceivably explain the tiny tails. Neither explanation is established in the records, so this is scored as distribution texture rather than an impossible native schema claim.

### macOS process/session semantics and limitations

The Terminal chain in Mac 01 Endpoint Security lines 1–7 uses launchd fork, xpcproxy exec, Terminal exec, login and zsh. Mac 02 lines 1–10 instead contain iTerm2, its server, login and ShellLauncher before zsh. Same-PID exec transitions are correctly distinguishable from separate process lifetimes. Remote sessions have their own sshd family, audit session, shell and termination sequence.

The local-shell concurrency issue is narrower. Mac 01 PID 42200 launches both SSH clients and later local commands directly; these cannot be explained as commands executing on the remote host because the recorded parent, image and local TTY remain local. The history records plain foreground commands. An unrecorded suspend/background action remains possible, especially with selected telemetry; therefore I do not call the overlap a hard contradiction. It nevertheless warrants an explicit job-control explanation if these rows are intended to describe one ordinary interactive shell.

I did not treat Mac 01's policy message at Unified Log line 2 as proof of successful execution, nor infer effects or a child process from it. Thin Unified Log coverage is neutral. I also did not allege errors in the version-11 ES schema from unfamiliar fields or demand Linux PAM/systemd records from a Mac.

### Linux evidence

The Linux examples carry credible source-local relationships and realistic variation in authentication methods and account UIDs. APP-INT-01 syslog lines 60–61 show an accepted public-key authentication at `13:43:00.702475Z` and PAM opening at `13:43:00.878347Z`, sharing PID 2939047. PROXY-01 lines 3–6 show a sudo command and PAM opening followed by a separately denied operation; this avoids falsely implying all privileged attempts succeed.

Some service-management vocabulary, such as treating client utility names as systemd service names, deserves investigation, but commands can legitimately fail and custom units are possible. I did not score those observations without an explicit contradictory success result.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | macOS Endpoint Security | Both Macs; multiple command batches and browser launches | High: exact shared fractional anchors and duplicated +2/+3/+5-second helper timing |
| distribution_texture | macOS Endpoint Security | Six inventory process lifetimes | Moderate: exactly 2.000000 seconds fork-to-exit despite variable exec delay |
| distribution_texture | macOS executable stat metadata | 58 per-host path observations, 232 timestamps | High: all fractional timestamps fall in the first microsecond of a second |
| contract_gap | macOS ES, eCAR and zsh history | Mac 01 local shell and overlapping SSH clients | Moderate: ordinary foreground history conflicts with simultaneous local-shell work; suspension/backgrounding remains a possible explanation |

## Realism Score by Category

- **Field format accuracy:** 8 — Parseable structured records and credible identities; executable stat precision has a strong artificial texture.
- **Temporal patterns:** 5 — Most lifecycle order is coherent, but repeated exact fork schedules and lifetimes are conspicuous.
- **Cross-source correlation:** 8 — No visible eCAR actor-order or Windows same-GUID lifecycle violation was found; shell intent versus concurrent execution remains unresolved.
- **Behavioral realism:** 7 — Credible enterprise role variation, service noise and authentication variety; Mac command scheduling is overly templated.
- **Environmental consistency:** 8 — Mixed Windows/Linux/Mac environment is plausible; source selection and sanitized names were kept neutral.

## Recommendations

- If this were synthetic, sample independent process-launch delays within command batches and use actual application lifecycle behavior for browser helpers, rather than invariant integer offsets with a preserved fractional anchor.
- If this were synthetic, represent inventory subprocess duration independently of the job's schedule; verify that a fixed two-second lifetime reflects an observed wrapper or real process behavior.
- If this were synthetic, derive stat timestamps from a consistent filesystem/install model with plausible precision. Preserve deliberate whole-second package timestamps where appropriate, and avoid adding tiny random nanosecond tails across unrelated timestamp kinds.
- If this were synthetic, serialize foreground commands behind the active SSH client, or explicitly model separate terminal shells, background operators and job-control transitions. Preserve the terminal, process-group and session relationships that make the chosen concurrency possible.
