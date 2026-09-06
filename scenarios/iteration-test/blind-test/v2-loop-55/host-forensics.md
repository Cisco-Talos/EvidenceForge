# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 84
**Synthetic-Confidence Score:** 74

## Executive Summary

The endpoint telemetry is technically strong: Windows process identities, hashes, parentage, lifecycles, and cross-source correlations are unusually coherent without obvious impossible ordering. However, repeated lifecycle defects and dataset-wide behavioral templates—especially long-lived `userinit.exe` processes, formulaic SSH launcher trees, and implausibly homogeneous/high-volume Snap activity—make the data likely synthetic.

## Evidence For Synthetic

- `[contract_gap]` Four visible `userinit.exe` processes remain alive for 30 minutes to 2.7 hours instead of exiting shortly after starting the user shell. On `WS-AJOHNSON-01`, instances created at `15:01:34.570Z` and `15:20:10.823Z` terminate together at `17:46:20.539Z` and `17:46:17.666Z`, strongly resembling session-end lifecycle finalization rather than real `userinit.exe` behavior.
- `[distribution_texture]` Of 23 Windows `ssh.exe` creations, all 23 have a visible `cmd.exe` or `powershell.exe` parent, and 22 are launched within 2.96–6.00 seconds of that parent. Examples include `WS-MCHEN-01` at `12:21:34.096Z` → `12:21:39.461Z` and `WS-AJOHNSON-01` at `16:19:28.975Z` → `16:19:34.975Z`. This repeated “create fresh shell, wait several seconds, launch SSH” pattern across three users is generator-like.
- `[environment_or_collection_plausibility]` Every one of the ten Linux hosts producing Snap telemetry reports both `microk8s` and `lxd`, including mail, proxy, monitoring, file, web, laptop, and workstation roles. Nine also report `snapd-desktop-integration`, including apparently headless systems such as `MAIL-CLIN-01`, `MAIL-EDGE-01`, `PROXY-01`, and `WEB-EXT-01`.
- `[distribution_texture]` Snap volume is excessive for a six-hour window: `LOG-MON-01` has 105 `snapd` messages, `WEB-EXT-01` has 92, and `FILE-LNX-01` has 79. `LOG-MON-01` alone produces 53 messages mentioning `microk8s`, `lxd`, or `snapd-desktop-integration`, with repeated refresh, hook, and task-completion messages minutes apart.
- `[weak_signal]` Four of 951 Security 4688 process creations lack a matching Sysmon Event 1 despite the other 947 matching. This is consistent with ordinary collection loss, but in such an otherwise consistent collection profile it represents a small unexplained gap rather than strong authenticity evidence.

## Evidence For Real

- Windows process correlation is excellent: 947 of 951 Security 4688 records match Sysmon Event 1 by host, PID, image, and timestamp within three seconds. Matching Sysmon events precede 4688 by approximately 0.04–0.65 seconds, a plausible source-specific recording difference.
- No visible Sysmon child process was created before its matching visible parent or after that parent terminated. Likewise, no Sysmon network, module, file, registry, process-access, or remote-thread event referenced a visibly terminated process.
- eCAR lifecycle integrity is strong. No dependent event with a visible actor process occurs before its PROCESS/CREATE or after PROCESS/TERMINATE, and no visible process termination, session logout, or file use precedes the corresponding visible creation.
- Hashes are stable for a given binary path and host. They also align across machines with the same Windows build: for example, `taskhostw.exe` version `10.0.19041.1` has the same SHA-256 on `WS-AJOHNSON-01`, `WS-DRAMIREZ-01`, `WS-EBROOKS-01`, and `WS-SMARTINEZ-01`, while build `10.0.22621.1` consistently uses a different hash.
- Process trees are generally source-native and convincing: `services.exe` launches service executables, `svchost.exe` launches `taskhostw.exe` and WMI activity, `csrss.exe` owns `conhost.exe`, and `SearchIndexer.exe` owns search protocol/filter hosts.
- Host roles affect telemetry meaningfully. Domain controllers have dense Kerberos and authentication traffic; `FILE-SRV-01` has 4656/4658/4663 and share-access events; Linux mail systems contain Postfix/Dovecot activity; and `FILE-LNX-01` contains substantial Samba auditing.
- SSH session chains are internally coherent despite their launcher texture. For example, `WS-AJOHNSON-01` records an SSH flow to `LOG-MON-01` using source port `59094`; `LOG-MON-01` records the connection from `10.10.1.35:59094`, public-key acceptance, PAM open, systemd-logind session creation, and eventual close.
- User activity is differentiated. Lina Nguyen shows development activity (`git`, editors, compilers, Docker, tests), Marcus Chen performs broad administration, and other users show narrower desktop or operational behavior. Typos such as `catt`, `la`, and `dff` add credible human messiness.

## Detailed Analysis

The logs cover approximately `2024-03-18 12:00–18:00 UTC`. I treated unpaired pre-window and post-window state as neutral and required visible identifier-level contradictions.

### Windows process evidence

Across ten Windows endpoints, there are 951 Security 4688 and 947 Sysmon Event 1 records. All 947 Sysmon process creations match a Security 4688 by PID, image, host, and near timestamp. The four unmatched 4688 records are:

- `DC-01`, `12:55:57.091Z`, PID `0xe44`, `conhost.exe`
- `DC-01`, `14:58:11.066Z`, PID `0x1100`, `dllhost.exe`
- `FILE-SRV-01`, `15:11:36.594Z`, PID `0x14c4`, `WmiPrvSE.exe`
- `WS-PPATEL-01`, `14:57:29.216Z`, PID `0x1938`, `ssh.exe`

Parent-child structure is mostly realistic, and no visible parent-lifecycle violation was found. ProcessGUIDs are unique, PID reuse does not create visible contradictions, and hashes remain stable within each host.

The conspicuous exception is `userinit.exe`. Most instances last about 3–5 seconds, but four outliers last:

- `DC-01`: `17:09:36.569Z–17:58:01.719Z` — 2,905 seconds
- `MAIL-FIN-01`: `17:06:18.208Z–17:36:59.718Z` — 1,842 seconds
- `WS-AJOHNSON-01`: `15:20:10.823Z–17:46:17.666Z` — 8,767 seconds
- `WS-AJOHNSON-01`: `15:01:34.570Z–17:46:20.539Z` — 9,886 seconds

The two `WS-AJOHNSON-01` instances overlap and terminate less than three seconds apart. This looks like `userinit.exe` was incorrectly retained until session teardown.

### Logon and session lifecycles

The data includes service, network, interactive, remote-interactive, unlock, and new-credentials logons. Visible 4624/4634 pairs never close before their matching logon. Network-session durations range from seconds to hours; long SMB or administrative sessions are possible and were not scored merely for spanning much of the window.

Workstation lock/unlock evidence is plausible. For example, `WS-EBROOKS-01` records 4800 at `13:53:11.127Z` and 4801 at `13:55:18.360Z` for Logon ID `0xa3cf38d`.

The Windows and Linux remote-session evidence usually preserves source address and port identity. The `WS-AJOHNSON-01` to `LOG-MON-01` SSH session shows consistent principal, tuple, authentication, PAM, logind, and closure state.

### User and administrative behavior

The strongest behavioral artifact is the Windows SSH process pattern. Twenty-two of 23 `ssh.exe` records follow a newly created shell by at most 6.5 seconds. This affects Aisha Johnson, Marcus Chen, and Priya Patel and spans multiple destinations. Only Marcus Chen’s `14:39:44.393Z` SSH launch reuses a shell that has been open substantially longer.

Real administrators certainly start shells before SSH, but a lived-in workstation normally shows more terminal reuse, tabs, direct launches, and variable dwell time. The near-universal fresh-shell bundle is too consistent across users.

Bash histories otherwise contain credible role distinctions and human imperfections. Lina’s workstation has an extended developer workflow, while the server histories emphasize operational inspection. Commands correlate closely with eCAR process records; shell redirections are correctly absent from child-process command lines where they would be handled by Bash.

### Linux system telemetry

RFC 5424-style messages, PIDs, SSH authentication sequences, PAM sessions, cron activity, and role daemons generally look structurally credible. The problem is environmental distribution.

All ten Snap-reporting hosts show `microk8s` and `lxd`. Nine also show `snapd-desktop-integration`. Representative examples include:

- `APP-INT-01`, `12:23:51.654Z`: `auto-refresh for microk8s`
- `MAIL-CLIN-01`, `12:26:16.430Z`: hook for `snapd-desktop-integration`
- `PROXY-01`, `12:42:36.786Z`: completed `microk8s` task
- `MAIL-EDGE-01`, `13:49:24.480Z`: refresh candidates for `snapd-desktop-integration`
- `WEB-EXT-01`, `16:01:01.737Z`: waiting for `microk8s.configure`

A standardized Ubuntu fleet can share packages, but this particular combination across nearly every role—coupled with dozens of package-specific messages per host in six hours—resembles a common noise pool applied too broadly.

### eCAR/EDR correlation

eCAR process, session, file, and flow identifiers are internally consistent. Process termination reuses the creation object ID; dependent file/network records reference active actor IDs; and observed file creation/read chains are ordered correctly.

For example, on `WS-LNGUYEN-01`, `/usr/bin/tar` creates `/tmp/mhs-support-48217.tar.gz`, and a later `/usr/bin/curl` process reads that object and connects to the proxy. On `DB-PROD-01`, the dump, gzip, checksum, SCP flow, source-file read, target SSH session, and receiver-side file creation remain temporally coherent.

This correlation is a substantial realism strength and was not treated as suspicious merely because it is complete.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `contract_gap` | Sysmon, Security, eCAR process lifecycle | Four `userinit.exe` processes on three hosts | Long-lived and synchronized termination behavior conflicts with the normal role of `userinit.exe`. |
| `distribution_texture` | Sysmon, Security, eCAR | 22 of 23 Windows SSH launches | Repeated fresh-shell-to-SSH timing forms a clear multi-user behavioral template. |
| `environment_or_collection_plausibility` | Linux syslog | Ten Linux hosts | `microk8s` and `lxd` appear on every Snap-reporting host; desktop integration appears on nine, including headless roles. |
| `distribution_texture` | Linux syslog | Repeated, fleet-wide | Snap message volumes of 79–105 records on several hosts in six hours are implausibly dense and repetitive. |
| `weak_signal` | Security/Sysmon | Four process creations | Minor unexplained 4688/Event-1 gaps in an otherwise consistent process collection profile. |

## Realism Score by Category

- **Field format accuracy:** 9 — Windows XML, Sysmon fields, RFC 5424 syslog, Bash timestamps, hashes, SIDs, LUIDs, and eCAR shapes are generally convincing.
- **Temporal patterns:** 6 — Most causality is sound, but long-lived `userinit.exe` instances and formulaic SSH launch delays are substantial artifacts.
- **Cross-source correlation:** 9 — Process, session, flow, file, and SSH identifiers agree with very few unexplained gaps and no observed impossible ordering.
- **Behavioral realism:** 6 — Role differentiation is good, but SSH launcher behavior and portions of the command texture are too repeatable.
- **Environmental consistency:** 5 — Host-specific services are present, but Snap package placement and volume are implausibly homogeneous across unrelated Linux roles.

## Recommendations

- If this were synthetic, terminate `userinit.exe` independently a few seconds after it launches the user shell. Do not tie its lifetime to explorer, winlogon, RDP, or overall session teardown.
- Diversify SSH initiation behavior. Reuse existing terminals frequently, permit direct terminal/profile launches, vary command-entry delay, and avoid creating a fresh shell for nearly every SSH session.
- Assign Snap packages according to host role. Remove `snapd-desktop-integration` from headless mail, proxy, monitoring, and external web servers unless explicitly justified; install `microk8s` and `lxd` only where workloads require them.
- Reduce Snap refresh/status volume and model stateful refresh cycles. A package should not repeatedly emit unrelated candidate checks, hook waits, and task completions throughout a short window without a coherent refresh transaction.
- Preserve the existing process identity, hash, parentage, session, file-object, and source-port correlations; these are among the strongest production-like qualities of the dataset.
