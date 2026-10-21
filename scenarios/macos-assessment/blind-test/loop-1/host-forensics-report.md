# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 93  
**Synthetic-Confidence Score:** 84

## Executive Summary

The endpoint evidence has substantial realistic detail, including coherent process identities, stable binary hashes, recognizable session chains, and varied background activity. However, repeated Windows session-placement errors, Mac process transitions timestamped before their own forks, and Linux authentication classifications that conflict across sources strongly favor synthetic data.

## Evidence For Synthetic

- **[hard_contradiction] Mac process modifications precede their visible creation.** In `NS-MAC-02.northstar.example/ecar.json`, line 392 records PID `45580`, UUID `54f5c1e1-773d-4259-8050-40ea65da994d`, executing `/usr/libexec/sshd-auth` at `15:07:59.799Z`. Line 399 places that exact process’s `operation:"fork"` at `15:08:01.165Z`, **1.366 seconds later**. Lines 395–400 and 402 show the same problem for two additional processes.
- **[contract_gap] All three Windows `/netonly` children incorrectly occupy Session 0.** In `NS-WIN-01.northstar.example/windows_event_sysmon.xml`, records `607009` → `607011`, `607388` → `607390`, and `607394` → `607395` show interactive `runas.exe /netonly` callers with `TerminalSessionId=1`, followed by their `cmd.exe` children with `TerminalSessionId=0`. New network credentials should not move these interactive children into the service session.
- **[contract_gap] Linux SSH failures become local login attempts in eCAR.** `NS-BUILD-01.northstar.example/syslog.log` line 178 records `sshd` rejecting `svc_mgmt` from `10.42.0.31:42331` at `14:27:26Z`; apparently corresponding eCAR line 225, four milliseconds later, says `session_type:"local"` and `src_ip:"-"`. The same disagreement recurs at `18:02:06Z`, syslog line 458 and eCAR line 699.
- **[distribution_texture] Independent application launches repeatedly share a subsecond phase.** Among 148 consecutive Sysmon process-creation intervals longer than one second and shorter than two minutes, **30 are within three milliseconds of an integer number of seconds**. Examples span unrelated applications and system processes. Similar patterns appear on both Macs, making ordinary task scheduling an incomplete explanation.

## Evidence For Real

- All **214 Windows Sysmon Event 1 records** have matching Security 4688 records by PID, image, command line, parent PID, and parent image. This is meaningful correlation, without treating its completeness as suspicious.
- Repeated Windows executable paths retain consistent hashes and version metadata. Checks of GUID references against visible process creations found no conflicting PID or image identities.
- Windows session startup is recognizable: `winlogon.exe` → `userinit.exe` → `explorer.exe`, followed by applications belonging to the same user and logon ID. For example, Sysmon records `606861`–`606863` establish Nora’s Session 1.
- Linux SSH sessions preserve stable user-specific public-key fingerprints across reconnects and provide authentication, PAM session opening, logind registration, and closure evidence. Syslog lines 78–80 and 142–143 provide one complete example.
- The Linux background includes credible operational variety: sysstat cron jobs, sudo/PAM sequences, resolver degradation and recovery, package maintenance, Samba activity, and IRQ-balancing messages.
- Mac Terminal → login → zsh chains are plausible. Their normalized SSH records distinguish successive executable images, credential changes, and audit-session binding rather than treating every exec as a new process.

## Detailed Analysis

### Scope and interpretation

I examined all four hosts’ eCAR files, the Windows Security and Sysmon XML, Linux syslog and shell histories, and Mac Unified Log records and zsh histories. The endpoint records cover approximately `2026-10-20 13:00–19:00Z`; all times below are UTC.

The Windows process metadata includes build `10.0.22621.1`. Linux paths and messages support a Debian-family environment. The Mac material consists principally of normalized eCAR, shell history, and a small Unified Log export. It does not establish an Endpoint Security notification schema or a specific macOS release, so I have not judged its normalized fields as native ES fields.

I did not penalize absent pre-window initiators, sessions remaining open at the boundary, selected Sysmon coverage, or the small Unified Log sample.

### Windows process identity and session ownership

The strongest Windows issue is separate from otherwise reliable process identity matching.

| Sysmon caller record | Caller PID / session | Child record | Child PID / session | New logon ID |
|---|---|---|---|---|
| `607009` | `6564` / `1` | `607011` | `6592` / `0` | `0x103b67ce` |
| `607388` | `8040` / `1` | `607390` | `8048` / `0` | `0x1049c4e6` |
| `607394` | `7976` / `1` | `607395` | `7996` / `0` | `0x1049d1ea` |

All six records are in `NS-WIN-01.northstar.example/windows_event_sysmon.xml`.

The caller command is consistently:

```text
runas.exe /netonly /user:nora.ellis-admin "cmd.exe /c dir \\NS-BUILD-01\ADMIN$"
```

The children correctly retain `NORTHSTAR\nora.ellis` as their local identity and receive new logon IDs. Security 4624 records corroborate Type 9/NewCredentials logons—for example, record `244968` at `13:34:54.6762271Z`. However, the child’s terminal session is incorrectly reset to zero. A new authentication LUID and a Windows terminal session are different identities; `/netonly` changes outbound credential use while retaining the caller’s interactive placement.

Other Windows lifecycle details are substantially better. Security records `245265` and `245274` record a lock and unlock for logon `0x10373548`, Session 1, at `14:56:28.2595600Z` and `14:58:35.4687300Z`. Type 7 logon record `245272` participates in that unlock. A different visible interactive logon, `0x1037111b`, closes with record `245534` at `16:14:37.1558857Z`; I did not confuse these concurrent sessions.

### Mac SSH process chronology

The SSH connection reaches NS-MAC-02 before authentication: eCAR line 388 records inbound TCP/22 at `15:07:57.980Z`. The initial wrapper and its successive exec images also form a sensible chain.

The subsequent fork timestamps break that chronology:

| PID | Same-process modification | Visible fork | Inversion |
|---|---|---|---|
| `45580` | Line 392: exec at `15:07:59.799Z` | Line 399: `15:08:01.165Z` | 1.366 s |
| `45591` | Line 395: privilege drop at `15:08:00.480Z` | Line 402: `15:08:01.168Z` | 0.688 s |
| `45592` | Line 396: exec to zsh at `15:08:00.505Z` | Line 400: `15:08:01.165Z` | 0.660 s |

These are exact UUID matches within `NS-MAC-02.northstar.example/ecar.json`, not associations based only on recycled PIDs. The fork rows explicitly name the initial `:exec:0` execution; the earlier modification rows advance or alter that same lifetime.

Five modification rows—392, 393, 395, 396, and 397—precede their process creations. Thus this cannot be explained by an initiating process outside the collection window.

Undocumented ingestion-time semantics could explain reordered observation timestamps. The supplied records do not expose separate occurrence and receipt timestamps, however, and the timeline as represented is internally inconsistent. This is a major contributor to the assessment, with that collection-side explanation retained as uncertainty.

### Linux authentication normalization

Two source pairs preserve the user and almost exactly the same time while disagreeing about the authentication channel:

| Time | Native syslog | eCAR |
|---|---|---|
| `14:27:26Z` | Line 178: `sshd 61962`, failed password for `svc_mgmt` from `10.42.0.31 port 42331 ssh2` | Line 225: failed local login, source `-`, timestamp `.004` |
| `18:02:06Z` | Line 458: `sshd 93324`, failed password for `svc_mgmt` from `10.42.0.31 port 60124 ssh2` | Line 699: failed local login, source `-`, timestamp `.003` |

Files are `NS-BUILD-01.northstar.example/syslog.log` and its adjacent `ecar.json`.

A connection originating from the host’s own address remains an SSH authentication attempt. It should not become a local terminal login merely because source and destination belong to the same machine. Independent coincident attempts are theoretically possible, but the repeated user/time alignment makes a normalization error considerably more likely.

Successful SSH sessions are better represented. For example, syslog lines 78–80 record Nora’s public-key acceptance, PAM opening, and logind session `272680`; eCAR line 93 identifies that session and source port `54438`. Native closure appears in syslog lines 142–143, with corresponding eCAR logout line 167.

### Timing texture and user activity

The timing concern is repeated phase preservation, rather than simply bursts of activity.

In the Windows Sysmon file, these `UtcTime` values all end in `.573`:

- Record `607268`: `wevtutil.exe`, `14:54:15.573`.
- Record `607270`: `conhost.exe`, `14:54:17.573`.
- Record `607271`: another `conhost.exe`, `14:54:25.573`.
- Record `607272`: `WMIC.exe`, `14:54:32.573`.
- Record `607275`: `sqlcmd.exe`, `14:54:45.573`.
- Record `607280`: PowerShell, `14:54:56.573`.

On NS-MAC-01, eCAR lines 201, 206, and 208 launch Terminal, Sublime Text, and Emacs at `14:08:58.200`, `14:09:19.200`, and `14:09:34.200`. Another three-application sequence at lines 350–352 retains phase `.744/.745`.

Automated application launches can produce integer-second spacing, so this is not an impossibility. Its recurrence across different applications and hosts is nevertheless a concrete distribution artifact that strengthens the verdict.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `hard_contradiction` | Mac eCAR process lifecycle | Five modifications across three SSH processes | Major: same-lifetime transitions precede explicit forks; undocumented receipt-time semantics remain an alternative |
| `contract_gap` | Windows Sysmon / Security session ownership | All three `/netonly` launches | Major: new credential contexts incorrectly become Session 0 processes |
| `contract_gap` | Linux syslog ↔ eCAR authentication | Two matching failure pairs | Moderate: SSH failures become local login attempts and lose source tuples |
| `distribution_texture` | Windows Sysmon and Mac eCAR | Repeated application bursts | Moderate: recurring integer-second offsets with millisecond phase preservation |

## Realism Score by Category

- **Field format accuracy:** 8 — XML and JSON parse cleanly; most source fields and identities are credible.
- **Temporal patterns:** 4 — Mac fork/exec inversions and recurring launch-time quantization materially weaken realism.
- **Cross-source correlation:** 7 — Windows process matching is strong, but Linux authentication classifications disagree.
- **Behavioral realism:** 7 — User tools and background operations are plausible; repeated application timing has templated texture.
- **Environmental consistency:** 7 — Platform-specific process chains are largely credible, with repeated Windows terminal-session placement errors.

## Recommendations

If this were synthetic, the most useful improvements would be:

- Preserve fork → credential transition → exec ordering for each Mac process UUID. Represent collection delay separately from occurrence time when it can reorder observations.
- Keep `/netonly` children in the caller’s terminal session while assigning their separate NewCredentials logon IDs and outbound credentials.
- Preserve SSH authentication classification and source address/port when translating failed Linux authentication into eCAR.
- Vary independent user-application launch timing below the second; retain periodic timing where a visible scheduler or service explains it.
- Preserve the existing strengths in process identity, binary hashes, parent relationships, and successful Linux SSH session correlation.
