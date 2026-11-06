# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 88
**Synthetic-Confidence Score:** 68

## Executive Summary

Most endpoint identities, Windows process trees, and visible session lifecycles are credible, and I found no demonstrated process-after-termination contradiction in the inspected native Windows and normalized endpoint records. The strongest authenticity problem is repeated, microsecond-exact scheduling texture in the macOS Endpoint Security records: unrelated shell commands preserve identical fractional timestamps, browser children start at exact integer offsets, and six inventory processes have exactly two-second lifetimes. Those repeated native-event timing patterns support a synthetic verdict despite otherwise strong source correlation.

## Evidence For Synthetic

- [distribution_texture] Numerous separate shell commands have exactly the same six fractional timestamp digits within command groups. In `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson`, lines 32, 35, and 38 record zsh forks at `13:48:48.715405000Z`, `13:49:18.715405000Z`, and `13:50:08.715405000Z`; their execs are respectively `/bin/pwd`, `/bin/ls -la /Users/maya.ross/Documents`, and `/usr/bin/du -sh /Users/maya.ross/Documents` (lines 33, 36, 39). This is not merely second-resolution history: the native fork times retain six meaningful fractional digits. Across both Macs, 33 of 57 zsh-parented forks belong to 14 groups sharing exact fractional microseconds.
- [distribution_texture] Every visible endpoint-inventory job has an exactly `2.000000` second fork-to-exit interval, across three runs on each of two hosts. MAC-MROSS-01 ES line pairs 28/31, 62/65, and 131/134 have fork/exit times `13:30:38.076617`/`13:30:40.076617`, `15:16:00.008749`/`15:16:02.008749`, and `17:39:08.404874`/`17:39:10.404874`. MAC-MROSS-02 pairs 31/34, 94/97, and 123/126 repeat this property. Each lifetime includes launchd, xpcproxy, and a final `/usr/bin/sw_vers` exec, rather than an explicitly logged sleep command. Exact elapsed time across all six different executions is a strong scheduling fingerprint.
- [distribution_texture] Browser startup repeats the same exact offsets on both hosts. MAC-MROSS-01 ES lines 17/20/22/24 put the launchd fork at `13:13:31.649335000Z` and renderer/GPU/network forks at exactly +2, +3, and +5 seconds. MAC-MROSS-02 lines 22/25/27/29 repeat +2, +3, +5 seconds from `13:27:10.342871000Z`. The corresponding exec records have variable subsecond delays, making the rigid fork anchors especially conspicuous. This reinforces the timing finding above; it is not counted as an unrelated lifecycle contradiction.

## Evidence For Real

- Windows process ownership is substantially convincing. On WS-PPATEL-01, Sysmon EventRecordID `739645` creates WmiPrvSE PID `5756`, parent PID `5048` running `svchost.exe -k DcomLaunch`, SYSTEM account, System integrity, and LogonId `0x3e7`; EventRecordID `739677` terminates the same ProcessGuid at `13:16:01.538`. This is a plausible provider-host lifetime and parent chain.
- Windows user-session scaffolding includes plausible `smss.exe -> winlogon.exe -> userinit.exe -> explorer.exe` relationships. On DC-01, the visible remote interactive session has winlogon at `13:41:59.130`, userinit at `13:42:01.864`, and explorer at `13:42:02.665`, with userinit and explorer sharing `aisha.johnson`, LogonId `0x53c7d14`, TerminalSessionId `5`, and the same LogonGuid.
- macOS records distinguish process lifetime from successive executable images. MAC-MROSS-01 ES lines 1–7 preserve PID `42169` through launchd/xpcproxy/Terminal and model login and zsh as separate descendants. MAC-MROSS-02 lines 1–10 use the different iTerm/iTermServer/login/ShellLauncher/zsh route, rather than copying the Terminal process tree unchanged.
- SSH evidence preserves plausible remote session identity and closure. MAC-MROSS-02 Unified Log line 2 records acceptance for `maya.ross` from `10.10.1.41:61230` at `14:24:50.491082`; ES lines 58–60 subsequently create the post-auth session descendant and zsh, and lines 73–75 close shell/session/monitor near `14:34:59`. The eCAR session uses that same source tuple (lines 108 and 155).
- Linux records contain credible service and administrative detail: DB-PROD-01 syslog lines 21–23 show a sudo journalctl command, PAM session open, then close; FILE-LNX-01 lines 21–24 distinguish Samba open/write/close and connection closure. These are source-specific sequences, not one generic endpoint event repeated under several source labels.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory. It contains 23 endpoint eCAR files totaling 34,474 records and 2,207 PROCESS/CREATE records, alongside ten Windows Security/Sysmon pairs, eleven Linux syslogs, and two macOS ES/Unified Log collections. I parsed the Windows XML and endpoint JSON, inspected representative actual records, checked native Windows process identities and account/session mappings, and examined the full macOS ES event sequences.

A bounded collection window and selective source coverage were treated as collection assumptions. I did not score missing Sysmon event families, missing pre-window processes, out-of-window exits, sanitized names, or complete cross-source matching.

### macOS native timing texture

The principal issue is event timing, not an allegation that the ES schema is invalid. On MAC-MROSS-02, ES lines 61, 64, and 67 fork three children of remote zsh PID `30083` at `14:26:53.627715`, `14:27:06.627715`, and `14:27:39.627715`. The associated execs are id, sw_vers, and find. The same phenomenon appears across other hours and on the other workstation, including MAC-MROSS-01 lines 49/52/55 at `14:37:48.314210`, `14:38:25.314210`, and `14:39:17.314210`.

There are six repeated-fraction groups containing 14 shell forks on MAC-MROSS-01, and eight groups containing 19 shell forks on MAC-MROSS-02. The total 33/57 count considers only fork notifications whose current process executable is `/bin/zsh`; it does not mistake multiple observations of one event for separate commands. Integer-second intervals can arise in scripts, but repeated six-digit phase preservation across many ordinary command groups and different hosts is substantially less plausible as independently observed kernel activity. Exec delays and command run times do vary, so this is a localized anchor-time artifact rather than globally coarse timestamp resolution.

Inventory jobs provide a separate view of the same scheduling texture. All six have precisely two seconds from fork notification to exit notification even though the xpcproxy and sw_vers transitions occur at different offsets. A fixed collection delay would not by itself impose the same exact lifetime on every process. The logs do not expose a timer or wrapper that would explain this exactness. This is strong distribution evidence, not proof that any individual two-second execution is impossible.

The identical browser +2/+3/+5 second fork pattern on the two Macs reinforces this conclusion. The later Chrome launch on MAC-MROSS-01 at `15:47:11.119666` does have noninteger helper offsets, which is a useful counterexample and limits the finding to a recurring subset of startup behavior.

### Windows process and session consistency

The Windows records show OS-sensitive file versions: workstation examples use `10.0.22621.1`, while DC-01 examples use `10.0.20348.1`. Services, WMI providers, console hosts, and desktop session initialization have sensible parent identities. Sysmon hashes have correct digest lengths: across the provided files I checked 998 SHA1, 998 MD5, 998 SHA256, and 989 IMPHASH values, with no length defect. Within a host, repeated Sysmon Event 1 records for the same executable path did not change hash values in this collection.

I compared Sysmon Event 1 users to corresponding visible Security 4624 LogonIds and found no mismatching account mappings in those comparisons. I also compared Sysmon process image paths to Security 4688 image paths for matching PIDs and found no image mismatch. These checks establish useful consistency; they do not prove authenticity or complete capture.

The session mix varies by role. DC-01 has 128 type-3, 133 type-5, and two type-10 successful logons, while WS-PPATEL-01 has six type-3, eight type-5, two type-7, and one type-2 logon. This is more plausible than assigning the same session distribution to every machine. I do not interpret absent type-5 logoffs for the fixed built-in service LUIDs as a standalone defect.

### Visible process lifecycle checks

Across endpoint eCAR records, I checked actor references against visible PROCESS/TERMINATE records and parent creation references against visible PROCESS/CREATE records. I found no actor activity more than one second after the referenced termination and no child creation more than one second before its visible parent's creation. Separately, native Windows Sysmon checks found no later same-ProcessGuid event after a visible Event 5 termination. These checks are intentionally identity-based rather than PID-only because PID reuse is legitimate.

The Mac records generally maintain fork/exec/exit identity correctly. The SSH trees distinguish launchd activation, sshd wrapper images, authentication helpers, post-auth session descendants, and shells. Removing an inventory plist is not treated as evidence that its loaded job necessarily stopped. The MAC-MROSS-01 Unified Log policy message saying policy “would not allow” MeetingAssist execution is also not treated as a demonstrated denial or an impossible child execution.

### Behavioral and environment limits

The shell activity contains repeated simple diagnostics and some cat/tee interactions with office-document paths. Such commands are possible, and the supplied collection does not establish the user's intent, redirection, file contents, or terminal state. I therefore did not elevate those observations into an independent synthetic indicator. Likewise, limited Unified Log volume, selectively absent ES events, and different source counts are neutral without a required companion or an impossible field relationship.

The verdict rests on repeated source-native timing precision artifacts, rather than attack linearity, narrative completeness, or a demand for additional products or audit facilities.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | macOS Endpoint Security fork notifications | 33 of 57 zsh-parented forks; 14 timestamp-phase groups across both Macs | Strong: unrelated external commands repeatedly share exact fractional microseconds despite otherwise fine timestamp resolution. |
| distribution_texture | macOS Endpoint Security process lifecycle | Six inventory jobs across both Macs | Strong: every fork-to-exit lifetime is exactly 2.000000 seconds through variable executable transitions. |
| distribution_texture | macOS Endpoint Security browser process creation | Initial Chrome startup on both Macs | Supporting: matching +2/+3/+5 second helper-fork offsets with identical fractional phase; correlated with the broader timing issue. |

No demonstrated hard contradiction or verified native schema defect is required for this assessment, and none is asserted here. Strong Windows/Linux consistency and plausible process ownership keep the synthetic-confidence score below the hard-contradiction band.

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed native records and inspected hashes, account fields, process identities, and platform-specific forms are largely convincing.
- **Temporal patterns:** 4 — Repeated exact microsecond phases and identical inventory lifetimes provide strong synthetic timing texture.
- **Cross-source correlation:** 9 — Process images, visible session users, SSH tuples, and process lifecycles generally agree in the checked records.
- **Behavioral realism:** 7 — Process/session behavior is credible overall, but repeated diagnostic command timing and startup schedules reduce organic realism.
- **Environmental consistency:** 8 — Host roles, OS-specific process versions, and session distributions are generally plausible; there is no demonstrated platform mixing defect.

## Recommendations

- If this were synthetic, generate independent subsecond execution anchors for each external shell command. Preserve intended burst spacing without repeating one fractional microsecond across an entire command group.
- If this were synthetic, derive inventory exit time from the modeled sw_vers execution and actual wrapper lifecycle, rather than fixing all launchd-to-exit durations at exactly two seconds.
- If this were synthetic, vary initial Chrome helper creation delays at native-event precision; preserve process ownership and reasonable ordering while avoiding the identical +2/+3/+5 second template on separate machines.
- Preserve the existing identity-based process tracking, platform-specific launch trees, hash consistency within hosts, and tuple-specific SSH session correlation while changing timing behavior.
