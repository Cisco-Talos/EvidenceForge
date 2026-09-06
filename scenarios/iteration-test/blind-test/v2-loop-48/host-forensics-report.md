# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 84
**Synthetic-Confidence Score:** 69

## Executive Summary

The endpoint telemetry is unusually strong in its routine Security/Sysmon/eCAR correlation, host-specific process mix, stable hashes, and Linux SSH/PAM sequencing. However, four visible RDP session chains contain source-native parent contradictions and implausibly session-long `userinit.exe` processes, while the exposed Linux host's UFW records show a repeated per-source TCP-window randomization fingerprint; together these concrete defects make the data more likely synthetic than real.

## Evidence For Synthetic

- [hard_contradiction] Four RDP-created `userinit.exe` records have a `ParentProcessGuid` that resolves to a visible `winlogon.exe` Event 1, yet the same child record renders `ParentImage=-` and assigns `ParentUser` to the interactive user rather than the parent process's visible `NT AUTHORITY\SYSTEM`. Examples are FILE-SRV-01 at `2024-03-18T17:06:19.5798457Z` (child PID 6120, parent PID 6116), DC-01 at `17:09:56.9420099Z` (5656/5652), and WS-AJOHNSON-01 at `15:00:29.7008245Z` (5980/5976) and `15:20:34.9095282Z` (6024/6008). Their immediately following `explorer.exe` records repeat the impossible blank parent image despite referencing those visible `userinit.exe` GUIDs.
- [contract_gap] The same four RDP `userinit.exe` processes remain alive for 2,948.624, 2,986.166, 8,045.324, and 9,263.337 seconds. In the same dataset, ten ordinary interactive `userinit.exe` instances exit in 2.938-5.195 seconds. The remote-session instances are terminated near session teardown as though `userinit.exe` were the durable shell, which conflicts with its normal role as a short-lived logon initializer.
- [schema_or_format] All four visible successful Type 10 Security 4624 records render both `TargetUserSid` and `LogonGuid` as empty XML values even though the username, domain, and target Logon ID are populated and those users' SIDs are present elsewhere. The affected events are DC-01 at `17:09:56.8851662Z`, WS-AJOHNSON-01 at `15:00:29.5947752Z` and `15:20:34.8148036Z`, and FILE-SRV-01 at `17:06:19.5077017Z`.
- [distribution_texture] WEB-EXT-01's 841 UFW-block records are dominated by eight repeatedly reused source IPs. For each source, packet length and TTL remain fixed while the TCP initial window is distributed almost evenly among exactly `1024`, `14600`, and `65535`: for example, `145.78.103.167` has 151 records split 54/49/48, `38.186.148.245` has 139 split 50/47/42, and `74.172.69.175` has 92 split 31/30/31. A stable apparent scanner identity repeatedly and near-uniformly switching among three unrelated OS-style SYN windows is a generator-like field-selection pattern.

## Evidence For Real

- Across all 19 eCAR files, records are timestamp-sorted and no object with both a visible start and end has an end before its start. No dependent eCAR event references a process actor whose visible creation occurs later.
- Windows process evidence correlates closely: 926 Security 4688 records match Sysmon Event 1 on host, PID, image, command line, and parent path; only four Security records lack a Sysmon partner. For matched pairs, Sysmon precedes Security by a variable 0.035-0.650 seconds, consistent with distinct local provider/collection timing.
- Process hashes remain stable for each image within a host, while common Windows binaries separate into plausible OS-build groups across hosts. For example, `WmiPrvSE.exe`, `conhost.exe`, `taskhostw.exe`, and `svchost.exe` each have four cross-host hash variants rather than per-event random hashes.
- Process trees contain credible host-specific software and parentage: workstation logon chains normally run `winlogon.exe -> userinit.exe -> explorer.exe`; service activity includes `services.exe` children, IIS/Exchange workers, search hosts, update clients, browsers, office software, and endpoint-management utilities. Core checks found no `lsass.exe`, `services.exe`, or `svchost.exe` instance with an obviously impossible parent.
- Linux SSH evidence is source-native and temporally coherent. On PROXY-01, source `10.10.1.31:56510` connects at `12:38:59.991148Z`, authenticates by public key at `12:39:09.363888Z`, opens PAM at `12:39:09.418650Z`, and closes at `13:13:48.855557Z`; eCAR independently preserves the same tuple, sshd PID 594588, user, child shell, and session identity in compatible order.
- Bash histories show differentiated activity rather than a single copied script: developer-oriented Git, test, Docker, and package commands cluster with Lina Nguyen; database inspection and backup commands occur on DB-PROD-01; mail, proxy, and system-administration commands are host appropriate. Of 263 visible commands, 216 are unique, and no pair of histories shares more than three distinct commands.

## Detailed Analysis

### Scope and window handling

I examined only host-facing generated data in the supplied directory: 19 eCAR streams, ten Windows Security/Sysmon pairs, eleven Linux syslog streams, and 22 bash histories spanning approximately `2024-03-18T12:00Z` through `18:00Z`. I treated unmatched starts or ends at either boundary and source-local omissions as neutral; the findings above rely on visible same-identity contradictions or repeated field distributions, not lifecycle completeness.

### Windows process trees and RDP sessions

Ordinary console logons are convincing. WS-PPATEL-01, for example, records `winlogon.exe` at `12:20:57.0299540Z`, `userinit.exe` at `12:20:58.9737946Z`, and `explorer.exe` at `12:20:59.2821209Z`; `userinit.exe` exits 5.092 seconds after creation. Comparable local chains on WS-DRAMIREZ-01, WS-AJOHNSON-01, WS-SMARTINEZ-01, and WS-EBROOKS-01 show the same technically credible sequence with 2.938-5.195-second initializer lifetimes.

The four RDP chains diverge in a way that collection delay cannot explain. FILE-SRV-01's Sysmon stream visibly creates `winlogon.exe` PID 6116 with GUID `{1b54004d-748b-65f8-5002-00002ac79ff7}` at `17:06:19.380Z`. About 200 ms later, PID 6120 `userinit.exe` names that exact GUID and PID as its parent but reports `ParentImage=-` and `ParentUser=MERIDIANHCS\aisha.johnson`; the parent Event 1 says `Image=C:\Windows\System32\winlogon.exe` and `User=NT AUTHORITY\SYSTEM`. eCAR simultaneously retains the correct `winlogon.exe` parent image and SYSTEM source principal, proving that the contradiction is in the visible source representation rather than absent upstream activity. The same defect recurs in the three other Type 10 chains and propagates to their `explorer.exe` children.

These chains also make `userinit.exe` live for nearly the whole remote session. FILE-SRV-01's PID 6120 runs from `17:06:19.5798457Z` to `17:55:28.2043210Z`; DC-01's PID 5656 runs from `17:09:56.9420099Z` to `17:59:43.1082733Z`; WS-AJOHNSON-01's PIDs 5980 and 6024 run 2 hours 14 minutes and 2 hours 34 minutes. The tight contrast with every visible normal interactive initializer indicates a repeated remote-session lifecycle modeling defect, not random endpoint variation.

The associated 4624 records are otherwise well formed enough to make their empty identity fields conspicuous. Each has Type 10, `User32`, `Negotiate`, a workstation, IPv4-mapped source address, source port, and target Logon ID, but both `TargetUserSid` and `LogonGuid` are zero-length values. This is repeated specifically across all four visible RDP successes.

### Security, Sysmon, and eCAR correlation

Outside the RDP defect family, process correlation is strong. Security 4688 and Sysmon Event 1 agree on PID, image basename, command line, and parent path in all 926 matched pairs across ten Windows hosts. Sysmon Event 5 and Security 4689 generally preserve the process identity through termination, and eCAR keeps stable object IDs between create and terminate. The four Security-only process creations are sparse enough to fit the stated source-local missingness.

ProcessGUID values remain stable across Event 1 and Event 5, and hashes are stable per image within each host. Shared hash variants line up in host groups rather than changing per process instance. The process inventory is also appropriately heterogeneous: domain controllers emphasize `WmiPrvSE.exe`, `taskhostw.exe`, `dllhost.exe`, DFSR, and directory services; MAIL-FIN-01 includes IIS and Exchange workers; workstations include office, browser, conferencing, VPN, search, update, and user-profile software.

Logon IDs show no visible logoff-before-logon contradiction. The mix includes network Type 3 and service Type 5 activity on servers, interactive Type 2, RDP Type 10, unlock Type 7, and new-credentials Type 9 on suitable workstations. I did not count sessions lacking one boundary as defects because the dataset is a six-hour slice.

### Linux endpoint evidence

The Linux records preserve credible RFC 5424-style timestamps, facilities, persistent daemon PIDs, PAM open/close pairs, cron identities, and role-specific services. SSH sessions show connection, authentication, PAM open, shell activity, and close in plausible order; failed sessions include invalid-user or bad-password evidence followed by pre-auth close. GUI workstations show GDM sessions, NetworkManager, DHCP, desktop services, and user-specific bash activity, while servers show postfix/dovecot, web, proxy, database, multipath, rsyslog, or monitoring behavior.

The UFW stream on WEB-EXT-01 is the notable exception. Repeated internet scan noise is plausible, as are stable source TTL and packet length. What is not convincing is that each of eight high-frequency source identities independently selects one of the same three TCP windows in near-equal proportions while every other fingerprint field remains fixed. That repeated conditional distribution is materially more consistent with independent random choice from a small pool than packets emitted by stable scanner stacks.

### User behavior and timing texture

Human and administrative activity has useful variation in command content, session duration, and work cadence. Bash-history overlap is low, service-management commands fit host roles, and Windows application launches differ by user and workstation. Periodic sysstat cron events retain host-specific minute offsets and millisecond jitter; I did not score their regularity because such periodicity is native to cron and the visible omissions are consistent with the stated collection model.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `hard_contradiction` | Sysmon Event 1 / eCAR RDP process trees | Eight child records across four RDP chains on three hosts | Exact visible parent GUIDs resolve to records whose image and principal contradict the child record's parent fields; this is the strongest authenticity failure. |
| `contract_gap` | Sysmon Event 1/5, Security 4688/4689, eCAR process lifecycle | Four `userinit.exe` instances | Remote initializers persist 49 minutes to 2.57 hours and terminate near session teardown, unlike all ten normal 2.9-5.2-second instances. |
| `schema_or_format` | Windows Security 4624 | All four visible Type 10 successes | Known successful users have empty `TargetUserSid` and `LogonGuid` values in an otherwise populated event. |
| `distribution_texture` | Linux kernel/UFW syslog | 840 of 841 blocks across eight reused scanner IPs | Each stable source nearly uniformly rotates among the identical three TCP window values while TTL and packet length stay fixed. |

## Realism Score by Category

- **Field format accuracy:** 7 — Most Windows, eCAR, and Linux values are source appropriate, but blank Type 10 identity fields and contradictory Sysmon parent fields are material defects.
- **Temporal patterns:** 7 — Routine timing and SSH/PAM sequences are varied and coherent, but four RDP `userinit.exe` lifetimes repeatedly follow the wrong lifecycle.
- **Cross-source correlation:** 8 — Process, session, tuple, command, and hash correlation is generally excellent; the RDP parent representation is the important exception.
- **Behavioral realism:** 8 — Host roles, process inventories, user commands, and session behavior are diverse and credible outside the isolated RDP lifecycle family.
- **Environmental consistency:** 7 — The source mix and host specialization are plausible, but WEB-EXT-01's low-diversity scanner population and conditional TCP-window distribution look generated.

## Recommendations

- If this were synthetic, make RDP process construction obey normal Windows logon semantics: render the already visible `winlogon.exe` as the `userinit.exe` parent with SYSTEM as `ParentUser`, render `userinit.exe` as the `explorer.exe` parent, and terminate `userinit.exe` within seconds rather than at session teardown.
- If this were synthetic, populate successful Type 10 4624 `TargetUserSid` from the same canonical user identity used elsewhere and emit the source-native unavailable LogonGuid representation rather than an empty value.
- If this were synthetic, model UFW scanner fingerprints per source or scanner family. Keep TCP window coherent with the apparent stack and introduce a realistic long tail of source identities instead of independently drawing each packet from the same three-value window pool.
