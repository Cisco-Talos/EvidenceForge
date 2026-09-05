# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 94
**Synthetic-Confidence Score:** 84

## Executive Summary

The dataset has unusually strong source-native detail and mostly coherent lifecycle correlation, but two concrete endpoint defects materially break the illusion of production telemetry. Five Windows workstations repeat a user-shell chain in which `services.exe` creates `explorer.exe`, and one of those hosts simultaneously records the normal `winlogon.exe` → `userinit.exe` → `explorer.exe` chain for the same logon; separately, APP-INT-01 records a Java-owned eCAR connection after that exact process identity has terminated.

## Evidence For Synthetic

- [hard_contradiction] On WS-DRAMIREZ-01, Sysmon Event 1 records two competing shell roots for the same interactive logon `0x9753671`: EventRecordID 319978 at `2024-03-18T12:06:56.1205637Z` has PID 6624 `explorer.exe` parented by PID 5752 `services.exe`, while EventRecordIDs 319979-319980 at `12:06:56.3103700Z` and `12:06:56.5532635Z` show the normal PID 6296 `winlogon.exe` → PID 6324 `userinit.exe` → PID 6332 `explorer.exe` chain. PID 6624 then launches Outlook (EventRecordID 319981), so it is not merely a stale process-table annotation.
- [distribution_texture] The same `services.exe` → domain-user `explorer.exe` construction recurs once each on five unrelated workstations: WS-AJOHNSON-01 at `14:23:53.3487267Z` (Sysmon EventRecordID 30823), WS-DRAMIREZ-01 at `12:06:56.1205637Z` (319978), WS-MCHEN-01 at `15:03:10.5253868Z` (525433), WS-PPATEL-01 at `14:06:08.2064796Z` (739927), and WS-SMARTINEZ-01 at `12:15:33.2463356Z` (121125). Security 4688 independently preserves each same anomalous parent-child relation, making this a repeated construction pattern rather than an eCAR-only translation issue.
- [hard_contradiction] APP-INT-01 eCAR line 363 terminates process object `8fa86dfb-38ff-4a8a-bc5e-9b397ed3d1f3`, PID 1927829 `/usr/bin/java`, at `1710777712247` ms. Line 365 then records that identical object as `actorID`, with the same PID, principal, image, and command line, opening a TCP/80 flow to `10.10.1.10` at `1710777716022` ms—3.775 seconds after termination.
- [distribution_texture] Windows application-start telemetry frequently appears as compact, repeated micro-bundles: a process create followed within milliseconds by a small, familiar subset of core DLL loads. For example, WS-AJOHNSON-01 eCAR lines 384-390 start PowerShell and emit `ntdll.dll`, `kernel32.dll`, `kernelbase.dll`, `ucrtbase.dll`, `advapi32.dll`, and `rpcrt4.dll` in 126 ms. The exact short-list texture recurs across unrelated application launches and hosts, which resembles a curated module vocabulary more than the irregular module-load footprint of lived-in endpoints.

## Evidence For Real

- Security 4688 and Sysmon Event 1 process records correlate exceptionally well on PID, image, command line, parent, and logon identity. Across the ten Windows hosts, 1,163 of 1,171 visible Security process creations matched a Sysmon creation within two seconds, with Sysmon preceding Security by plausible subsecond delays and no matched image or command-line disagreement.
- Sysmon Event 5 process termination is internally coherent: 768 visible create/terminate pairs had no termination-before-create ordering, and durations ranged from roughly 3 seconds to more than 5.6 hours. Short-lived `conhost.exe`, `userinit.exe`, and command processes coexist with long-lived explorer, VPN, browser, and Office processes.
- User and role differentiation is convincing. Workstations show distinct application mixes—Postman/Chrome/SSH for priya.patel, Outlook/Slack for diego.ramirez, PowerShell/SSH/Firefox for aisha.johnson, and browser/data tooling for Linux users—while servers show role-specific mail, database, Samba, monitoring, proxy, and web processes.
- Linux authentication evidence has realistic sequencing and source-native texture. Accepted SSH authentication precedes PAM session open, sessions overlap naturally, and PAM close records retain the same daemon PID and user; examples include DB-PROD-01 PIDs 847782 and 848417 and FILE-LNX-01 PIDs 1921991, 1924151, 1927990, and 1931731.
- Routine endpoint noise is varied and operationally plausible: Windows Search hosts, WMI providers, update workers, service processes, scheduled utilities, lock/unlock activity, failed logons, and Linux cron, package, systemd, rsyslog, Samba, sudo, and local/SSH session evidence are all represented.
- File hashes are stable for repeated executions of the same binary within an apparent OS-build cohort, while several Windows build cohorts legitimately produce different hashes for the same system image across host groups.

## Detailed Analysis

### Scope and source mix

The visible collection spans approximately `2024-03-18T12:00Z` through `18:00Z`. I examined endpoint evidence for ten Windows systems with Security XML, Sysmon XML, and eCAR; eleven Linux systems with syslog and eCAR; and 24 user bash-history files. I treated unmatched starts or ends at the collection boundaries as neutral and did not penalize the deliberately selected Sysmon event-family mix.

Windows Security volume is dominated by 5156 network permits on workstations and by 5156 plus Kerberos 4768/4769 activity on the domain controllers. Sysmon includes process creation/termination, DNS, network, process access, image load, registry, file, and remote-thread records. Linux syslog includes RFC 5424-style SSH/PAM, sudo, cron, systemd, package maintenance, mail, web, Samba, and general daemon messages.

### Windows process trees

The ordinary interactive bootstrap is accurately represented when used: `smss.exe` creates `winlogon.exe`, `winlogon.exe` creates `userinit.exe`, and `userinit.exe` creates `explorer.exe`, with the user's logon ID propagated into Sysmon, Security, and eCAR. WS-DRAMIREZ-01 demonstrates this at Sysmon EventRecordIDs 319977, 319979, and 319980. Browser and Electron child trees also include plausible renderer/network utility children, and system services generally descend from `services.exe` while console hosts descend from `csrss.exe`.

That strength makes the parallel WS-DRAMIREZ-01 shell more conspicuous. At `12:06:56.1205637Z`, PID 6624 `explorer.exe` is attributed to domain user diego.ramirez and logon `0x9753671`, but its parent is PID 5752 `services.exe`. Less than half a second later, the canonical chain creates a second explorer, PID 6332, under `userinit.exe` for that same logon. The anomalous PID 6624—not the canonical shell—then creates Outlook at `12:06:57.4364928Z`. This is an internally visible competing ownership model, not a missing-pre-window-parent issue.

The same service-parent shell primitive appears on four additional workstations and is followed by user applications or shells, including PowerShell on WS-AJOHNSON-01, WS-MCHEN-01, and WS-SMARTINEZ-01 and cmd.exe on WS-PPATEL-01. The Security and Sysmon records agree on the anomalous relationship: for example, WS-AJOHNSON-01 Sysmon EventRecordID 30823 records PID 5872 with parent PID 4284, while Security EventRecordID 130429 records `NewProcessId=0x16f0`, `ProcessId=0x10bc`, and `ParentProcessName=C:\Windows\System32\services.exe`. Cross-source agreement therefore confirms the bad canonical relationship rather than excusing it.

### Process lifecycle and eCAR ownership

Most lifecycle handling is strong. Sysmon yielded 768 visible create/terminate pairs with no negative durations. Security 4688 and Sysmon Event 1 matched on content with realistic observation offsets: host-average Sysmon lead ranged from about 159 to 208 ms, with observed extremes around 35 to 642 ms. eCAR process termination reused the correct process object, PID, and image for matched processes.

The APP-INT-01 Java health-check sequence violates that otherwise consistent ownership. eCAR line 359 creates PID 1927829 at `1710777709200`; line 362 records its LDAP/TCP 636 flow at `1710777711188`; line 363 terminates it at `1710777712247`; and line 365 reuses the terminated process object to create a TCP/80 flow at `1710777716022`. Because the visible create, terminate, and dependent flow all use the same durable process object, the post-termination activity cannot be explained by a pre-window process or PID reuse.

### Logon and session lifecycle

Windows logon types include interactive (2), network (3), service (5), unlock (7), new credentials (9), and remote interactive (10). Network sessions are generally short, while interactive sessions last from tens of minutes to several hours. Unlock records reuse the original authentication ID, and final 4634 events retain the original interactive type, which is consistent with Windows behavior rather than a mismatch.

Linux SSH sequences are particularly credible. DB-PROD-01 records accepted-password and PAM-open pairs for lina.nguyen at `13:33:06Z` and `13:39:49Z`, with overlapping closes at `14:19:39Z` and `14:01:08Z`; this avoids an overly serialized session model. FILE-LNX-01 similarly has overlapping sessions for priya.patel, marcus.chen, and aisha.johnson. Sudo records preserve user IDs, TTYs, working directories, exact commands, and short but variable PAM session durations.

### User behavior and system background

The behavioral layer is substantially more realistic than a simple attack-only corpus. User applications differ by host and role, server commands are service-appropriate, and routine activity is mixed with administrative and suspicious operations. Linux history has timestamped commands with both repetition and host specialization: database queries on DB-PROD-01, development commands on WS-LNGUYEN-01, and service/network diagnostics on infrastructure hosts.

The main residual texture is the compactness of module-load bundles. eCAR repeatedly records only a small core set in near-identical order immediately after process creation. Filtering could explain sparse module coverage, so this is not a standalone contradiction, but the repeated cross-host vocabulary and millisecond cadence modestly increase synthetic likelihood.

### Cross-source correlation

The high correlation itself was not treated as a synthetic indicator. Security/Sysmon process tuples, eCAR process identities, Windows logon IDs, SSH source tuples, and Linux PAM lifecycles usually align. The two scored issues are narrower: one repeated source-semantic contradiction in Windows parentage and one impossible visible eCAR process/flow ordering.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the synthetic-confidence score |
|---|---|---|---|
| `hard_contradiction` | Sysmon, Security, eCAR | Repeated on five Windows workstations; explicit duplicate shell on WS-DRAMIREZ-01 | A service-owned user shell competes with the canonical interactive shell for the same visible logon, and the anomalous shell launches user applications. |
| `hard_contradiction` | eCAR | One APP-INT-01 process identity | A TCP flow is owned by the exact Java process object 3.775 seconds after its visible termination. |
| `distribution_texture` | eCAR module telemetry | Repeated across Windows applications and hosts | Small, nearly fixed core-DLL bundles recur in tight post-create bursts with limited long-tail variation. |

## Realism Score by Category

- **Field format accuracy:** 9 — Windows XML, Sysmon fields, eCAR records, RFC 5424 syslog, identifiers, paths, hashes, and timestamps are generally source-appropriate.
- **Temporal patterns:** 7 — Broad timing and lifecycle duration are varied, but the post-termination Java flow is an impossible visible ordering.
- **Cross-source correlation:** 8 — Correlation is excellent overall, though it faithfully propagates the bad Windows parent relationship into three endpoint sources.
- **Behavioral realism:** 8 — User, workstation, and server behavior is differentiated and operationally plausible; compact module bundles retain some generated texture.
- **Environmental consistency:** 8 — Host roles, services, users, and background activity fit a coherent mixed Windows/Linux enterprise, aside from repeated service-owned user shells.

## Recommendations

- If this were synthetic, create interactive Windows shells only through the canonical `winlogon.exe` → `userinit.exe` → `explorer.exe` lifecycle. For actions occurring in an existing desktop session, attach new child processes to the already-active shell identity instead of creating a new `explorer.exe` under `services.exe`.
- If this were synthetic, enforce a process-lifetime invariant in eCAR: no dependent FLOW, MODULE, FILE, REGISTRY, or THREAD event may use a process object after its termination timestamp. Build the full dependent timeline before scheduling termination, or extend the process lifetime through the last child/dependent action.
- If this were synthetic, vary filtered module telemetry by executable, version, loaded feature, and process lifetime. Preserve collection filtering if intentional, but avoid emitting the same small core-DLL sequence in nearly identical millisecond bursts for unrelated applications and hosts.
