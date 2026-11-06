# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 63

## Executive Summary

The endpoint evidence has substantial operational realism: process identities, parentage, executable hashes, session boundaries and source-specific timing generally hold together. I favor synthetic because independently launched macOS inventory processes repeatedly have exactly identical microsecond-resolution lifetimes, accompanied by repeated exact shell scheduling offsets; these are concrete timing fingerprints rather than a judgment about how the suspicious activity unfolds. I did not establish a hard contradiction, so the score remains near the lower end of the “likely synthetic” band.

## Evidence For Synthetic

- [distribution_texture] All six visible macOS inventory invocations have **exactly 2.000000 seconds from native ES fork to exit**, despite different start times and varying intermediate exec delays. In `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson`, the fork/exit line pairs are **28/31, 64/67 and 121/124**; in the corresponding MAC-MROSS-02 file they are **36/39, 100/103 and 138/141**. Each child passes through xpcproxy to `/usr/bin/sw_vers`, then exits with `stat:0`. Exact repetition of the full child lifetime at six decimal places across two hosts is the strongest indicator.
- [distribution_texture] In `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson`, four next-command forks occur **exactly 0.001000 seconds after the preceding child exit**, preserving all six fractional timestamp digits: lines **43/44, 46/47, 81/82 and 84/85**. These are shell PID 18953 continuing after SSH or a local command. Fast queued shell execution is plausible, but the repeated exact one-millisecond boundary suggests a scheduling floor applied to otherwise variable events. This is secondary evidence, not an impossible ordering claim.
- [weak_signal] Native ES lines **94–95** on MAC-MROSS-01 show `/usr/bin/id` with no arguments, PID **64554**, executing at **16:04:00.770729Z** and exiting successfully at **16:05:25.766165Z**, nearly 85 seconds later. A paused or heavily stalled process could explain this, so I give it little independent weight; it is nevertheless an unusual runtime for this specific executable and argument list, especially alongside the rigid inventory lifetimes.

## Evidence For Real

- Mac process lifetimes distinguish fork identity from successive exec images. MAC-MROSS-01 ES lines **1–7** show launchd → xpcproxy → Terminal, followed by login and zsh; PID **42186** persists across exec while `pidversion` changes. This avoids treating each exec as a new unrelated process.
- The Mac sources distinguish platform-specific UI login, native process notifications and normalized endpoint records. MAC-MROSS-01 Unified Log line **1** is a loginwindow message; line **3** is an SSH acceptance message from `/usr/libexec/sshd-session`. These are not incorrectly rendered as Linux PAM/systemd messages.
- Linux host evidence includes plausible paired sudo messages, actual user UIDs and terminal context. `APP-INT-01.meridianhcs.local/syslog.log` lines **8–12** show aisha.johnson invoking `apt-get -s upgrade` via sudo, opening root's PAM session and closing it after roughly 18 seconds. Lines **43–45** show a different command and duration.
- FILE-LNX-01 syslog lines **5–10** show Kerberos SMB authentication, a share connection, open/read/close audit operations and connection closure for lina.nguyen, rather than isolated file activity without its visible session context.
- Windows process trees include service-host distinctions and user-session ownership. For example, WS-AJOHNSON-01 Sysmon Event 1 at **13:19:12.096Z** has `taskhostw.exe /Run` under `svchost.exe -k LocalSystem`; at **13:21:02.148Z**, the user's `ssh.exe` is a child of her preceding cmd process rather than a generic SYSTEM parent.
- Automated scans of all supplied eCAR files found no visible PROCESS/CREATE after the recorded termination of its same-identity parent, no same-identity termination before creation, and no inspected actor activity outside its visible create/terminate interval. Equivalent checks of present Sysmon process identities found no dependent events outside their visible lifetimes.
- Hash values have appropriate lengths and remain consistent for repeated executions of the same image/version on a host. Across the inspected Sysmon `Hashes` fields, **991** values each of SHA1, MD5 and SHA256 had lengths **40, 32 and 64**, respectively; **981** IMPHASH values had length **32**. This is more than merely plausible-looking strings in one example.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory. I inventoried the endpoint sources, parsed every eCAR JSON file and Windows Security/Sysmon XML file, checked process lifetime relationships using durable process identities, and read native macOS ES records, Unified Log messages, Linux syslog and shell histories. Native Mac ES coverage consists of fork, exec and exit notifications: **139 records on MAC-MROSS-01** and **171 on MAC-MROSS-02**. I treated the lack of other ES notification types as a collection choice.

The evidence window covers November 2, approximately 13:00–19:00 UTC. Existing processes and sessions can predate this window. I did not score absent pre-window creation or post-window termination as defects, and I did not infer a required audit product merely from a host's platform.

### Exact inventory runtimes

The repeated two-second duration is observable directly in one native source:

| Host | PID | Fork line/time (UTC) | Exit line/time (UTC) | Elapsed |
|---|---:|---|---|---:|
| MAC-MROSS-01 | 44454 | 28 / 13:30:55.503137 | 31 / 13:30:57.503137 | 2.000000 s |
| MAC-MROSS-01 | 59593 | 64 / 15:15:46.859128 | 67 / 15:15:48.859128 | 2.000000 s |
| MAC-MROSS-01 | 73937 | 121 / 17:39:13.244911 | 124 / 17:39:15.244911 | 2.000000 s |
| MAC-MROSS-02 | 21918 | 36 / 13:43:10.118008 | 39 / 13:43:12.118008 | 2.000000 s |
| MAC-MROSS-02 | 44095 | 100 / 15:46:48.875258 | 103 / 15:46:50.875258 | 2.000000 s |
| MAC-MROSS-02 | 56592 | 138 / 17:52:20.143237 | 141 / 17:52:22.143237 | 2.000000 s |

Intermediate exec notification times vary. For PID 44454 the final exec is at **13:30:55.511034Z**, whereas PID 56592's is at **17:52:20.149186Z**. Thus the invariant is anchored to the fork, not just a rounded display of executable runtime. Each launch identifies `com.meridianhcs.endpoint-inventory` in its xpcproxy arguments. Scheduled inventory itself is ordinary; the repeated exact runtime is what affects the authenticity score. A deliberately instrumented or controlled process could produce related timing, but no visible wrapper, timeout failure or explanatory result establishes that explanation here.

### Shell command scheduling and behavior

MAC-MROSS-02's first relevant SSH exits at **14:18:16.813290Z** (line 43); zsh forks the next child at **14:18:16.814290Z** (44). The ls child exits at **14:18:16.965114Z** (46), followed by a fork at **14:18:16.966114Z** (47). A second pair of the same pattern occurs at **15:12:08.570673/.571673** and **15:12:08.630328/.631328** (81–85). Their command histories preserve the same clustered seconds. Scripts or pasted commands could explain immediate continuation, so I do not treat fast execution itself as a defect; the repeated exact increment is the limited concern.

Other behavior is less rigid. Linux developer histories include git, npm, cargo and editors, while database-server sessions include database health checks and SQL clients. APP-INT-01 has variable SSH-session lifetimes, cron/sysstat jobs and longer-running `docker compose logs -f` activity. Those distributions counterbalance the narrow Mac timing fingerprint.

### Windows sessions and process correlation

The Windows XML parses successfully and uses source-appropriate hexadecimal logon/process IDs and GUID-based Sysmon process references. Repeated per-image hashes did not change arbitrarily between launches. Present Sysmon termination/dependent events did not demonstrate dead processes continuing to produce activity.

I did not label repeated reserved service logon IDs (`0x3e7`, `0x3e5`, `0x3e4`) as session-identity collisions: built-in service contexts require different interpretation from independent user/network sessions. I also did not count unmatched service or interactive logons as errors solely because no closure appears in this bounded collection.

### macOS policy and collection limits

MAC-MROSS-01 Unified Log line 2 contains `ASP: Security policy would not allow process: 62492, /Applications/MeetingAssist.app/Contents/MacOS/MeetingAssist`. That wording alone does not establish a completed denial, and I did not use it to infer an impossible child execution or successful effect. I did not find enough visible policy lifecycle evidence to score a policy contradiction.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | macOS Endpoint Security | Six inventory process lifetimes across two hosts | Main reason to favor synthetic: identical 2.000000-second fork-to-exit intervals despite varying exec delays |
| distribution_texture | macOS Endpoint Security and shell history | Four shell handoffs on MAC-MROSS-02 | Secondary timing-floor fingerprint; immediate shell continuation itself remains plausible |
| weak_signal | macOS Endpoint Security | One `/usr/bin/id` invocation | Minor contribution only; long successful runtime has possible production explanations |

No hard contradiction or demonstrated native-schema defect was established.

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed fields, hash lengths and native-vs-normalized source distinctions are credible.
- **Temporal patterns:** 5 — Strong exact-duration and exact-handoff fingerprints in the Mac native source undermine otherwise variable timing.
- **Cross-source correlation:** 9 — Inspected process identities and lifetimes are coherent; no demonstrated impossible correlation.
- **Behavioral realism:** 8 — Role-specific tools and differentiated process trees are convincing; the no-argument id runtime is unusual.
- **Environmental consistency:** 8 — Windows, Linux and Mac evidence generally preserves platform-specific semantics and host roles.

## Recommendations

- If this were synthetic, derive the inventory process exit from a realistic execution lifetime rather than an identical two-second interval from each fork. Preserve the existing xpcproxy/exec identity relationships.
- If this were synthetic, make shell continuation latency reflect scheduler and input behavior instead of repeatedly adding exactly one millisecond. Preserve legitimate queued-command bursts and foreground blocking.
- If this were synthetic, assign runtimes by executable and invocation: a no-argument id command should ordinarily complete promptly unless a visible pause or other modeled cause explains its roughly 85-second lifetime.
