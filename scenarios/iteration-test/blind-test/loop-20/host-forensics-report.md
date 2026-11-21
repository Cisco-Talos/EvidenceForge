# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 77
**Synthetic-Confidence Score:** 49

## Executive Summary

The endpoint evidence is substantially production-like: process identities, parent relationships, binary hashes, session distinctions, and platform-specific execution chains survive direct inspection and broad consistency checks. Repeated background-message vocabulary, a concentrated Windows server process mix, and unusual local macOS terminal process groups raise authenticity questions, but none establishes an impossible visible lifecycle or a decisive synthetic fingerprint.

## Evidence For Synthetic

- [distribution_texture] Linux background chatter repeatedly draws from a very small vocabulary. In `APP-INT-01.meridianhcs.local/syslog.log`, all 67 `irqbalance` records are four exact messages, with counts 18/18/16/15; `LOG-MON-01` has 70 records using the corresponding four messages, counts 21/19/18/12. Their other leading background family is `snapd`, with 69 and 71 records respectively. The balanced, repeated family texture across hosts is suggestive, although persistent diagnostic logging and collection filtering are credible alternatives.
- [distribution_texture] Four generic executable families dominate the visible Windows server process creations: `taskhostw.exe`, `WmiPrvSE.exe`, `conhost.exe`, and `dllhost.exe` account for 125/164 Sysmon Event 1 records on DC-01, 130/145 on DC-02, 87/104 on FILE-SRV-01, and 54/81 on MAIL-FIN-01. DC-01 has exactly 32 creations each of `conhost.exe`, `dllhost.exe`, and `WmiPrvSE.exe`; MAIL-FIN-01 has 14 each of `conhost.exe`, `taskhostw.exe`, and `WmiPrvSE.exe`. This repeated mixture looks somewhat pool-driven, but shared management software and source filtering prevent a firm inference.
- [weak_signal] Local Mac terminal commands consistently retain their login process group, whereas the visible interactive SSH terminal uses distinct command groups. In MAC-MROSS-01 Endpoint Security line 7, shell PID 25529 has `group_id=25528`, `session_id=25528`, and `/dev/ttys000`; all 25 subsequent execs directly from that local zsh retain that group/session pair. MAC-MROSS-02 similarly has 30 local-zsh command execs in group/session 88254. In contrast, MAC-MROSS-01 remote-terminal commands at 16:04:17.888894, 16:05:10.203857, and 16:05:49.694991 have groups equal to their individual PIDs, retaining session 44185. Disabled local shell job control could explain this, so it is a limited concern rather than a demonstrated native-schema defect.

## Evidence For Real

- Windows process correlation is strong without requiring identical observation timestamps. Of 948 Security 4688 records, 947 match a Sysmon Event 1 by host, new PID, and image; all 947 matched records agree on creator/parent PID and command line. Small source count differences exist rather than a forced one-to-one assumption.
- Sysmon process identity is coherent. Across all ten Windows hosts, visible Event 1 parent GUID references do not conflict with their visible parent creations on parent PID, image, or creation ordering. Binary hash lengths are valid, and repeated binary/version combinations do not change hashes within a host.
- At WS-AJOHNSON-01, `conhost.exe` PID 5184 has Sysmon `UtcTime=2026-11-02 13:07:35.793`, parent PID 4256, and parent image `csrss.exe`. Security 4688 at 13:07:35.9093130Z has the same new PID (`0x1440`), creator (`0x10a0`), image, and command `conhost.exe 0x4`. The differing source timestamps are plausible.
- Linux SSH evidence has meaningful sequencing. DB-PROD-01 records connection arrival at 13:08:57.484358Z, password acceptance for lina.nguyen at 13:09:02.848109Z, PAM session opening at 13:09:02.915188Z, and logind session creation at 13:09:03.360344Z. The same SSH PID 1367366 and source tuple 10.10.1.21:49410 persist across the relevant records.
- macOS evidence distinguishes fork from exec and preserves process lifetime across successive executable images. MAC-MROSS-01 PID 25527 begins as a launchd child, executes xpcproxy, and then Terminal, with a stable start time and advancing audit-token versions; it is not incorrectly represented as three unrelated operating-system process lifetimes.
- Native Mac policy rejection is not followed by invented successful execution of the denied application: the 15:42:09.009673Z Unified Log policy message naming MeetingAssist PID 42008 has no matching successful MeetingAssist exec in the supplied Endpoint Security export.
- User activities have visible role differentiation: lina.nguyen's Linux history contains git, Docker, npm, pytest and SSH operations; marcus.chen's Windows telemetry includes MMC, RDP, PowerShell, SQL client and SSH tools. Windows workstation evidence also includes type 7 unlocks and lock/unlock event IDs, rather than only initial interactive logons.

## Detailed Analysis

### Scope and method

I inspected only the supplied data directory. It contains 37,971 eCAR records across 23 hosts, Windows Security/Sysmon exports on ten hosts, Linux-style syslog on eleven hosts, and Endpoint Security, Unified Log and zsh history on two Mac hosts. The visible interval is approximately 2026-11-02 13:00–19:00 UTC. I parsed the Windows XML and endpoint JSON records and read representative native records and command histories directly.

The automated lifecycle checks used explicit identities rather than PID alone: eCAR object/actor identifiers and Sysmon ProcessGuid references. I allowed a one-second margin in the eCAR check for independent source timing. These checks do not prove every event is realistic, and they do not treat unobserved pre-window starts or post-window closes as defects.

### Windows process trees, hashes and sessions

The ten Sysmon exports contain 949 process-create records in total. Matching the 948 Security process creations by host/PID/image yields 947 matches with no parent-PID or command-line disagreements. FILE-SRV-01 contributes the single unmatched Security process creation; source counts differ by one on several hosts. I do not score those minor differences as a contract gap without evidence that both observations were required by the collection policy.

For visible parent creations, the referenced parent GUID consistently resolves to the recorded parent PID and image, with parent creation before child creation. Across Sysmon's dependent events checked against visible creations and terminations, I found no clear process-lifetime violation. Across eCAR, I found no actor reference more than one second before its visible process creation or after its visible termination.

The hash check covered 4,236 algorithm/value entries: 1,062 SHA1, 1,062 MD5, 1,062 SHA256, and 1,050 IMPHASH values. Their lengths were appropriate. The same complete non-placeholder hash string did not identify conflicting reported file versions across the inspected process creations. This is positive consistency evidence, not proof that the files or hashes exist outside the dataset.

Sessions have differentiated semantics. WS-AJOHNSON-01 records a local type 2 logon for aisha.johnson at 13:58:03.7514091Z, LUID `0x25e4b26`, followed by type 7 unlock records for that same LUID at 14:55:40.1035978Z, 15:04:00.5730332Z, and 18:34:37.1232016Z. Its type 10 logon at 16:01:26.6364944Z instead uses LUID `0x26db47f` and names LT-MRIVERA-02 / `::ffff:10.10.1.99:50462` as remote source. Server logons have a different mix: DC-01 has 151 type 3, 126 type 5, and two type 10 successes. Repeated built-in service LUIDs are not evidence of a new initial boot session, so I did not turn earlier SYSTEM activity into false before-logon findings.

The main Windows concern is distribution, not broken identity: generic background processes occupy a large and similarly composed fraction of visible server process creation. For example, DC-01 begins with `taskhostw.exe /Run` at 13:02:00.991, `conhost.exe 0x4` at 13:07:47.958, `dllhost.exe /Processid:{AB8902B4-09CA-4BB6-B78D-A8F59079A8D5}` at 13:11:41.170, and `WmiPrvSE.exe -Embedding` at 13:12:35.252. These individual records are plausible. Their repeated mixture warrants scrutiny but cannot overcome an unknown capture/filter policy by itself.

### Linux authentication, administration and background activity

The DB-PROD-01 SSH sequence described above separates transport arrival, authentication, PAM opening and logind session creation. Other examples include public-key acceptance with key type/fingerprint, sudo command records followed by PAM open/close pairs, scheduled sysstat activity, and anacron start/job/termination messages. These are meaningful details of actual host operation.

APP-INT-01 has CRON sysstat commands at 13:05:00.211792Z and 13:15:00.168742Z, and the corresponding ten-minute schedule continues through the window. Multiple Debian-like hosts show 36 such records. This is a normal cron schedule and is not a uniform-timing authenticity defect.

The repetitive irqbalance/snapd family mixture is more questionable. APP-INT-01's irqbalance PID 39958 repeatedly emits the same four CPU/IRQ messages, beginning with `IRQ 16 classified for CPU 0 balancing on ahci` at 13:08:33.779887Z and a balancing-pass message at 13:11:08.742734Z. LOG-MON-01 exhibits the same four-message structure with its own IRQ/interface parameters. DB-PROD-01 has 52 irqbalance and 60 multipathd records among 191 syslog lines. Routine daemon logs can repeat heavily, and selected forwarding rules can magnify those repetitions; the evidence supports a texture concern, not an impossible environment.

Command histories include role-specific commands, pipelines, backgrounding, and occasional errors such as `rgep` in maya.ross's WEB-EXT-01 history. I did not execute any logged commands or treat their contents as instructions. Commands referencing Debian and RPM tools are not sufficient to identify an impossible OS without exit results and installed-tool evidence.

### macOS execution and policy interpretation

The native Endpoint Security exports declare message version 11. I did not assume that unfamiliar fields were schema violations. Both exports use 40-character cdhash values, and repeated observations of a given PID/audit-token version do not conflict on executable path or start time.

On MAC-MROSS-01, lines 1–7 show launchd fork at 13:07:32.811343Z, xpcproxy exec at 13:07:32.820534Z, Terminal exec at 13:07:32.835499Z, then login and zsh preparation. PID 25527 retains start time 13:07:32.811343Z across those images. The terminal/login/shell roles are distinct; login is not automatically treated as a Linux PAM session.

Remote execution is also differentiated. MAC-MROSS-01 shows xpcproxy, sshd-keygen-wrapper, sshd, sshd-session and sshd-auth activity around 16:02:06, a native public-key acceptance message at 16:02:06.829781Z, and the zsh target at 16:02:06.905481Z. That shell uses `/dev/ttys001`, audit session 100003 and POSIX session 44185. Its later commands have independent groups. MAC-MROSS-02's separate remote shell has no tty, which is plausible for an SSH session without terminal allocation.

The discrepancy is local-terminal job-control texture. The local zsh processes and every directly launched command remain in the login group's ID on both Macs. The SSH tty example demonstrates that other parts of the supplied evidence do represent per-job process groups. An intentionally disabled MONITOR option or other local terminal configuration can account for the difference; without that configuration, it remains a weak authenticity signal.

I also distinguish policy observation from authorization semantics. The Unified Log wording about MeetingAssist is not evidence that an ES notification itself authorized a child. Here there is no successful matching exec to contradict the rejection. Similarly, the eCAR creation and later deletion of `com.meridianhcs.endpoint-inventory.plist` do not themselves establish loading, unloading or process termination, so I did not infer an invalid launchd lifecycle from file operations alone.

### Weight of evidence

The strongest direct tests support coherent endpoint telemetry. The negative observations concern repeated distributions and a potentially explainable terminal configuration, rather than proven impossible native values or causal relationships. That combination supports an inconclusive verdict near the center of the synthetic-confidence rubric; it does not justify an 81–100 score or confident identification as real.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| distribution_texture | Linux syslog | Four-message irqbalance vocabulary; similarly sized daemon-family populations on multiple hosts | Moderate concern about repeated background templates; diagnostic verbosity and filtering remain credible explanations |
| distribution_texture | Windows Sysmon Event 1 | Four executable families comprise 67–90% of visible creations on four servers | Modest concern about a repeated process pool; real management activity and collection selection could explain it |
| weak_signal | macOS Endpoint Security | 55 direct local-zsh command execs across two Macs retain login groups, unlike the visible remote tty commands | Small increase only; disabled job control can produce the observed behavior |

## Realism Score by Category

- **Field format accuracy:** 9 — XML/JSON structure, hash lengths, Windows identities and Mac execution snapshots are consistent in the checks performed.
- **Temporal patterns:** 8 — Native authentication and execution ordering is credible; no clear visible lifetime inversion was established.
- **Cross-source correlation:** 9 — Matched Windows process records agree on identity, command and parent, and eCAR actor lifetimes are coherent within the timing margin.
- **Behavioral realism:** 7 — Roles and administrative workflows differ meaningfully, with some repetitive background vocabulary and server process mixtures.
- **Environmental consistency:** 8 — Platform-specific execution/session details are well distinguished; local Mac process-group behavior needs an environment explanation.

## Recommendations

- If this were synthetic, base repeated Linux daemon messages on persistent daemon state and observed diagnostic verbosity, especially the four-message irqbalance loops documented above. Preserve legitimate periodic cron behavior.
- If this were synthetic, calibrate the Windows server background process mix against the intended collection filter and host workloads; the four-family concentration and near-balanced counts should arise from actual modeled work rather than a generic selection pool.
- If this were synthetic, represent local terminal job control explicitly. For normal interactive zsh, align foreground process-group ownership with the terminal workflow; if job control is intentionally disabled, keep that configuration consistent with the observed local shell behavior.
