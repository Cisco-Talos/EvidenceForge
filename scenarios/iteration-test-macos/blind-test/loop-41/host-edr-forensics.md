# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 63

## Executive Summary

The endpoint data is substantially realistic: Windows process identities and hashes are coherent, native log clearing changes record numbering correctly, and the Mac records distinguish fork, successive exec images, and terminal/session ownership. My synthetic verdict rests chiefly on repeated microsecond-exact timing templates in the native Mac process notifications, rather than any demonstrated impossible process tree or missing source family. Those timing artifacts are persuasive but concentrated in two endpoints, which limits the score and confidence.

## Evidence For Synthetic

- [distribution_texture] Independent shell-command forks repeatedly preserve an identical six-digit fractional second across tens of seconds. In `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson`, lines 32, 35, and 38 are `13:48:35.351324000Z`, `13:49:05.351324000Z`, and `13:49:55.351324000Z`; the execs immediately following them run `pwd`, `ls`, and `du`. Lines 53, 56, and 59 repeat this with `.173001000Z` at `14:38:18`, `14:38:55`, and `14:39:47`. On MAC-MROSS-02, lines 65, 68, and 71 preserve `.560051000Z` for `id`, `sw_vers`, and `find` launches. Across the two native ES files, 30 of 58 forks whose source executable is `/bin/zsh` belong to 13 groups with repeated fractional seconds. The varying whole-second gaps combined with invariant microseconds resemble planned offsets attached to one anchor rather than observed operating-system fork times.
- [distribution_texture] Six independent inventory process lifetimes, across both Macs, are exactly **2.000000 seconds from child start to exit**, even though their intermediate exec timing varies. MAC-MROSS-01 lines 30–31 show PID 44501 executing `sw_vers`, with `start_time=13:31:25.866513Z` and exit `13:31:27.866513000Z`; lines 72–73 and 135–136 repeat the exact interval for PIDs 59635 and 73882. MAC-MROSS-02 lines 33–34, 97–98, and 140–141 do the same for PIDs 21921, 44140, and 56599. A periodic inventory tool is plausible; precise reuse of a two-second fork-to-exit lifetime across every visible run is the tell.
- [distribution_texture] Initial Chrome helper forks also use exact offsets from their launch anchor. MAC-MROSS-01 lines 17–25 place the initial browser fork at `13:14:00.135114000Z` and helper forks at `13:14:02.135114000Z`, `13:14:03.135114000Z`, and `13:14:05.135114000Z`. MAC-MROSS-02 lines 22–30 use the same +2, +3, and +5 second pattern, preserving `.996507000Z`. This reinforces the same timing-template finding; I do not count it as a separate hard contradiction.

## Evidence For Real

- Windows process identity is strong. All 876 Sysmon Event 1 records were checked against the corresponding host's Security 4688 records by PID and case-insensitive executable path; 875 had a match. A single unpaired process, without an impossible companion, is neutral under selective collection.
- Across all ten Windows Sysmon files, each observed process GUID retained the same executable/PID identity. Repeated Event 1 observations of the same executable and file version on one host retained consistent hashes.
- Process lifecycle checks found no visible eCAR actor/self use more than three seconds before its CREATE or after its TERMINATE. Native Sysmon checks found no corresponding same-GUID ordering violation exceeding one second, including parent references and process access targets. These are bounded checks, not claims about invisible processes.
- `DC-01.meridianhcs.local/windows_event_security.xml:268429` contains Event 1102 at `18:42:26.0007020Z`, correctly uses `Microsoft-Windows-Eventlog` and `UserData/LogFileCleared`, and resets `EventRecordID` to 1. The preceding record ID is 28261379 at line 268401; the later 4689 uses record ID 7 at line 268468. This is credible source-native state behavior.
- Mac process structure is more detailed than a flat command history: MAC-MROSS-02 ES lines 1–10 describe launchd → xpcproxy → iTerm2 → iTermServer → login → ShellLauncher → zsh, preserving PID across exec and introducing a child at fork. Remote SSH later uses a distinct audit session.
- Linux SSH records preserve user/key consistency across receivers. For example, LOG-MON-01 syslog lines 17–18 show Marcus's accepted ECDSA key followed by PAM session opening; MAIL-CLIN-01 lines 79–80 and MAIL-EDGE-01 lines 54–55 use the same user/key fingerprint with distinct source ports and PIDs.

## Detailed Analysis

### Scope and method

I inspected only the supplied data files. I inventoried the host sources, parsed every eCAR JSON record and all Windows Security/Sysmon XML files, checked visible process identity/lifecycle relationships, and read native Mac notifications, Unified Log records, Linux syslog, and shell histories. The supplied host sources span Windows, Linux, and two Macs over the visible November 2 window. Missing pre-window initiators, post-window terminations, and unselected event families were not scored.

The Windows collection contains 876 Security 4688 records and 876 Sysmon Event 1 records, 739 Security process exits, and 747 Sysmon process exits. Those unequal exit counts do not establish a defect: collection boundaries and source selection are sufficient alternatives. I did not infer synthetic origin from complete matching where matching existed.

### Windows process and session evidence

The source-native structures generally look credible. Sysmon carries native process GUIDs, logon identifiers, parent GUID/PID/image fields, integrity levels, version metadata, and multiple hashes. Security process creation records use hexadecimal PIDs and distinguish subject identity from the optional target identity. Domain-controller samples use Windows Server build metadata such as `10.0.20348.1`; workstation samples include Windows client metadata such as `10.0.19041.1`.

On DC-02, Sysmon Event 1 at `13:05:16.907` describes PID 7236, `taskhostw.exe`, under PID 5128, `svchost.exe -k LocalSystem`, as SYSTEM. Security 4688 at `13:05:17.2249540Z` describes new PID `0x1c44` and creator `0x1408` with matching images and SYSTEM subject. The subsecond difference is compatible with distinct observation paths and is not an impossible ordering claim.

The logon mix includes interactive, network, service, remote-interactive, failures, and workstation lock/unlock activity. It is not necessary for this bounded collection to contain every expected boot or unlock event. The 1102 example above is particularly useful positive evidence because its provider, payload shape, and channel record-number transition agree.

The single unpaired Sysmon creation is WS-AJOHNSON-01 PID 5324, `cmd.exe`, at `13:56:55.728`, with parent PID 5004 `explorer.exe`. I found no same-PID Security creation with a conflicting image; absence alone does not justify a synthetic penalty.

### macOS process, session, and policy interpretation

The ES records declare message `version=11` and differentiate source process snapshots from exec targets. A later image of one PID is not a new forked process. In MAC-MROSS-02 lines 2–3, PID 18966 successively executes xpcproxy and iTerm2; the later child PID 18967 then executes iTermServer. This is an internally intelligible terminal bootstrap rather than a Windows/Linux process template relabeled as Mac.

MAC-MROSS-02 Unified Log line 2 records keyboard-interactive/PAM acceptance at `14:24:35.344259+0000` from `10.10.1.41:63486`, under sshd-session PID 30036. ES lines 50–64 show its launch and SSH process chain, then session-associated descendants with `auid=501`, `asid=100002`, and the remote zsh shell PID 30042. The local shell uses a distinct `asid=100001`. ES lines 74–76 close shell, session child, and listener-associated process in order. MAC-MROSS-01 similarly distinguishes local and remote activity.

MAC-MROSS-01 Unified Log line 2 reports AppleSystemPolicy saying it would not allow MeetingAssist PID 62521 at `15:42:28.922523+0000`. I did not reinterpret an ES notification result as an authorization decision, or infer successful child execution from this rejected-attempt message. The source is too narrowly selected to demand a full policy conversation, launchd export, or file audit trail.

The substantive weakness is timing. Native fork notifications preserve identical microseconds across multiple separate user-command launches. Exact +2/+3/+5 second Chrome helper creation and six exact two-second inventory lifetimes provide additional examples of the same texture. Ordinary scripts can create regular timing, and a collector can transform timestamps, so these are not impossible values. However, exact microsecond preservation over many unrelated delays and both endpoints warrants a synthetic lean unless an explicit timestamp transformation explains it.

### Linux evidence and behavioral texture

The Linux sources include cron, sudo/PAM, systemd, resolver, SSH, and desktop/service messages. APP-INT-01 eCAR lines 1–2 model a cron-owned shell invoking `debian-sa1`, with sysstat principal and a root cron parent; syslog line 1 logs the matching cron command. APP-INT-01 syslog lines 15–16 have password acceptance followed by PAM opening for Lina. Public-key sessions elsewhere retain the same user fingerprints while varying session details.

Histories distinguish roles: Lina's workstation includes Git/build/development activity, Marcus's server histories contain operational inspection, and Maya's DB history includes MySQL commands. Some service-target choices, such as `systemctl status cifs-utils` or restarting `smbclient`, are unusual because those names commonly identify client packages/tools. They could be user mistakes or local wrappers; the visible records do not prove a successfully running nonexistent service. I therefore did not score them as contradictions.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Native Mac ES fork notifications | 30 of 58 zsh-source forks, 13 repeated-fraction groups across two hosts | Strongest indicator: variable command gaps preserve exact microseconds |
| distribution_texture | Native Mac ES inventory lifecycle | All six visible inventory runs across two hosts | Exact 2.000000-second child-start-to-exit duration suggests assigned lifecycle timing |
| distribution_texture | Native Mac ES browser startup | Initial Chrome tree on each Mac | Identical +2/+3/+5-second helper schedule reinforces shared timing-template concern |

No hard contradiction is established. These findings share a timing theme and are not treated as three independent proofs. Strong Windows identity/format consistency and coherent visible lifecycles restrain the overall score.

## Realism Score by Category

- **Field format accuracy:** 9 — Native Windows structures and differentiated Mac process snapshots are convincing; no demonstrated parser or identity-format defect.
- **Temporal patterns:** 5 — Repeated exact microsecond anchors and fixed inventory lifetimes undermine otherwise varied timing.
- **Cross-source correlation:** 9 — Windows image/PID identity checks and native/normalized lifecycle checks show strong agreement.
- **Behavioral realism:** 8 — Appropriate process chains and differentiated operational/development activity; regular Mac command timing is the main concern.
- **Environmental consistency:** 8 — Platform-specific sources, domain identities, and SSH users/keys are coherent within the visible evidence.

## Recommendations

- If this were synthetic, give each observed shell fork its own scheduling/observation variation instead of adding integer seconds to a retained microsecond anchor. Keep genuinely scheduled automation regular at the appropriate granularity.
- If this were synthetic, derive inventory exit timing from the actual modeled subprocess work, including independently varying exec/start/exit latency, instead of assigning exactly two seconds to every launched child.
- If this were synthetic, vary Chrome helper startup relationships with an empirically supported distribution while preserving process order and identity.
- If timestamps were transformed by a collector or sanitization step, document that transformation; a precision-preserving timing rewrite could explain the principal authenticity concern without changing the underlying process data.
