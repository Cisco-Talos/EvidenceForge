# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 18

## Executive Summary

The bounded endpoint sample looks substantially production-like, with plausible process ancestry, varied session types, stable executable hashes, and coherent visible process lifetimes. I found no reproducible hard contradiction or strong synthetic distribution artifact; this supports a low synthetic-confidence score, but these checks cannot establish production provenance.

## Evidence For Synthetic

- No substantive synthetic indicator was established in the bounded checks. In particular, I did not find a visible same-identity process lifecycle inversion in the six eCAR host samples, and apparent doubled Windows path separators in a programmatic display proved to be representation escaping rather than malformed XML values.
- [weak_signal] `APP-INT-01.meridianhcs.local/bash_history/marcus.chen.bash_history`, lines 1–2 and 7–8, records `systemctl status cifs-utils --no-pager` and `systemctl cat cifs-utils 2>/dev/null | head -40`. Treating a utilities package name as a service is slightly unusual, but an administrator probing for a unit is entirely possible. There is no exit status or command output proving a fabricated successful service operation. This observation does **not** materially raise the score.

## Evidence For Real

- Windows process identity and command details reconcile across independent source shapes. All 97 Sysmon Event 1 process creations on WS-MCHEN-01 have a Security 4688 match on decimal/hex PID, executable path, and command line; WS-DRAMIREZ-01 has 52/52 such matches. This is evidence of coherent endpoint semantics, not proof of origin.
- The first sampled WS-MCHEN-01 service process has PID 7260, parent PID 5872, image `C:\Windows\System32\svchost.exe`, command `svchost.exe -k netsvcs -p -s LanmanServer`, and SYSTEM ownership. Sysmon identifies it at `2026-11-02T13:07:20.9196390Z`; Security records PID `0x1c5c` at `13:07:20.9970862Z`. The timing difference and identifier representations are plausible.
- WS-MCHEN-01 contains Security 4624 types 2, 3, 5, 7, and 9, rather than treating every activity as a fresh interactive login. Its type 7 record at `13:49:51.2820703Z` names `marcus.chen`, `winlogon.exe`, logon ID `0x6c2f76f`, and `LogonProcessName=User32`.
- Linux cron evidence includes real shell/helper relationships. APP-INT-01 eCAR lines 1–4 show shell PID 2931365 spawning helper PID 2931366 for the sysstat collection command, followed by helper termination before shell termination. The syslog line 1 independently records the corresponding CRON command.
- macOS ES distinguishes fork from successive exec images instead of treating each executable replacement as a new PID. MAC-MROSS-01 ES lines 1–7 trace launchd, xpcproxy, Terminal, login, and zsh with explicit audit-token identities and inherited parent/responsible-process information.
- Sampled Windows Sysmon process hashes remain stable per image path within each of WS-MCHEN-01, WS-DRAMIREZ-01, and DC-01. I found no repeated executable path acquiring unrelated hashes within those samples.

## Detailed Analysis

### Scope and method

I inspected only the supplied data directory. The focused sample covered Windows workstation process/session records on WS-MCHEN-01 and WS-DRAMIREZ-01, a DC-01 Windows role comparison, Linux APP-INT-01 and WS-LNGUYEN-01, and macOS MAC-MROSS-01 and MAC-MROSS-02. I parsed the relevant XML and JSON records rather than relying solely on aggregate counts, and read selected syslog and shell-history entries.

This was a representative review, not a complete census of every source and event family. The visible interval is approximately 2026-11-02 13:00–19:00 UTC; I treated unmatched beginnings or endings at its boundaries as neutral. I did not infer a required audit source merely from a host platform.

### Windows process and session semantics

On WS-MCHEN-01, `windows_event_sysmon.xml` line 395 identifies process PID 7260; its surrounding Event 1 contains the service command and parent described above. `windows_event_security.xml` line 555 gives its matching `NewProcessId=0x1c5c`. On WS-DRAMIREZ-01, Sysmon lines 25–26 identify PID 6544 and `C:\Windows\System32\dllhost.exe`; Security line 31 gives the matching PID `0x1990`. The parent for that COM surrogate is a `svchost.exe -k DcomLaunch` instance, which is appropriate.

The ancestry distribution has useful role variation. WS-MCHEN-01 contains explorer-to-PowerShell, PowerShell-to-OpenSSH, explorer-to-mstsc, and normal services/SearchIndexer descendants. WS-DRAMIREZ-01 has more taskhostw, WmiPrvSE, and COM-surrogate activity. DC-01 shows substantial authentication/connection activity and background process families; its service and network logons differ from workstation interactive/unlock behavior. None of these counts alone demonstrates production provenance, but the samples do not show an obvious OS or role mismatch.

The Windows XML path values are ordinary single-backslash strings after XML parsing. For example, WS-DRAMIREZ-01's first Sysmon image has length 31 and begins with character codes `[67,58,92,87,105,110,100,111,119,115,92,83,121,115]`; it contains zero consecutive backslash pairs. Similarly, parsed privilege lists contain actual whitespace. A doubly escaped debug representation is not evidence of synthetic telemetry.

### Visible eCAR process lifetimes

I checked eCAR records on six hosts: WS-MCHEN-01, WS-DRAMIREZ-01, APP-INT-01, WS-LNGUYEN-01, MAC-MROSS-01, and MAC-MROSS-02. For visible process identities, I looked for actor references more than two seconds after a visible termination, actor references more than two seconds before a visible creation, and non-termination process activity more than two seconds after termination. No such contradictions were found. The two-second margin acknowledges source observation timing; this does not certify finer ordering or every lifecycle family.

APP-INT-01 has 98 visible create/terminate pairs, WS-LNGUYEN-01 75, MAC-MROSS-01 50, and MAC-MROSS-02 48. Their visible lifetimes vary substantially: APP-INT-01 ranges from 0.250 to 13,307.381 seconds, while WS-LNGUYEN-01 ranges from 0.134 to 14,220.603 seconds. Short-lived commands coexist with long-running shells and processes.

A reproducible small example is APP-INT-01 eCAR lines 1, 2, 3, and 4: shell PID 2931365 is created at timestamp_ms `1793624401077`; child helper PID 2931366 at `1793624401273`; helper exits at `1793624403546`; shell exits at `1793624403569`. Their process UUID relationships also agree.

### Linux authentication and user activity

APP-INT-01 syslog lines 60–61 record an accepted public key for aisha.johnson from `10.10.1.35:61718` at `13:43:00.702475Z`, then PAM session opening at `13:43:00.878347Z`. eCAR line 52 records the same source tuple and successful session, with logon ID `0x1519c2a2` and session ID `376383`; line 108 closes that same identity. Other visible logons include password and public-key authentication, varied users, and different session durations.

WS-LNGUYEN-01's history contains development and administration commands, including git, kubectl, VS Code, SSH, and diagnostic upload preparation. APP-INT-01's sampled history instead includes service/log inspection. I did not score the compactness or apparent narrative organization of any suspicious commands.

### macOS source interpretation

MAC-MROSS-01 `macos_endpoint_security.ndjson` declares message `version=11` and represents fork, exec, and exit as separate event shapes. The first launch chain preserves process start time across executable changes, advances exec identity, and distinguishes the actor executable from the exec target. For example, lines 1–3 reuse PID 42169 through launchd/xpcproxy/Terminal; lines 4–7 then model Terminal's login/shell descendants. This is more faithful to native process semantics than assuming one PID per image.

The second Mac has an iTerm-specific chain instead of blindly duplicating Terminal's process tree. MAC-MROSS-01 also has a separate SSH-origin zsh execution at ES line 97 (`2026-11-02T16:02:23.747524000Z`), and its Unified Log line 3 records public-key acceptance from `10.10.1.42:52550` shortly beforehand. I did not establish a native schema contradiction from these records. This was not an exhaustive verification of the declared ES version against every Apple structure field.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| weak_signal | Linux shell history | Two service-inspection commands on APP-INT-01 | Negligible; possible operator probing, without a contradictory success result |
| No established defect | Windows/Sysmon/eCAR and sampled Linux/macOS endpoint evidence | Representative hosts and visible lifetimes only | Keeps the score in the indistinguishable/production-like band; does not prove provenance |

## Realism Score by Category

- **Field format accuracy:** 9 — Sampled native XML and structured endpoint records parse and retain plausible types and source-specific semantics; macOS version coverage was limited.
- **Temporal patterns:** 9 — Sampled process lifetimes vary and no material same-identity ordering inversion was found with the stated observation margin.
- **Cross-source correlation:** 9 — Windows PID/image/command matching and selected Linux SSH/session relationships agree.
- **Behavioral realism:** 8 — Plausible role-dependent tools and background ancestry; a six-hour bounded sample limits conclusions about long-tail user routines.
- **Environmental consistency:** 8 — Sampled Windows, Linux, and macOS process/session roles are coherent; host software inventories and full collection policies are unavailable.

## Recommendations

- If this were synthetic, retain the distinct native process, exec, session, and source-observation semantics demonstrated here. No concrete lifecycle repair is justified by these bounded checks.
- For the `cifs-utils` service-inspection commands, additional captured exit status or command output would help distinguish a normal unsuccessful probe from an incorrectly modeled service. The existing history alone does not justify changing the commands or penalizing authenticity.
