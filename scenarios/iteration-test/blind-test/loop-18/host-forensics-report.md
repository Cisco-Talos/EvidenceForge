# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 84
**Synthetic-Confidence Score:** 55

## Executive Summary

The endpoint evidence is substantially coherent across Windows, Linux, macOS and normalized eCAR records, and the checks performed did not reveal an impossible visible process lifecycle. The strongest authenticity concern is repeated microsecond-exact timing phases across several macOS command groups on both Macs; this suggests constructed scheduling, but could also reflect automation or timestamp transformation and does not establish synthetic origin by itself.

## Evidence For Synthetic

- [distribution_texture] In `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson`, fork records at lines 35, 38, 41 and 44 occur at `13:48:41.198588000Z`, `13:49:08.198588000Z`, `13:49:43.198588000Z` and `13:50:02.198588000Z` on November 2, 2026. Four separate children of the interactive zsh PID 25529 preserve exactly the same microsecond fraction across integer-second offsets of 27, 35 and 19 seconds. Their succeeding exec records have independently differing fractions. This is a concrete timing pattern, independent of what the commands accomplish.
- [distribution_texture] The same pattern recurs in two other groups: Mac 01 lines 53, 56 and 59 at `14:37:50.487145000Z`, `14:38:28.487145000Z` and `14:38:57.487145000Z`; Mac 02 lines 86, 89 and 92 at `15:30:55.965208000Z`, `15:31:17.965208000Z` and `15:31:58.965208000Z`. In total, 10 of 103 observed ES fork records participate in these three repeated-fraction groups. Ordinary process scheduling is unlikely to preserve an exact six-digit fractional phase across separate shell commands on this timescale. A scripted schedule or preprocessing remains an alternative explanation, so I treat the three groups as one repeated timing indicator rather than independent contradictions.

## Evidence For Real

- The Windows process evidence supports consistent identities and executable truth. Across all ten Windows hosts, 949 Sysmon Event 1 records were parsed. A conservative same-PID/same-minute match found 945 Security 4688 counterparts; all matched executable paths and command lines agreed. The unmatched cases were not treated as defects because the matching method has minute boundaries and collection can differ by source.
- Within each Windows host, same-GUID Sysmon records did not show an image changing unexpectedly, a dependent record preceding a visible creation, or activity following a visible termination when comparing the source's `UtcTime` values. Executable hash sets were stable for repeated paths within each host's visible Event 1 records.
- eCAR process identities are similarly coherent. Across all 23 host files, the checks found no actor UUID reference preceding its visible process creation or following its visible termination. Where the actor had a visible process creation, the child's `ppid` agreed with that parent's PID.
- Windows includes meaningful session distinctions. For example, `WS-MCHEN-01/windows_event_security.xml` contains types 2, 3, 5, 7 and 9, with local, service, unlock, network and alternate-credential semantics; it also contains 4800/4801 lock/unlock events. Servers and workstations have visibly different session and process distributions.
- Native macOS records preserve fork versus exec rather than equating an image change with a new process. On Mac 01, PID 25527 progresses from inherited launchd image to xpcproxy to Terminal, while PID versions change and its process start time remains stable. Terminal subsequently forks a login process and a zsh session. The normalized records retain the same process object through exec modifications.
- Linux SSH and privilege-use examples have source-appropriate detail. `WEB-EXT-01/syslog.log` records PID 3030818's connection, public-key acceptance, PAM session opening and logind session creation in order. A separate denied sudo command at `13:01:36.096882Z` does not turn into the nearby successful root command: the latter is a distinct sudo PID and different command.

## Detailed Analysis

### Examination scope and method

I examined only the supplied data directory. Endpoint coverage comprises 23 eCAR host files, ten Windows Security/Sysmon pairs, Linux syslog and bash histories, and two sets of native macOS ES/Unified Log records and zsh histories. The visible period is approximately `2026-11-02 13:00–19:00 UTC`. I parsed endpoint records, tested identifier and lifetime relationships, compared Windows process fields, and read representative native records and command histories. These checks are not an assertion that every possible field or event family was exhaustively validated.

Collection-window boundaries were respected: termination without a visible creation, an existing shell or service at the first timestamp, and a process surviving past the slice do not count against authenticity. Missing Sysmon event families, absent optional sources, sanitized domains and the comprehensibility of suspicious activity were not used as indicators.

### Windows process trees, hashes and sessions

The visible process population distinguishes roles. DC-01's Sysmon process creations include 32 `csrss.exe → conhost.exe`, 32 `svchost.exe → dllhost.exe`, 32 `svchost.exe → WmiPrvSE.exe` and 29 `svchost.exe → taskhostw.exe` relationships. Workstation MCHEN instead includes seven `explorer.exe → mstsc.exe`, four PowerShell-to-OpenSSH relationships and interactive administration. The repeated server families are narrow, but their counts alone are insufficient to establish an unrealistic workload or contradictory collection scope; I did not score them as a synthetic tell.

One concrete workstation process is AdobeARMservice PID 6852, Sysmon `UtcTime=2026-11-02 13:08:44.049`, GUID `{7b2a0e3f-8b5c-6ae8-b100-0000d578c07b}`. It runs as `NT AUTHORITY\SYSTEM`, LogonId `0x3e7`, integrity `System`, terminal session 0, parent `services.exe` PID 5872. This is an internally sensible service relationship. The source carries multiple binary hash algorithms and a consistent parent identity.

MCHEN's Security log has 21 Event 4624 records: ten network, seven service, two unlock, one interactive and one NewCredentials. The interactive event at `14:44:15.3040531Z` identifies `marcus.chen`, type 2, LogonId `0x6d0365e`. Network examples include `14:40:57.4334660Z`, type 3, Kerberos, source `::ffff:10.10.2.26`. Unlocks use the existing `0x6c29844` identity. An older existing session and a subsequent fresh local session can coexist; I did not reinterpret that as an ordering error.

### Linux SSH, sudo and shell histories

On WEB-EXT-01, eCAR creates privileged sshd PID 3030818 with parent sshd PID 23965 at timestamp_ms `1793624445113`. Syslog subsequently records:

- `13:00:48.651630Z`: connection from `10.10.1.21:40111`;
- `13:00:54.830747Z`: accepted public key for `lina.nguyen`, same PID and tuple;
- `13:00:54.940587Z`: PAM session opened for UID 5302;
- `13:00:55.554934Z`: logind creates session 293.

This is a plausible within-window sequence. Nearby closure of marcus.chen's different sshd PID 3016354 is separate activity, not premature closure of lina.nguyen's session.

The WEB sudo denial at `13:01:36.096882Z` is PID 3030910 attempting `/usr/bin/tail -n 50 /var/log/nginx/error.log`. The successful command nearby uses sudo PID 3030912 and root child PID 3030913 for `/usr/bin/systemd-analyze blame`. Treating the denial as evidence that the successful child was impossible would incorrectly merge different commands and process identities.

Linux history content differentiates users and roles: database queries on DB-PROD-01, Elasticsearch checks on LOG-MON-01, development tools on WS-LNGUYEN-01 and data-analysis tools on WS-OHADDAD-01. Some service names and command choices are unusual, but no observed command output proves they were invalid, and failed administrator commands would remain possible. I did not score those impressions.

### macOS lifetimes and native versus normalized evidence

Both ES exports declare schema version 1/message version 11. I assessed their visible identity relationships without claiming unverified version-specific schema violations.

On Mac 01, ES lines 1–7 show launchd forking PID 25527 at `13:07:32.811343000Z`, followed by xpcproxy exec and Terminal exec. Terminal forks PID 25528, which execs `/usr/bin/login`; its child PID 25529 execs `/bin/zsh` at `13:07:32.886423000Z`. The forked child initially has the parent's executable image, and later exec changes that image; this is appropriate process-lifetime modeling. Audit user/session identifiers, effective credentials and POSIX process/session fields are represented separately.

For the 47 Mac 01 and 56 Mac 02 forked processes matched to eCAR creates, the parent PID relationship agrees. Native ES timestamps and normalized eCAR timestamps are offset, so I did not require exact timestamp equality between sources. Within the examined ES executable snapshots, the same device/inode pairs did not carry conflicting paths, hashes, sizes or modification times.

Mac 01 Unified Log contains `ASP: Security policy would not allow process: 42008, /Applications/MeetingAssist.app/Contents/MacOS/MeetingAssist` at `15:42:09.009673+0000`. That policy message is not itself a successful exec record. I did not infer successful execution or downstream effects from it.

The repeated exact fractional seconds described above remain the main concern. The collision is in the fork event's native `time` field, before the later independently varying exec times. It therefore cannot be dismissed simply as millisecond quantization in the normalized eCAR format. However, without collector transformation details or evidence excluding scripted shell scheduling, it remains a distribution artifact rather than an impossible event.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Native macOS Endpoint Security fork timing | Three command groups, both Macs; 10 of 103 forks | Moderate upward pressure: repeated exact microsecond phases suggest fixed offsets from shared anchors. Automation or timestamp transformation could explain them. |

No hard contradiction was established by the performed checks. Stable process identities and matched cross-source executable facts offset the timing concern; completeness itself was not scored in either direction as proof of origin.

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed endpoint records retain plausible source-specific fields and identity structure; no demonstrated native schema contradiction.
- **Temporal patterns:** 7 — Process lifetimes are coherent, but three macOS fork groups preserve suspiciously exact fractional phases.
- **Cross-source correlation:** 9 — Matched Windows process fields and macOS parent identities agree, with no tested actor-lifecycle inversion.
- **Behavioral realism:** 8 — Role-dependent processes, administration, shell tools and privilege outcomes are credible within the visible slice.
- **Environmental consistency:** 9 — Mixed operating systems and service/workstation roles remain internally compatible in the evidence examined.

## Recommendations

- If this were synthetic, improve command-start scheduling so independent shell actions do not inherit identical six-digit fractional timestamps merely because they share an activity anchor. Preserve genuine scripted timing only when the modeled execution mechanism supports it.
- If a timestamp transformation intentionally preserves these phases, document that collection behavior; it would explain the specific observed timing artifact without requiring changes to otherwise coherent process identities.
