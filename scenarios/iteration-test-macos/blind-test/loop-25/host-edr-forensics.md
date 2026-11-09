# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 80
**Synthetic-Confidence Score:** 25

## Executive Summary

The sampled endpoint evidence is largely production-like, with coherent process identities, plausible process lifetimes, stable binary hashes, and sensible Windows and Linux session relationships. I did not substantiate an impossible visible lifecycle or a source-native contradiction in the bounded checks; a small amount of repetitive command texture is insufficient to distinguish a carefully constructed dataset from collected operational activity.

## Evidence For Synthetic

- [weak_signal] The two Mac shell histories draw repeatedly from a small diagnostic/file-inventory vocabulary. For example, `MAC-MROSS-01.meridianhcs.local/zsh_history/maya.ross.zsh_history` lines 11–14 contain `ifconfig`, `dscl`, SSH and `id`, while lines 20–23 return to `find`, `ps`, and `df`; the second Mac's history similarly repeats `sw_vers`, `uname`, `pwd`, `du`, `df`, `ps`, and `find`. This could reflect a bounded command catalog, but these are ordinary commands, both machines belong to the same named user, and collection may select shell activity. I assign it very little weight.
- No high-impact synthetic indicator was demonstrated in this review. The presence of extensive correlation, selective source coverage, and sessions crossing the collection boundary were not scored as defects.

## Evidence For Real

- A concrete Windows process agrees across three representations: WS-MCHEN-01 Sysmon Event 1 has PID `7260`, SYSTEM, `svchost.exe -k netsvcs -p -s LanmanServer`, parent services.exe PID `5872`, and LogonId `0x3e7`; Security 4688 has equivalent PID `0x1c5c`; eCAR line 19 carries the same process and parent. The small differences in observed timestamps are plausible source observation differences.
- Sampled Windows images retain their hash sets across repeated launches. On WS-MCHEN-01, the svchost.exe SHA256 `B4083E283A3A584775A3205489BB47B38976DCD9F7767480915E9DFFE4DDB40A` recurs at Sysmon XML lines 409, 1484, 3571, and subsequent occurrences rather than changing per process.
- APP-INT-01 shows a coherent SSH sequence: inbound TCP/22 observation, privileged sshd child, public-key acceptance, PAM session open, eventual PAM close and endpoint termination. Its session is not an isolated authentication row.
- Mac telemetry distinguishes fork from exec. On MAC-MROSS-01, Endpoint Security lines 1–4 show launchd forking PID `42169`, that PID executing xpcproxy, then Terminal, then Terminal forking a child. Successive executable images preserve the original process start time while pidversion advances; these are not incorrectly represented as separate PID lifetimes.
- Windows background-process durations are heterogeneous rather than uniformly short: WS-EBROOKS-01's paired eCAR dllhost lifetimes include approximately 3, 8, 23, 43, 50, 261, and 916 seconds; DC-01's WmiPrvSE lifetimes extend from tens of seconds to many minutes.

## Detailed Analysis

### Scope and method

I examined the supplied data directory only. Representative checks covered WS-MCHEN-01, WS-EBROOKS-01, DC-01, APP-INT-01, WS-LNGUYEN-01, MAC-MROSS-01 and MAC-MROSS-02, with additional targeted Linux records from DB-PROD-01. This was not an exhaustive audit of every host or source. XML line numbers refer to the supplied text files; JSON and history line numbers are physical lines.

I parsed the three selected Windows hosts' Security/Sysmon XML, compared visible logon identifiers and GUIDs, grouped process hashes by image and FileVersion, and checked selected eCAR process identities against subsequent actor activity. Across the seven eCAR files there were 590 visible PROCESS/CREATE records and 546 PROCESS/TERMINATE records. Unequal totals are compatible with processes crossing this bounded window and are not evidence of an error. For nonterminal rows referring to an actor identity, plus process modification identities, I found no reference more than 1.5 seconds after that identity's observed termination. This deliberately tolerates small source timing differences and does not validate all PID-only references.

### Windows process and authentication evidence

The WS-MCHEN-01 process example is reproducible at Sysmon XML lines 394–409 and Security XML lines 538–555. Sysmon's event body `UtcTime` is `2026-11-02 13:07:20.918`; Security's `SystemTime` is `13:07:20.9970862Z`; eCAR line 19 is timestamp_ms `1793624841056` (`13:07:21.056Z`). Decimal PID 7260 equals hexadecimal 0x1c5c, and the image, SYSTEM account, parent and command agree.

Across WS-MCHEN-01, WS-EBROOKS-01 and DC-01, repeated Sysmon Event 1 records showed no conflicting hash set for the same image/FileVersion grouping. For Sysmon creations whose LogonId had a visible Security 4624 counterpart, LogonGuid matched in all checked instances. These checks support internal consistency, not provenance: a synthetic system can also preserve these relationships.

The observed process mix differentiates roles. DC-01 has 133 Security process creations and substantial Kerberos audit activity (404 Event 4768 and 1,090 Event 4769); WS-MCHEN-01 has an administrator-like mix including SSH and mstsc; WS-EBROOKS-01 includes browser and updater activity. Neither a common service command nor repeated COM registration GUID was treated as a synthetic fingerprint by itself.

### Linux SSH and local activity

APP-INT-01 eCAR line 50 observes source `10.10.1.35:61718` to `10.10.2.30:22` at `13:42:52.024Z`. Line 51 creates sshd PID `2939047` at `13:42:56.184Z`. Syslog lines 60–61 accept aisha.johnson's RSA key at `13:43:00.702475Z` and open the PAM session at `13:43:00.878347Z`; eCAR line 52 observes LOGIN at `13:43:02.313Z`. Syslog line 87 closes the session at `14:00:32.390845Z`; eCAR lines 107–108 observe process termination and logout shortly afterward. This is coherent transport-before-auth ordering with plausible observation differences.

Local/background messages are more than generic login lines: APP-INT-01 includes anacron job scheduling, snapd changes, rsyslog queue state, DNS fallback and D-Bus activation. WS-LNGUYEN-01 includes DHCP renewal, NetworkManager, polkit and GDM session messages. I did not require uncollected companion families or assume every service status message needs a visible service start within this window.

### macOS native and normalized evidence

I reviewed all 152 and 151 supplied Endpoint Security rows on the two Macs through targeted summaries and selected records, together with their short Unified Log exports and shell histories. The visible event set contains fork, exec and exit notifications. I did not infer an authorization denial from notification action fields or claim that this export must include every possible ES event type.

MAC-MROSS-01 Unified Log line 2 records a policy message at `15:41:46.250414Z` concerning MeetingAssist PID `62464`. Searching that path/name in this host's supplied ES and eCAR records found no successful child execution. Thus this selected policy observation does not demonstrate a denied execution followed by successful effects. Its sparse Unified Log coverage is neutral under the study's collection assumptions.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| weak_signal | Mac shell histories | Two computers, one named user | Recurrent small diagnostic command vocabulary; slight concern only, with routine behavior and selection as plausible explanations. |
| None demonstrated | Windows, Linux and Mac endpoint lifecycles | Selected hosts and identity checks | No substantiated hard contradiction or contract gap; prevents a high synthetic-confidence score. |

## Realism Score by Category

- **Field format accuracy:** 8 — Parsed native-looking fields are plausible; I did not independently certify every version-specific ES field.
- **Temporal patterns:** 8 — Heterogeneous lifetimes and sensible observed ordering in the sampled relationships.
- **Cross-source correlation:** 9 — Sampled process and SSH identities agree; no score penalty for completeness.
- **Behavioral realism:** 8 — Role-sensitive process mix and operational background activity, with mildly narrow Mac shell vocabulary.
- **Environmental consistency:** 8 — Domain-controller, workstation, Linux and Mac evidence generally fits its apparent platform and role.

## Recommendations

- If this were synthetic, expand Mac shell-command breadth only where the modeled user work actually warrants it; preserve the recurring routines that a real single user would repeat. The current small command vocabulary is a weak texture issue, not a lifecycle defect.
- No evidence-backed lifecycle or source-native repair is established by these bounded checks. Further verification should target additional concrete process/session identities before changing otherwise coherent evidence.
