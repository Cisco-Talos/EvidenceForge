# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 63

## Executive Summary

The endpoint data is substantially realistic: Windows process identities and executable metadata agree across sources, visible process lifetimes are internally consistent, and Linux authentication includes credible transport/authentication/session stages. My synthetic verdict rests primarily on a reproducible timing fingerprint in the native-looking macOS Endpoint Security stream: seven successive-command transitions land exactly 1,000 microseconds after a preceding child exit, followed by a shutdown chain spaced at exactly one microsecond. This is a localized distribution artifact, not a demonstrated impossible lifecycle; the strong Windows/Linux consistency limits the score and confidence.

## Evidence For Synthetic

- [distribution_texture] `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson` contains seven exit-to-next-fork gaps of exactly 1,000 microseconds for shell PID 21359. The line pairs are 18→19, 21→22, 24→25, 85→86, 88→89, 94→95, and 97→98. For example, PID 21390 exits at `13:37:33.437983000Z` and its parent forks the next command at `13:37:33.438983000Z`; PID 44283 exits at `15:48:48.136163000Z` and the next fork occurs at `15:48:48.137163000Z`. These are repeated exact intervals despite preservation of six meaningful fractional-second digits, involving different commands and two separated activity clusters.
- [distribution_texture] The same file's lines 170–172 serialize three process exits one microsecond apart: `/bin/cat` PID 65753 at `18:56:58.339699000Z`, `/bin/zsh` PID 21359 at `.339700000Z`, and `/usr/bin/login` PID 21358 at `.339701000Z`. Their `mach_time` values are respectively `56501240152776`, `56501240152800`, and `56501240152824`. The matching fixed-step changes in both clocks strengthen an inference of constructed ordering. I treat this as a second manifestation of the same timing-texture problem, not an independent hard contradiction.

## Evidence For Real

- Windows process evidence has stable identity and metadata. Across all supplied Sysmon streams, references to a process GUID matched its visible creation's PID and image, and no checked reference occurred before that creation or after that GUID's visible termination. This check used GUIDs rather than treating reused numeric PIDs as identical processes.
- Security 4688 and Sysmon 1 agree on executable path, command line and resulting account for all matched creation PIDs checked across the ten Windows hosts. No mismatch was found after accounting for a nonzero 4688 target account when present.
- Executable hash tuples remain stable across repeated observations. All checked encoded hashes have the expected lengths: 1,114 SHA1 values of 40 hexadecimal characters, 1,114 MD5 values of 32, 1,114 SHA256 values of 64, and 1,105 IMPHASH values of 32. Repeated SHA256 values did not acquire conflicting full hash tuples or visible file versions.
- Windows endpoint activity differentiates users and machines. WS-MCHEN has 19 PowerShell, 10 SSH and 7 RDP-client process creations, whereas WS-DRAMIREZ shows application maintenance/search activity such as eight AdobeARMservice, six SearchFilterHost and five SearchProtocolHost creations. This is more credible than giving every user the same tools and counts.
- APP-INT syslog lines 3–5 retain SSH daemon PID 2931388 and source tuple `10.10.1.35:65202` through connection, accepted public key and PAM session opening, at `13:00:15.633505Z`, `13:00:22.231675Z` and `13:00:22.298841Z`. The same daemon logs session closure at `14:01:11.365187Z` on line 47.
- The Mac streams distinguish fork from same-PID executable transitions. MAC-MROSS-01 lines 1–7 show launchd → xpcproxy → Terminal, then a distinct child executing login, then its child executing zsh. MAC-MROSS-02 lines 3–12 show a different iTerm/iTermServer/ShellLauncher path. The graphs do not simply equate an exec with a fresh process lifetime.

## Detailed Analysis

### Scope, provenance and method

My filesystem inputs were the supplied neutral briefing and files under `/private/tmp/log-study-vn4mfwps/data`. I did not inspect repository files, scenarios, previous assessments, other reviewers' results, or parent-directory inventories. Inherited project-oriented operating instructions were treated as an environment limitation and were not evidence of origin. Parsing used system `python3` with `/private/tmp` as the explicit working directory.

The examined endpoint inventories contain 37,394 eCAR rows, 19,411 Security XML events, 12,058 Sysmon XML events, 4,291 syslog lines, 299 Endpoint Security records and five Unified Log records. I parsed all supplied Windows XML and all eCAR rows for identity/lifecycle checks, examined representative native records, and inspected both complete Mac Endpoint Security process timelines. Shell histories were used as supporting behavioral observations. This is an endpoint review; I do not claim exhaustive network/protocol assessment.

I consulted official Microsoft documentation and Apple's upstream XNU files while checking platform semantics. No task-project pages or prior-assessment material were accessed. In particular, I did not turn unfamiliar audit-token generation details into an alleged defect: Apple's implementation compares process identity against PID/version, but that does not justify assuming that every numeric version in a filtered export must form a globally monotonic sequence. See the upstream [Apple process-identity implementation](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/kern/kern_proc.c).

### Windows identity, tree and logon checks

All ten Windows hosts' Security and Sysmon XML files parsed successfully. The Windows process test indexed visible Sysmon 1 creations and Sysmon 5 terminations by ProcessGuid, then checked image/PID consistency and event ordering for ProcessGuid, source/target process references, and visible parents. No inconsistency was found. An independently normalized eCAR check also found no non-process evidence using an actor more than 50 milliseconds before its visible creation or after its visible termination, and no child being created by a visibly terminated parent under the same actor identity. The 50-millisecond tolerance in that eCAR test avoids turning source timestamp rounding into a lifecycle allegation.

Concrete native records include `WS-MCHEN-01.meridianhcs.local/windows_event_sysmon.xml`, record 525219, whose EventRecordID appears at line 1293. It creates winlogon PID 7264 at `13:33:45.856`, with SYSTEM identity and terminal session 6. Record 525221, identifier at line 1369, creates userinit PID 7292 at `13:33:47.331` under that winlogon GUID, with user `MERIDIANHCS\marcus.chen` and LogonId `0x6c75d51`. The sequence is a credible transition from system-owned logon machinery to the user environment.

There are meaningful logon-type differences. DC-01 has 147 Type 3, 121 Type 5 and four Type 10 successes; WS-MCHEN has 22 Type 3, six Type 5, two Type 2, two Type 7 and two Type 9 successes. Service records use the appropriate built-in accounts: for example DC-01 record 28246062, identifier at Security XML line 13892, is a Type 5 NETWORK SERVICE logon with SID `S-1-5-20`, LogonId `0x3e4`, and services.exe caller. Repeated well-known service identities were not mistaken for newly allocated ordinary-user logon sessions.

The supplied sources include workstation lock/unlock evidence and remote-session behavior. I did not penalize missing initiators before the slice, missing closure after it, selected-out Sysmon types, or the small differences in creation counts among collectors. The visible account and binary agreement is positive realism evidence; its completeness is not a synthetic indicator.

### Linux sessions and background processes

The APP-INT example above has a sensible separation between transport arrival and authentication. Its session duration is about 61 minutes rather than a fixed instantaneous login/logout pair. Other visible Linux process chains distinguish an unprivileged sudo caller from a root child: DB-PROD eCAR lines 7–8, for example, show lina.nguyen launching sudo PID 1043736 followed by root `/bin/systemctl is-active sshd` PID 1043737 with sudo as parent. Such process ownership is much better evidence than merely having plausible command strings.

Background activity includes cron/sysstat, anacron, systemd units, package maintenance, resolver fallback messages, SSH, and Samba workers where relevant. FILE-LNX has many smbd children, whereas the proxy and web machines have correspondingly heavy flow activity. I did not require every syslog message to have a corresponding collected process event: source coverage does not establish exhaustive kernel process auditing.

Recurring diagnostic commands and shared administrative tools can follow organizational practice. Their existence was not enough to add a separate command-pool penalty, particularly where the same named administrators operate across hosts.

### macOS process semantics and timing

MAC-MROSS-01 has 38 fork, 44 exec and 37 exit notifications; MAC-MROSS-02 has 57 fork, 67 exec and 56 exit notifications. Greater exec than fork counts are compatible with successive images within a lifetime. Browser helpers retain recognizable renderer, GPU and network-service roles. TTY/session metadata and terminal-specific process chains provide detail beyond a generic Unix process list.

The strongest anomaly is nevertheless in this family's event timing. For MAC-MROSS-02, I retained the latest visible child exit per parent and measured the interval to a subsequent fork by that parent. Seven gaps hit exactly 1,000 microseconds, all with parent shell PID 21359. Three appear together around `13:37:33`; four appear around `15:48:46–48`. Other small measured gaps are 2,998 and 21,574 microseconds, so the source is not simply rounding every interval to a one-millisecond bucket. MAC-MROSS-01's equivalent smallest gaps were 8,462 and 32,454 microseconds, without the same sevenfold floor.

The distinction matters: a batch of sequential commands is realistic and is not itself penalized. A repeated exact delay at microsecond timestamp precision, replicated in the native Mach clock and followed by exact one-microsecond process-exit stepping, supplies the specific distribution evidence. It resembles a scheduling or serialization floor in constructed timestamps. I cannot establish from these records alone whether an export/postprocessing step, rather than original event generation, imposed the floor; this is why I do not call it an impossible native event or score in the 81–100 band.

The endpoint policy message on MAC-MROSS-01 Unified Log line 2 says security policy would not allow a MeetingAssist process. I did not infer successful execution, descendants, or successful command effects from that message. Likewise, the inventory plist's eCAR creation/deletion is file evidence; deletion alone does not prove job unload, and a subsequent inventory execution is not automatically contradictory. Thin Unified Log coverage is neutral.

### Balance of evidence

The data withstands the most useful visible-identity tests, which argues against a crude fabricated dataset. The synthetic assessment is driven by a concentrated, reproducible native-timing fingerprint rather than attack narratability, clean cross-source matching, sanitized names, sparse sources, or ordinary slice boundaries. A production export with a documented timestamp-adjustment rule could account for the principal anomaly and would materially reduce my synthetic-confidence score.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | macOS Endpoint Security | MAC-MROSS-02, seven child-exit → parent-fork transitions in two clusters | Main upward driver: exactly 1,000 microseconds repeatedly despite finer event precision and diverse commands |
| distribution_texture | macOS Endpoint Security | MAC-MROSS-02, lines 170–172 | Supporting manifestation of the same timing problem: exits advance by exactly one microsecond and Mach time advances by exactly 24 ticks each time |

No hard contradiction, generator identity leak, demonstrated invalid native event type, or visible same-identity use-after-exit is established in this review. The two rows above are related and were not scored as independent failures across multiple platforms.

## Realism Score by Category

- **Field format accuracy:** 9 — XML/NDJSON parse cleanly, Windows hash encodings and process metadata are consistent; no unverified Mac enum assertion is penalized.
- **Temporal patterns:** 6 — Overall ordering is sound, but the repeated exact Mac transition delays and finalization steps look constructed.
- **Cross-source correlation:** 9 — Matched Windows process paths, commands and accounts agree, and GUID/actor lifecycle checks found no visible contradiction.
- **Behavioral realism:** 8 — User/tool differences, terminal-specific process chains, privileged subprocess ownership and background work are convincing.
- **Environmental consistency:** 8 — Server/workstation activity has credible differences; selected source coverage and time-slice boundaries remain neutral.

## Recommendations

- If this were synthetic, preserve the actual variability of command completion, parent wakeup and next process creation instead of applying the repeated 1,000-microsecond transition floor seen in MAC-MROSS-02. Test the resulting distribution across unrelated commands as well as individual timelines.
- If this were synthetic, model child completion and parent cleanup without manufacturing exact one-microsecond stepping in both wall-clock and Mach timestamps. Retain causality while allowing realistic event acquisition and scheduling variation.
- If the timestamps were adjusted during collection/export, document that adjustment with the dataset. A declared ordering transformation would allow reviewers to distinguish native execution timing from postprocessed event ordering and reassess this localized finding.
