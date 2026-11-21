# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 80
**Synthetic-Confidence Score:** 64

## Executive Summary

The endpoint evidence is technically coherent and substantially more realistic than a simple collection of fabricated event templates. I lean synthetic primarily because two Macs contain independent groups of shell-command fork notifications with exactly repeated microsecond fractions, supported by repetitive document-access behavior and Linux background-message texture; I did not establish an impossible visible process lifecycle or a Windows cross-source field contradiction.

## Evidence For Synthetic

- [distribution_texture] Two separate native Endpoint Security exports contain triples of distinct shell forks separated by whole seconds but sharing the exact six-digit fractional timestamp. In `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson`, lines 56, 59 and 62 are at `14:37:50.487145000Z`, `14:38:28.487145000Z` and `14:38:57.487145000Z` on November 2; their child PIDs are 34639, 34723 and 34771. The analogous triple in `MAC-MROSS-02.../macos_endpoint_security.ndjson`, lines 89, 92 and 95, occurs at `15:30:55.965208000Z`, `15:31:17.965208000Z` and `15:31:58.965208000Z`, with child PIDs 13190, 13236 and 13310. These are event-envelope times, not inherited process start times. Other timestamps retain varying microsecond fractions, so ordinary export rounding does not explain this localized structure.
- [distribution_texture] On MAC-MROSS-02, all seven regular-file `FILE/READ` observations in eCAR that are distinct from directory listings use `/bin/cat` against PDF, XLSX or DOCX paths. Examples are the ES exec at `13:37:11.214478000Z` for `cat /Volumes/ClinicalResearch/Team/2026/project-plan.pdf`, `16:05:48.676562000Z` for `cat /Volumes/ClinicalResearch/Archive/2025/service-review.xlsx`, and `17:12:27.402087000Z` for `cat /Volumes/Shared/Reference/onboarding.docx`. The behavior is possible, including for collection or automation, but repeated raw terminal reads across several binary document formats look more like a generic file-access recipe than ordinary application use. This is supporting evidence only; selective collection could accentuate it.
- [environment_or_collection_plausibility] Linux background logs give considerable weight to a narrow set of verbose maintenance messages across unlike hosts. APP-INT-01 has 61 `irqbalance` and 64 `snapd` lines among 269 syslog records; LOG-MON-01 has 98 and 73 among 304. WEB-EXT-01 has 114 `irqbalance` and 111 `snapd` lines. Examples include repeated IRQ classification/affinity/balancing messages and snap change/hook/candidate messages, such as APP-INT-01 at `13:03:50.072817Z`, `13:10:50.995761Z`, and `13:21:37.687428Z`. A deliberately verbose collection profile could produce this, but the shared, narrow message grammar and its prominence are a modest synthetic-texture concern, not a native-format impossibility.

## Evidence For Real

- Every one of the 873 visible Sysmon Event 1 process creations across the ten Windows endpoints had a matching Security 4688 by host, PID and executable. For those matches, command line, creator PID and parent image agreed. This supports authentic shared process truth; complete matching is not itself a synthetic indicator.
- Visible process identity and lifecycle checks held up. Across 36,715 eCAR records on 23 endpoints, the checks found no visible process termination preceding that process's own creation and no actor-reference activity more than 100 ms before a visible actor creation or after its visible termination. A separate Sysmon check found no reversed visible create/dependent/terminate ordering using ProcessGUID references and `UtcTime`.
- Windows background trees are recognizable: DC-01 has `services.exe` spawning `svchost.exe -k netsvcs -p -s Winmgmt` at `13:02:10.538`; WS-AJOHNSON-01 has SearchIndexer spawning SearchFilterHost at `13:02:46.142`; FILE-SRV-01 has a csrss-parented console host at `13:08:07.001`. User applications can belong to an explorer process and a specific interactive logon instead of an indiscriminate SYSTEM parent.
- Windows sessions contain meaningful variety. WS-AJOHNSON-01 has successful logon types 2, 3, 5, 7, 9 and 10, plus failed logons, lock/unlock and reconnect/disconnect evidence. DC authentication traffic is much more substantial than workstation authentication traffic.
- The Mac evidence distinguishes forks from successive exec images. MAC-MROSS-01 PID 25527 progresses from a launchd child through xpcproxy to Terminal without inventing a new process for each exec; MAC-MROSS-02 separately represents the iTerm server and ShellLauncher path. Audit tokens, parents, responsible tokens, executable snapshots and execution identities are not flattened into Windows-style process fields.
- SSH authentication varies coherently. DB-PROD-01 shows Maya's ED25519 key, Marcus's ECDSA key, Aisha's RSA key and Lina's password authentication; recurring connections retain the relevant user's key fingerprint. Native SSH messages include source ports that can be followed into eCAR sessions.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory. Its endpoint records cover approximately `2026-11-02 13:00–19:00 UTC` and include ten Windows Security/Sysmon pairs, eleven Linux syslogs, two macOS Endpoint Security exports, shell histories, and 23 eCAR files. I parsed the Windows XML and JSON records, reviewed actual source records, checked host-local process references and lifecycle times, compared Windows process-creation fields, and inspected Linux/macOS session and command examples.

This is a windowed collection. I did not count a missing pre-window parent creation, a surviving end-of-window process, deliberately unselected Sysmon event types, or thin Unified Log coverage as a defect. The native macOS exports identify message `version:11` and `schema_version:1`; without an explicit OS release declaration or external documentation within the permitted scope, I make no allegation about an unfamiliar native field solely from its shape.

### Windows processes, hashes and sessions

The strongest production-like result is agreement on process semantics. For example, WS-MCHEN-01 Sysmon Event 1 at `13:03:50.517` records Firefox PID 7184, explorer parent PID 6780, user `MERIDIANHCS\marcus.chen`, logon `0x6c29844` and terminal session 5. Its eCAR `PROCESS/CREATE` at timestamp_ms `1793624630631` carries the same PID, parent, executable, user and command URL. The small timestamp difference is compatible with independently observed source timing.

Across all ten Windows hosts, the comparison found 873 matching Sysmon process creations and 877 Security process creations. The four Security-only creations are not a scoring issue: source filtering or observation loss is plausible, and I did not infer a contradictory collection contract. Matched records had no differences in the three checked command/parent fields. Hash sets were stable per image within each host, and grouping identical full hash strings across hosts found no conflicting `FileVersion` values. Stable hashes alone do not prove the bytes exist, but no internal binary-version contradiction emerged.

The Windows session mix also avoids the usual all-interactive or all-network flattening. WS-AJOHNSON-01's 22 successful logons comprise twelve type 3, six type 5 and one each of types 2, 10, 9 and 7. Its older interactive session can end at `13:33:28.8578097Z` while a new type 2 session begins at `14:00:45.4986710Z`; the older session's initiation need not fall inside the slice. I found no basis to call that a missing-lifecycle defect.

The checks do not validate every Windows audit field against an external provider manifest, and they do not establish the correctness of every authentication relationship. They do establish that the obvious host-local creation/reference/termination contradictions are absent from the tested relationships.

### macOS native event timing and execution semantics

The repeated-fraction groups are the finding carrying the most weight. On MAC-MROSS-01, the first group forks a shell child for `bash .../connector-check.sh --check-network`, then children for `cat /etc/resolv.conf` and `cat /etc/hosts`, at exact offsets of 38 and 29 seconds while retaining `.487145`. Their corresponding exec observations occur at `14:37:50.504588000Z`, `14:38:28.502088000Z`, and `14:38:57.502372000Z`; those exec fractions vary. Thus the suspicious repetition is specifically in the initiating fork times, not an across-the-board timestamp resolution limit.

On MAC-MROSS-02, a separate trio forks `dscl`, `find`, and `du` children from `/bin/zsh` at offsets of 22 and 41 seconds with the shared `.965208` fraction. These are the only repeated fractional-time groups among the 102 visible ES fork notifications across the two hosts. A replay or scheduled driver could create time structure, so this is not logically impossible. However, two localized triples with unchanged microsecond precision, surrounded by varying precision, strongly suggest event batches anchored once and advanced by integer seconds. This conclusion concerns timestamp distribution, not whether the activity tells a tidy story.

Other Mac details deserve credit. The local terminal chains differ appropriately between Terminal and iTerm, and eCAR represents exec as `PROCESS/MODIFY` with previous/current execution and image identities. The incoming SSH path on MAC-MROSS-01 progresses through xpcproxy, sshd-keygen-wrapper, sshd, sshd-session, an auth helper, and a user shell. Unified Log at `16:02:08.147068+0000` records accepted public-key authentication from `10.10.1.42:53621`; the shell exec follows at `16:02:08.299168000Z`.

The `15:42:09.009673+0000` AppleSystemPolicy message refers to a rejected MeetingAssist executable. I found no matching successful MeetingAssist process in that host's eCAR evidence. I did not reinterpret the policy message as successful execution or count an absent child as a defect. Likewise, the inventory plist creation/removal records do not alone establish job registration or unload; I did not demand that removal terminate a loaded job.

### Linux sessions, histories and background texture

Linux evidence contains meaningful host and user differences. DB-PROD-01's Lina history includes PostgreSQL, MySQL and Redis administrative commands, while WS-LNGUYEN-01 contains git/build work. Other users execute shorter troubleshooting sequences. Root's database history includes a mysqldump, gzip and scp sequence; its suspiciousness does not make it synthetic evidence.

APP-INT-01 syslog at `13:21:15.251527Z` accepts Priya's key from `10.10.1.32:54546`; eCAR records the SSH login at timestamp_ms `1793625676995` and logout at `1793628094516` with the same tuple and logon `0x15171006`. The different authentication/session timestamps are plausible separate stages. Existing SSH sessions closing near the beginning of the slice are also plausible.

Cron's approximately ten-minute sysstat entries are expected automation, so their periodicity is not a synthetic finding. The weaker concern is instead the prominence of a shared verbose IRQ/snap vocabulary in several server syslogs: those two programs account for 46% of APP-INT-01 and 56% of LOG-MON-01 records. This might be a real logging configuration, and the record counts alone are insufficient to prove otherwise. I assign it much less weight than the native Mac timing pattern.

### Balance of evidence

There is no demonstrated hard contradiction in this review. The distribution findings make synthetic the more likely origin, but the intact host-local semantics keep the score near the lower end of the likely-synthetic band. The evidence would not justify an 81–100 score or a claim that the endpoint records are broadly unusable for forensic analysis.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| distribution_texture | Native macOS Endpoint Security | Two independent three-fork groups on two hosts, six of 102 fork notifications | Primary indicator: localized exact microsecond reuse with whole-second offsets despite varying surrounding timestamps |
| distribution_texture | macOS ES/eCAR file access | Seven regular-file reads on MAC-MROSS-02 use cat on Office/PDF formats | Supporting behavioral repetition; possible scripted collection and selection bias limit weight |
| environment_or_collection_plausibility | Linux syslog | IRQ/snap messages prominent on several unlike servers | Small increase: narrow verbose service texture; legitimate logging policy remains an alternative |

## Realism Score by Category

- **Field format accuracy:** 9 — Parseable native-looking structures, consistent Windows process fields and hashes, and distinct native Mac execution snapshots; no verified native-schema contradiction.
- **Temporal patterns:** 6 — Lifecycles are coherent, but two localized exact-microsecond fork triples are a strong distribution artifact.
- **Cross-source correlation:** 9 — All 873 visible Sysmon process creations match Security process semantics, with coherent sampled eCAR and SSH relationships.
- **Behavioral realism:** 7 — Role-specific tools and session variety are good; repeated cat-based binary-document access weakens ordinary user texture.
- **Environmental consistency:** 8 — Platform-specific process/session paths hold together; verbose Linux maintenance-message prominence is a limited concern.

## Recommendations

- If this were synthetic, derive native fork times from each command's actual modeled dispatch rather than preserving a batch anchor's fractional second while adding integer offsets. Retain legitimate bursts and automation, but make their clock/dispatch behavior coherent with the claimed source precision.
- If this were synthetic, give routine Office/PDF access on MAC-MROSS-02 a reason appropriate to the command and user workflow. Preserve raw cat reads where inspection or collection is intended; use application or file-transfer behavior for other reads instead of applying one shell recipe to every document format.
- If this were synthetic, tie verbose IRQ/snap messages to explicit daemon states and collection verbosity. The observed counts and shared message grammar should reflect a defensible logging configuration across the affected servers.
- Preserve the present process/session identities, per-source timestamps, cross-source process fields, distinct fork/exec semantics, SSH authentication variation, and window-boundary behavior; those are substantial strengths.
