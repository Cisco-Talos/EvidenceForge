# Verdict

- **Assessment:** Inconclusive
- **Verdict Confidence:** 78/100
- **Synthetic-Confidence Score:** 36/100 (low indicates production-like)

## Executive Summary

The reviewed host evidence is substantially coherent across Windows Sysmon/Security and eCAR, Linux syslog/shell history and eCAR, and macOS Endpoint Security and eCAR. I found no clear impossible process-parent ordering, process termination before creation, or paired session logout before login in the inspected records. Representative Windows Sysmon process create/terminate events correlate with same-action eCAR events within one second on nearly all reviewed hosts; visible parent-process references also agree on image, PID, and ordering.

The material limitation is coverage: both Macs have only 2–3 Unified Log rows despite 122/186 Endpoint Security rows, and several host files are filtered to a narrow set of event classes. That can fit a deliberately scoped collector, so it does not establish synthetic origin. Endpoint, session, and shell evidence is too internally plausible to support a confident synthetic verdict; the available host-only sample also cannot establish production provenance.

## Evidence For Synthetic

### hard_contradiction

- None found in the representative host evidence reviewed. No observed within-window process or session sequence required a pre-window or post-window event to explain an impossible ordering.

### contract_gap

- No proven lifecycle contract violation. Some process creates or terminations lack a counterpart in the same six-hour slice, but the direction and timing are compatible with events outside the slice or source-level filtering. These are not counted as defects.

### distribution_texture

- macOS Unified Log coverage is extremely thin: 3 rows on `MAC-MROSS-01` and 2 on `MAC-MROSS-02`, while their Endpoint Security files contain 122 and 186 rows. This is a collection-shape concern only; the separate streams can have different predicates and retention.
- The sampled Windows host streams contain a narrow, repeated event mix (notably Sysmon network connections plus process create/terminate and Security filtering/process/authentication events). Selective collection can produce this shape; the data alone do not show it is impossible.

### schema_or_format

- No material host-record format defect found in the inspected XML/JSON/NDJSON samples. Windows XML fields are well-formed and use source-native event IDs; macOS Endpoint Security records include event-specific payloads; Linux syslog uses RFC 5424-like records.

### environment_or_collection_plausibility

- The small Unified Log row count is the primary plausibility concern. It is not enough to distinguish aggressive filtering from synthetic sparsity without collector configuration or an expected collection contract, which were outside this blind review.

### weak_signal

- High cross-source alignment is visible, but it is explicitly not treated as a synthetic clue by itself. Shell-history commands, Linux login/session messages, Endpoint Security activity, and eCAR activity often agree in time and actor. No copied-mtime claim is made.

## Evidence For Real

- Across the ten Windows hosts with Sysmon files, event ID 1 creates and event ID 5 terminations were consistently ordered when paired by ProcessGuid; there were **no observed termination-before-create pairs**. Unpaired records are plausible at six-hour boundaries or under source filtering.
- On the Windows hosts, 1,661 of 1,677 sampled Sysmon process create/terminate records had an eCAR record with the same PID and action within three seconds; almost all matched within one second. The small unmatched set does not violate lifecycle semantics and may reflect source observation differences.
- In a check of visible Sysmon parent events, 146 children had a parent create record present in the same slice. Those visible parent links had no parent-after-child timestamps, parent PID discrepancies, or parent-image discrepancies. Parent events outside the slice were not treated as missing evidence.
- eCAR session pairs sharing an object ID were chronological in the inspected hosts; paired records had matching logon/session attributes where those attributes were present on both sides. No paired logouts preceded their logins.
- Windows Security and Sysmon streams cover plausible complementary evidence: Security 4688/4689 roughly tracks Sysmon process create/terminate; 4624/4634 and 4768/4769 provide authentication context; 5156 is prominent on hosts with filtering-platform activity. A one-for-one count is not expected for independently filtered sources.
- Linux host evidence uses plausible source semantics: `sshd` connection/accept/PAM session-open and systemd-logind session creation appear in a coherent order; `sudo` command and PAM session records agree on command/user and open/close timing. A representative DB login used a source IP/port consistently across SSH acceptance and session records.
- Linux shell history contains timestamped commands consistent with the host role and observed tools. It is supporting context only; shell history is not a complete execution audit trail.
- macOS Endpoint Security event types 9/11/15 carry exec/fork/exit-specific payloads. Fork parent identity, child parent identity, and event ordering were coherent in inspected examples. Global sequence numbers were unique, increasing, and contiguous in the supplied rows; per-event sequence values varied plausibly by process.
- Process and session evidence is not uniformly complete across hosts, which is compatible with endpoint telemetry selection and ordinary window truncation.

## Detailed Analysis

### Windows: process tree and lifecycle

The review covered `DC-01`, `DC-02`, `FILE-SRV-01`, `MAIL-FIN-01`, and five Windows workstations. Sysmon event IDs 1 and 5 had 1,677 combined records across these hosts. Joining by ProcessGuid produced no termination timestamp earlier than the corresponding create. Create-only and terminate-only ProcessGuids were present, especially on user workstations, but those one-sided edges are consistent with a six-hour slice and cannot be called defects without an impossible visible ordering.

For child process events whose ParentProcessGuid resolved to another visible create, I compared ParentProcessId and ParentImage with the referenced parent record and checked timestamps. All 146 resolved links agreed. Representative trees included ordinary shell/Explorer-launched user tools and service/COM processes launched by `svchost.exe`; visible parent details were consistent.

### Windows: eCAR and Security alignment

The eCAR stream has event objects/actions and process identity fields. Per-host process create/termination volumes broadly track Sysmon, and timestamp joins by PID/action were close. Security event volumes are larger or smaller by class as expected from differing providers and collection policies; Security 4688/4689 and Sysmon process events mostly track one another without demanding exact equality. Authentication examples include network and service logons, privileged logons, Kerberos ticket activity, and paired termination evidence.

No observed session pair had a logout before login. Where an eCAR session ID had both endpoints under the same object ID, common attributes such as logon ID, session ID/type, and tuple fields agreed when present. Separate IDs for non-paired attempts or sessions were not merged based on username alone.

### Linux: syslog, shell history, and eCAR

Representative Linux hosts (`FILE-LNX-01`, `DB-PROD-01`, `WEB-EXT-01`, and `WS-LNGUYEN-01`) show RFC 5424-style records with host, process, PID, and message. The reviewed SSH sequences have connection and authentication evidence before PAM session open, with systemd-logind session creation shortly afterward. `sudo` command records are followed by PAM session-open and then session-close records. These are source-appropriate semantics and maintain plausible temporal ordering.

Shell histories have timestamp formats appropriate to Bash (`#epoch` lines) and Zsh (`: epoch:duration;command`). The commands are plausible for the host/user context. They support local activity interpretation but do not prove that every command generated a retained process event.

### macOS: Endpoint Security and Unified Log

Both Endpoint Security files contain source-shaped records with audit tokens, executable paths, PPIDs, start times, action results, and type-specific `event.exec`, `event.fork`, or `event.exit` objects. In inspected examples, fork child `parent_audit_token.pid` matched the forking process PID; exec payload target PID matched the process PID; event time followed process start time. Unified Log records have plausible loginwindow subsystem/category/message fields, but there are too few rows to evaluate its distribution or richly corroborate the Endpoint Security activity.

### Scope and limitations

This is a host/EDR-focused review of the supplied six-hour slice only. It does not assess network sensors, scenario intent, ground truth, collection configuration, or artifact provenance. Absence of pre-window initiators/post-window endings, copied mtimes, complete cross-source alignment, sanitized names/domains, and volume alone were not treated as proof of synthetic data.

## Synthetic Indicator Summary

| Category | Finding | Strength |
|---|---|---:|
| hard_contradiction | None observed | 0/100 |
| contract_gap | No proven in-window lifecycle violation | 5/100 |
| distribution_texture | Very sparse macOS Unified Log stream; filtered host event mixes | 28/100 |
| schema_or_format | No material defect observed | 3/100 |
| environment_or_collection_plausibility | Unified Log coverage merits collection-context review | 25/100 |
| weak_signal | None beyond coverage and controlled-looking alignment; alignment not counted by itself | 12/100 |

## Realism Score by Category

Scores represent host-evidence realism in the observed slice; they are not probabilities of provenance.

| Category | Score / 100 | Basis |
|---|---:|---|
| hard_contradiction | 96 | No impossible in-window process/session ordering found. |
| contract_gap | 90 | Process and session lifecycle behavior is coherent; boundary truncation explains one-sided pairs. |
| distribution_texture | 68 | Windows/Linux activity is varied and role-plausible; macOS Unified Log coverage is very thin. |
| schema_or_format | 94 | Native-looking source formats and type-specific event payloads. |
| environment_or_collection_plausibility | 76 | Host behavior is plausible, with limited ability to judge Mac Unified Log collection scope. |
| weak_signal | 82 | No strong standalone synthetic indicator; broad alignment is not penalized. |

## Recommendations

- Preserve the current host data with the collector predicates and retention boundaries documented alongside it, especially for the macOS Unified Log stream.
- If fuller macOS corroboration is required, collect a wider or explicitly scoped Unified Log sample and record the predicate/coverage window; do not infer absence from this 2–3-row excerpt.
- For future authenticity reviews, retain source-local process/session identifiers and event timestamps so process GUID/PID and logon/session joins can be independently audited.
- Keep window-boundary context available to reviewers where permitted, so one-sided create/terminate records can be distinguished from missing in-window lifecycle evidence.
