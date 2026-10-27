# Deliberation Summary

## Status, method, and scope

This is a facilitator's structured cross-examination of four completed independent reports. It is not a transcript of a discussion. No reviewers were contacted, no additional statements or revisions were elicited, and no new reviewer consensus is claimed. The initial verdicts and scores below remain the reviewers' actual submitted positions. Any assessment attributed to the facilitator is a synthesis of those reports and the explicitly described verification, rather than a fifth independent authenticity review.

Method guidance was limited to `expert-deliberation.md`. Evidence was limited to the four reports and the supplied dataset. The facilitator independently recounted only the reported connection-history, TLS-history, and NTP-reference-ID findings in `dataset/office-span/{conn,ssl,ntp}.json`, using read-only parsing and bounded example output. Official Zeek documentation and versioned Zeek source were consulted to check those fields' meanings. Endpoint findings and positive cross-source checks below are attributed to the reports; they were not independently rerun during facilitation. No repository code, scenarios, ground truth, evaluation output, previous studies, actual host state, or private captures were read. No recorded command was executed, and no host/service collection or probes were performed. Source data was not changed.

The supplied records cover roughly six hours, 13:00–19:00 UTC on 20 October 2026, across four endpoints and one network sensor. Source coverage is selective. The network reviewer examined network files only; the other reviewers examined wider endpoint/network selections. The Zeek release, custom logging policy, and any post-collection transformations are not specified. These limits matter when comparing the reports.

## Panel Composition — Round 1: submitted positions

Scores are shown separately. Verdict confidence and synthetic-confidence are different quantities; they are assessor judgments, not calibrated probabilities, and are not averaged or multiplied here.

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|---|---|---:|---:|---|---|---|
| Threat Hunter | Synthetic | 78 | 64 | Not elicited | Not elicited | Not elicited |
| Detection Engineer | Synthetic | 96 | 92 | Not elicited | Not elicited | Not elicited |
| Network Forensics | Synthetic | 95 | 90 | Not elicited | Not elicited | Not elicited |
| Host/EDR Forensics | Inconclusive | 82 | 56 | Not elicited | Not elicited | Not elicited |

### Threat Hunter

The threat hunter's synthetic lean rests on application and behavioral plausibility rather than a demonstrated impossible lifecycle. Their principal observations are overlapping same-user Chrome browser roots that each acquire renderer children without visible profile separation; repeated multi-second lifetimes for trivial macOS commands; and four browser-shaped HTTP requests attributed by exact tuple joins to Windows `svchost.exe -k netsvcs` under `NETWORK SERVICE`. A narrow approximately 21-minute cadence for varied SMB document activity is a smaller supporting signal.

Unique contributions include the browser-instance interpretation and the HTTP-to-process ownership joins. Positive findings include usable SSH and SMB pivots, coherent process lifecycles, stable certificate identities, and distinct local versus directory account scopes. The report explicitly preserves hidden configuration, legitimate automation, and collector-selection alternatives.

### Detection Engineer

The detection engineer's high-confidence synthetic verdict rests on two native-field contradictions: TLS histories assign server messages to client direction in 686 of 689 rows, and 352 of 873 TCP histories repeat markers Zeek records at most once in each direction. These are semantic problems even though the strings and JSON parse successfully.

Their distinctive contribution is broad source/schema checking alongside the defects: all 7,953 supplied JSON/NDJSON rows reportedly parse, Windows event fields have credible event-specific forms, process references remain within visible lifetimes, and protocol/certificate references join. macOS fork/exec identity handling is specifically credited. The report allows downstream corruption of real logs as an alternative to synthetic traffic origin.

### Network Forensics

The network reviewer reaches a similarly strong synthetic verdict from the same two history defects, plus a third, smaller source-format finding: all 12 NTP rows combine `stratum=2` with `ref_id=".GOOG."`. Their analysis is confined to 4,204 network records, so it does not independently validate or reject endpoint behavior.

Unique positive observations include DNS query/negative-answer diversity, plausible DNS-to-TLS ordering, stable certificate chains and fingerprints, coherent file direction/size, and application-dependent flow duration. The reviewer also identifies three ClientHello-only TLS histories carrying a selected version, treating that as reinforcement of the TLS issue rather than a fourth independent major finding.

### Host/EDR Forensics

The host reviewer remains inconclusive with a modest synthetic lean. Thirteen paired macOS diagnostic lifetimes are reported as 4.328–36.433 seconds, median 15.789 seconds, with no subsecond examples. Native Endpoint Security corroborates an 18.931068-second `id` execution. A separate Windows UserAssist value changes execution count 9 → 4 → 72 under the same recorded PID and actor UUID.

Their distinctive positive contributions are all 146 Windows Security 4688 creations matching Sysmon Event 1 counterparts, stable per-executable Sysmon hashes, careful macOS fork/exec and credential transitions, and source-specific Linux SSH/sudo ownership. They classify neither delayed diagnostics nor a writable registry-counter regression as an impossibility. A real stall, profile restore/reset, direct overwrite, or exporter behavior remains possible.

## Key Agreements

These are overlaps in the submitted reports, not newly elicited votes.

- **Operational correlation is a strength.** All four reports describe coherent references within their examined surface. Detection and host reviews report credible durable process identities; threat and host reviews describe usable SSH ownership and ordering; network and detection reviews find coherent UID/tuple and certificate references. These positive findings reduce claims of indiscriminate fabrication while leaving individual field defects intact.
- **The two Zeek history findings have independent reviewer support.** Detection and network reviewers identify the same affected records and the same documented semantic rules. Their shared evidence supports replication, but is not counted twice as two independent datasets or two independent sets of defects.
- **macOS diagnostic duration is a repeated concern with an alternative explanation.** Threat and host reviewers independently highlight the pattern and native ES corroboration. Neither calls a long-running command intrinsically impossible.
- **Collection limits are material.** All reports avoid scoring absent optional source families, pre-window starts, post-window closes, sanitized naming, source completeness, or the ease of reconstructing a narrative as synthetic indicators.
- **Useful data and authentic native fields are separate questions.** Good joins, process trees, and protocol sequencing support practical hunting. They do not establish that every source-native field has the meaning an analyst or detection rule expects.

## Key Disagreements — Round 2: cross-examination

### 1. High-confidence synthetic judgments versus an inconclusive endpoint judgment

This is chiefly a difference in evidentiary coverage and weight. The host reviewer does not claim to have disproved the network defects; their strongest endpoint findings retain real-world explanations. Conversely, valid Zeek-field criticisms do not invalidate the credited endpoint identity relationships. The threat hunter's statement that no unconditional native-field contradiction was established in their review is not evidence that the detection/network findings are false.

Facilitator assessment: the network findings provide stronger evidence against an untouched native Zeek export than the endpoint texture findings provide against real endpoint execution. That is an evidence-strength comparison, not a retroactive change to any reviewer's score or verdict.

### 2. Parsing success versus field authenticity

The threat and host reports give field-format realism 9/10, detection gives 7/10, and network gives 5/10. Their scopes and emphases differ: structural JSON/XML validity and endpoint identifier forms can be strong while particular Zeek strings violate their accumulation or direction rules. The favorable parsing results and unfavorable native-history results are compatible. A syntactically valid string is insufficient validation for a semantically defined field.

### 3. The transformation alternative

Both high-confidence reports acknowledge that real traffic could have been exported through a transformation that uppercases TLS histories or reconstructs connection histories incorrectly. The supplied material does not document such a transformation. The verified conclusion is that these field representations are incompatible with the checked native Zeek semantics. Synthetic origin remains an inference from that evidence; the finding does not prove that the underlying packets or host activity never occurred.

An unknown release or logging policy warrants checking actual provenance if available. It does not, on its own, explain systematic case loss or repeated once-only flags. Conversely, sanitized domains do not explain either defect and are excluded from the assessment.

### 4. Endpoint plausibility and genuine alternative explanations

The slow-command cohort is stronger than a single anomalous runtime, and native ES corroboration weakens an explanation based solely on an eCAR timestamp offset. It still lacks CPU, scheduling, blocking, security-scanning, or exporter evidence that would exclude genuine stalls. No runtime threshold is promoted to a hard contradiction.

The Chrome finding is more specific than merely observing multiple Chrome processes: later browser roots create renderer children while the earlier root lives. Hidden profile configuration or a custom launch mechanism remains unobserved, so absence of `--user-data-dir` in the visible command alone is not conclusive.

The service-owned HTTP observations use exact tuple joins, which is stronger than inferring ownership from a user-agent string. A service can nevertheless fetch arbitrary pages using a browser user agent; missing service configuration limits the conclusion to a repeated unlikely association.

The UserAssist regression concerns one persistent value and one recorded actor identity, which makes it more informative than comparing different users or values. Registry state is writable and restorable, so an unexplained regression is a state-continuity concern, not an immutable-counter violation.

### 5. Periodicity, human activity, and the observation window

The threat hunter's narrow SMB cadence concerns varied user-document operations, whereas the host review accepts periodic sysstat cron and the network review finds varied aggregate traffic. Those positions are compatible: periodic system work is legitimate, and variable fleet traffic does not establish the cadence of one user's activity. An indexer or sync utility could explain the SMB pattern. Six hours cannot establish full-day, overnight, or weekly behavior, and the cadence receives only modest weight.

## Bounded Verification and Original Hard Findings

The facilitator independently parsed 1,771 connection rows, 689 TLS rows, and 12 NTP rows. Physical line references below are one-based JSON-record lines under `dataset/office-span/`.

| Finding | Independent recount | Representative evidence | Disposition |
|---|---|---|---|
| Repeated once-only TCP history markers | 352 of 873 TCP rows (40.3%) repeat at least one of `a/A/d/D/i/I/q/Q`; all 352 repeat `a`, and 287 also repeat `D` | `conn.json:1`, UID `CFC20K6LLHisX5lUJlx`, `ShADaDadfFa`; `conn.json:4`, UID `Ccqm0bUSkySepOecTL`, `ShADaDadfF` | Original hard finding remains substantiated under native Zeek semantics. |
| TLS history direction loss | All 689 histories have no lowercase letters; 686 contain uppercase `S`; all 680 established rows contain uppercase `S` | `ssl.json:1`, UID `Ccqm0bUSkySepOecTL`, TLS 1.3 established, `CSD`; `ssl.json:2`, UID `C1zhfwA8fxOVmqbrgQq`, TLS 1.2 established, `CSXKNGIFIFD` | Original hard finding remains substantiated under native Zeek semantics; three ClientHello-only rows are excluded from the ServerHello count. |
| NTP reference-ID representation | All 12 rows have stratum 2 and `.GOOG.` | `ntp.json:1`, UID `CAD2SqFDzX1ACIHxJSI`; same pairing at line 12 | Reported schema/format finding remains substantiated; retained as smaller corroboration rather than relabeled as a new hard contradiction. |

The invalid TCP histories span 307 SSL, 22 SMB, 19 HTTP, two SSH, and two unlabeled connections. They originate from all four IPs: `.11` has 166, `.12` 143, `.21` 30, and `.31` 13 affected rows. This verifies the reported breadth without extrapolating to unseen sources or time periods.

Zeek documents per-direction suppression for the affected connection markers. The duplicated markers therefore cannot be justified simply as repeated packets or application turns. [Official connection-history definition](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html#type-Conn::Info).

Zeek's versioned TLS implementation defines case by sender and constructs lowercase server messages; uppercase ServerHello in these histories is a direction defect. The same source defines the version as selected by the server. The reported `ssl.json:11` ClientHello-only history with `version="TLSv12"` was also confirmed, but is retained as related support rather than a separately weighted major defect. [Official Zeek 8.0.0 TLS source](https://raw.githubusercontent.com/zeek/zeek/v8.0.0/scripts/base/protocols/ssl/main.zeek).

For a stratum above 1, Zeek documents the reference clock's IPv4 address representation, including a four-byte IPv6-reference hash. `.GOOG.` is incompatible with that representation. [Official NTP field definition](https://docs.zeek.org/en/current/scripts/base/protocols/ntp/main.zeek.html#type-NTP::Info).

These documentation checks support the field-semantic conclusions. They do not establish the dataset's actual Zeek release or rule out a custom transformation.

## Most Convincing Evidence

This ranking is the facilitator's ordering of the submitted evidence after the bounded checks, not a ranking collectively adopted by the reviewers.

1. **TLS direction loss:** 686 client-attributed ServerHello histories, including all established exchanges. Broad scope and a definite sender-encoding rule make this the strongest native-field defect.
2. **TCP history accumulation:** repeated suppressed markers in 352 TCP connections across hosts and services. This is a distinct semantic failure from TLS case loss; the two defects are not treated as additive probabilities.
3. **NTP reference-ID representation:** the same incompatible representation appears in all 12 selected records. It has smaller source scope than the first two findings but direct field-specific support.
4. **Repeated slow macOS diagnostics:** a defined 13-command cohort and native ES corroboration support a distribution concern. Real stalls remain possible, so this ranks below source-native contradictions.
5. **UserAssist count regression:** a specific value and actor show 9 → 4 → 72 without visible reset context. Writable/restorable state prevents treating the decrease as impossible.

The strongest counterweight is the reports' broad correlation and lifecycle integrity: all 146 visible Windows process-creation pairs agree in the host review, SSH transport precedes target authentication in the checked pivot, and network references/certificate identities remain coherent. These are affirmative strengths, not synthetic tells merely because they work.

## Most Debated Points

No live debate occurred. The points most deserving reviewer discussion are: whether field corruption alone warrants the high synthetic-origin scores; how much the selected endpoint timing cohort should move an inconclusive assessment; what observable browser/profile context would resolve the parallel Chrome roots; whether an actual service explains browser-shaped HTTP under `svchost`; and whether reset/restore context explains UserAssist state. Additional unrelated source families would not, by themselves, answer those questions.

## Round 3 — Revised Positions

No final positions or revised numerical scores were elicited. The table preserves this explicitly rather than assigning the reviewers statements they did not make. The original three synthetic verdicts and one inconclusive verdict remain the only actual submitted verdicts.

The independently confirmed network findings are relevant new cross-report evidence for the threat and host reviewers. They could reasonably prompt reassessment of overall dataset origin while leaving their endpoint-specific conclusions intact. This is a **facilitator estimate of a possible influence**, not an estimate of revised scores and not a claim that either reviewer changed their mind. The detection and network reports receive factual corroboration from the recount; no confidence increase is attributed to them.

## Improvement Recommendations (Consensus Status Explicit)

These are recommendations supported by the named submitted reports. No additional consensus was elicited.

| Priority | Concrete recommendation | Reported support and qualification |
|---|---|---|
| 1 | Construct TLS history from ordered sender-aware observations; validate TLS 1.2 full/resumed, TLS 1.3, and failed handshakes against native semantics. Populate negotiated version/cipher only when the observed handshake supports it. | Detection and network. Correct direction and field meaning, rather than adding superficial variation. |
| 2 | Accumulate connection history with Zeek's per-direction suppression rules; retain distinct semantics for repeatable handshake/close and logarithmic loss/retransmission markers. Include the observed invalid histories in conformance checks. | Detection and network. Do not blindly deduplicate every character. |
| 3 | Encode NTP reference IDs according to stratum and native field representation. If fields were transformed from real telemetry, document that transformation and retain original native values. | Network; transformation caveat also appears in detection. |
| 4 | Use command-sensitive diagnostic lifetimes, including a substantial short-lived component, and represent supported stalls consistently in normalized and native timestamps. | Threat and host. The requested change addresses repeated texture, not an asserted universal runtime limit. |
| 5 | Reuse a same-profile Chrome instance for new windows, or represent the actual supported instance/profile boundary and its renderer ownership. | Threat only; hidden configuration remains possible. |
| 6 | Attribute ordinary browser requests to their actual browser process; when a service intentionally makes them, retain service-specific context that explains the owner and request behavior. | Threat only; user-agent text alone is not process identity. |
| 7 | Maintain UserAssist history per user and exact value. Represent resets/restores as state transitions and keep counts, focus fields, and last-execution time compatible. | Host only; reset/restore remains a legitimate alternative explanation. |
| 8 | Distinguish scheduled SMB automation from interactive document work, preserving genuine periodicity where appropriate and linking human activity to its session/application context. | Threat only; this is a lower-priority, caveated concern. |
| Preserve | Retain working durable identities, fork/exec distinction, source-specific timestamps and identifiers, SSH ordering, coherent certificate references, and file direction/size relationships while correcting defects. | Positive evidence across all four reports, with each reviewer supporting the portions within their scope. |

## Round 4 — Facilitator Synthesis

The submitted reports show an initial majority of three synthetic verdicts and one inconclusive verdict, with a substantial and honest spread in synthetic-confidence scores: 64, 92, 90, and 56. There is no newly elicited unanimous verdict or pooled probability.

The original hard findings remain substantiated: TCP histories violate native marker suppression, and TLS histories lose required sender direction. The NTP format concern also survives verification. Their proper scope is the supplied source-field representations. Inferring synthetic origin is strongly supported by the detection/network reports, while undocumented transformation of real telemetry remains an unresolved alternative.

Endpoint coherence and softer endpoint concerns coexist. Slow diagnostics, Chrome instance behavior, service-owned browsing, UserAssist state, and SMB cadence deserve targeted explanation or improvement; none is promoted here to an unconditional execution contradiction. No weight is added for narrative design, sanitized names, compact suspicious activity, absent attacker mistakes, completeness, optional source absence, or boundary-limited lifecycle gaps. The actionable priority is native-field conformance while preserving the existing correlation strengths.
