# Deliberation Summary

## Status and provenance

This is a **facilitator-modeled reconciliation**, not a reconvened panel discussion. The four independent reports are the actual reviewer positions; no reviewer has seen another report, answered cross-examination, changed a vote, or endorsed the recommendations below. Every proposed revision and cross-specialty synthesis below is facilitator-modeled reconciliation. The facilitator is not a fifth authenticity reviewer.

The facilitator read only `/private/tmp/log-study-sucvw85x/deliberation-prompt.md`, including all four embedded reports and its instructions. An initial whole-file read was truncated; subsequent untruncated reads covered lines 1–170, 171–330, and 331–503, completing the file. No raw logs, repository files, scenario, TODO, worklog, coordinator probes, previous assessments, or other files were opened. No commands quoted in the evidence were executed. References to raw-data paths, source lines, counts, and external documentation below are inherited from the embedded reports, not independently verified by the facilitator. External reference pages were not opened.

The reports describe approximately 13:00–19:00 UTC on November 2, 2026. Their shared corpus includes 36,352 normalized endpoint records, ten Windows Security/Sysmon pairs, eleven Linux-style syslog endpoints, two macOS exports, and three network sensors. Sensor observations are not deduplicated sessions. Review scopes differ: the threat hunter followed selected investigation chains and screened identities; detection reviewed native semantics and ownership across several sources; network parsed the sensor-local JSON corpus; host concentrated on endpoint application and process lifecycles. Overlapping checks do not make a specialty-specific finding independently confirmed by everyone.

## Panel Composition

Initial columns are actual independent submissions. All final columns are **facilitator-modeled reconciliation**, including unchanged verdict categories. Verdict confidence expresses confidence in the stated classification; synthetic-confidence expresses degree of belief in synthetic origin. They are distinct, and confidence in an inconclusive classification can remain high.

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict — facilitator-modeled reconciliation | Final Verdict Confidence — facilitator-modeled reconciliation | Final Synthetic-Confidence — facilitator-modeled reconciliation |
|---|---|---:|---:|---|---:|---:|
| Threat Hunter | Inconclusive | 80 | 27 | Inconclusive | 75 | 55 |
| Detection Engineer | Synthetic | 86 | 67 | Synthetic | 88 | 76 |
| Network Forensics | Inconclusive | 85 | 20 | Inconclusive | 85 | 43 |
| Host/EDR Forensics | Synthetic | 82 | 67 | Synthetic | 86 | 75 |

Actual initial votes: two Synthetic, two Inconclusive, none Real. Actual initial synthetic-confidence mean: 45.25. **Facilitator-modeled reconciliation** scores in TH/DE/NF/H order are `[55, 76, 43, 75]`, with arithmetic mean **62.25**. These proposed numbers are a transparent qualitative synthesis, not measured probabilities, new votes, or a statistically calibrated panel outcome. The modeled verdict categories retain the original split.

## Round 1 — Independent Findings

### Threat Hunter: actual initial position

**Inconclusive; verdict confidence 80; synthetic-confidence 27.** The strongest positive checks were Windows NewCredentials semantics that preserve the local token while using a different outbound account; an established RDP transport before the target Type 10 logon; and the Linux database-to-SCP-to-SMB trail with consistent filenames, identities, and adequate payload. These demonstrate useful investigative coherence without proving origin.

The principal reservations were weak texture signals: 43 Mac shell-history entries with a small overlapping inspection vocabulary, and repeated wiki/Jira browser strings. The reviewer explicitly warned that fork-inherited command lines cannot be counted as independent user launches. Unique contributions include the concrete local-versus-outbound credential distinction, transport-before-auth RDP pivot, and the archive/proxy upload chain. Its claim that no material contract gap was demonstrated is limited to relationships it checked.

### Detection Engineer: actual initial position

**Synthetic; verdict confidence 86; synthetic-confidence 67.** The strongest finding was 24 Winlogon creations on six Windows hosts assigning different terminal sessions to the same per-host SMSS parent identity. On DC-02, sessions 5 and 6 share parent PID 5072 and the exact ParentProcessGuid; eCAR preserves the same parent ownership. This is a semantic ancestry concern, even though the references correlate correctly.

The second finding was 137 snapd task-completion messages across ten hosts using only task numbers 1–9, with reuse across changes. The report's Canonical-source interpretation is that native task IDs come from state-wide allocation independent of change IDs. Customized change-local ordinal logging remains an alternative. Four-string, invariant-result irqbalance pools provide weaker distribution evidence. Unique contributions are session-bootstrap ownership and daemon task-identity semantics. The reviewer also found broadly sound native field representations, visible process bounds, and network accounting.

### Network Forensics: actual initial position

**Inconclusive; verdict confidence 85; synthetic-confidence 20.** The strongest positive checks were sensor-local UID/tuple/time integrity; CONNECT control-versus-tunnel accounting with exact proxy byte decomposition; and TLS/X.509/file relationships respecting passive TLS 1.3 opacity. Checks also supported varied states, HTTP transactions, failures, resumption, and protocol-specific transport behavior.

The only synthetic reservation was unusual database-origin traffic to workstation-facing services on 443 and 8530. Workstation names cannot exclude installed management or laboratory services. Unique contributions include checking 1,206 gap-marked connections against positive missed-byte counts, verifying a zero-payload UDP history interpretation against upstream implementation, and validating certificate authentication/key/SAN relationships. These are strong protocol-quality findings, not authentication of production origin.

### Host/EDR Forensics: actual initial position

**Synthetic; verdict confidence 82; synthetic-confidence 67.** The principal concern was seven overlapping Chrome browser roots under the same user/audit session and HOME on MAC-MROSS-01. Native exec and exit records, plus helper subtrees, support persistent roots rather than a mere excess of normalized CREATE rows. Later ordinary new-window launches do not visibly identify separate user-data directories. Windows Sysmon shows a corresponding overlapping-root example on WS-DRAMIREZ-01.

The weaker concern was eight successful `/bin/cat` reads of PDF/DOCX/XLSX files on MAC-MROSS-02 lasting 11.98–23.34 seconds. Raw reads are possible; the repeated tool/duration combination is a texture signal. Unique contributions include native browser-root lifetime reconstruction and distinguishing process lifetime from exec image changes. Positive findings include stable hashes/identities, distinct Terminal/iTerm startup chains, coherent Linux SSH phases, and plausible Windows session types.

## Round 2 — Cross-Examination (facilitator-modeled reconciliation)

### Browser repetition: inherited strings or persistent independent roots?

The threat hunter's caution and the host finding concern different evidence. Repeated normalized command strings can result from fork inheritance; that explanation correctly limits raw command counts. It does not explain away the host report's seven native browser-root exec-to-exit intervals, continuing older roots, and new helper trees. The host evidence is more specific to application-instance ownership and should receive greater weight on that question.

This does not establish an unconditional contradiction. Chromium singleton behavior depends on the resolved user-data directory; the reports do not expose all resolved directories or isolation arrangements. Hidden distinct directories or other concrete isolation could permit multiple persistent roots. Same executable, HOME and user, coupled with ordinary new-window arguments and cross-platform recurrence, makes that qualification worth checking rather than a demonstrated explanation. The Windows example is additional platform evidence in the host report, not a second reviewer's independent confirmation. Count the Mac and Windows cases as one recurring browser-state family, not two unrelated decisive defects.

### Clean process lifetimes versus wrong Windows parent ownership

The detection engineer's SMSS finding does not conflict with the threat/host screens that found no actor use outside visible bounds. A parent can remain a valid, live process identity while being the wrong semantic owner for a session-specific bootstrap. DC-02's same parent GUID across different TerminalSessionIDs is affirmative evidence; missing SMSS births are not the complaint.

The detection report cites Microsoft session architecture to support per-session initialization. A material defense would need to explain why the recorded parent field legitimately names one shared process rather than the session-specific creator, or establish a platform/export behavior that changes that interpretation. None is supplied in the reports. Plausible general timestamp latency does not change the exact parent identity. This is therefore the strongest reported platform-ownership issue, while remaining a report-grounded architectural inference rather than a newly verified kernel-level impossibility.

### Cross-source agreement: correct relationship or consistently wrong truth?

The network reviewer correctly treats UID matching and good accounting as positive quality evidence. Detection shows why agreement alone is insufficient: Sysmon and eCAR both preserve the same disputed Windows parent ownership. Correlation can faithfully reproduce an upstream semantic error. Conversely, one endpoint ownership family does not invalidate the network reviewer's full sensor-local protocol checks. Both findings stand within their respective scopes.

The corresponding blind spot is evidentiary reach. Threat/network reviewers did not demonstrate the absence of the specific browser, SMSS or snapd issues. Detection/host did not demonstrate network transport defects. Adding specialized ownership findings can increase overall suspicion without withdrawing any successful protocol checks.

### snapd identity: native counter or customized ordinal?

The detection evidence is stronger than a general complaint about small numbers: task values recur across unrelated change IDs under the same daemon PID, with ten-host repetition and a 137-row vocabulary confined to 1–9. The report's cited allocator semantics give that observation a concrete contract.

Its limitation is equally concrete. The exact snapd release is unspecified; custom diagnostics could print within-change ordinals while retaining a native-looking taskrunner prefix. That possibility reduces certainty and makes this a contract gap rather than a hard contradiction. Ordinary PID persistence does not by itself rule out every state restoration or custom logging behavior. No other report independently investigated this counter's meaning. This finding deserves moderate weight, below the SMSS ownership evidence, without assuming that current upstream line numbers must match the host build.

### Repetitive daemon, shell, and document behavior

These observations are compatible with small activity pools but have credible production alternatives. Stable IRQ topology and repeated daemon diagnostics can yield repeated strings; a common user or operational checklist can repeat Mac commands; `cat` can legitimately dump arbitrary bytes, and file size/output conditions can influence duration. The reports establish repetitive samples, not population baselines proving those repetitions impossible.

The irqbalance volume and invariant outcome justify a targeted texture review. The office-document tool/dwell pattern is a separate, weaker behavioral question. Neither should be promoted to a hard contradiction or multiplied into many independent votes. The facilitator-modeled reconciliation retains them as supporting signals only.

### Workstation services and policy-message interpretation

The network service-placement concern remains weak: naming and segment origin do not establish a complete service inventory. It cannot justify moving traffic absent confirmation of intended services. The Mac AppleSystemPolicy line likewise does not prove a successful MeetingAssist exec, universal denial, or child effects. Threat, detection and host reports consistently avoid that overreach. No disagreement here warrants a new synthetic penalty.

No weight is assigned to readable intrusion narrative, compactness/completeness of an attack chain, collection completeness, absent product families, or generic pre-/post-window lifecycle omissions. Reported timing tolerances also differ: the threat hunter's two-second post-termination screening tolerance and detection's network interval tolerances are not interchangeable proofs of exact subsecond correctness.

## Round 3 — Proposed Revised Positions (facilitator-modeled reconciliation)

These are conditional models of how each report's reasoning could incorporate the others. They are not statements that an expert actually changed their mind.

- **Threat Hunter — facilitator-modeled reconciliation:** retain Inconclusive; verdict confidence **80 → 75**; synthetic-confidence **27 → 55**. The specific native browser lifetime evidence and detection's shared SMSS identity provide stronger reservations than repeated command vocabulary alone. The convincing credential, transfer and remote-session pivots remain valid, while hidden browser isolation and snapd logging customization prevent a compelled origin decision. The modeled reduction in verdict confidence reflects greater tension between coherent hunt evidence and specialized ownership concerns.
- **Detection Engineer — facilitator-modeled reconciliation:** retain Synthetic; verdict confidence **86 → 88**; synthetic-confidence **67 → 76**. The host's browser-instance finding adds a distinct application-state concern to the existing bootstrap/task-identity findings. The network report reinforces protocol correctness and constrains the diagnosis to semantics and behavior rather than generic formatting. Do not treat the cross-platform browser examples or the same SMSS issue in two renderings as independent duplicated defects.
- **Network Forensics — facilitator-modeled reconciliation:** retain Inconclusive; verdict confidence **85 → 85**; synthetic-confidence **20 → 43**. The expanded dataset-level view now includes endpoint issues outside the network audit. This raises modeled overall suspicion while leaving the original network-only conclusions intact. The absence of independent endpoint verification and the explicit alternative explanations sustain an inconclusive verdict. This is not a revised network-protocol score.
- **Host/EDR Forensics — facilitator-modeled reconciliation:** retain Synthetic; verdict confidence **82 → 86**; synthetic-confidence **67 → 75**. Detection's SMSS ancestry and snapd observations supplement the browser-state argument. The threat hunter's fork-inheritance caution further sharpens the need to base the browser finding on native exec/exit roots. Network correctness and hidden user-data-directory possibilities remain counterweights; no native-schema impossibility is newly claimed.

## Round 4 — Cross-Specialty Synthesis (facilitator-modeled reconciliation)

The modeled overall assessment **leans synthetic, with unresolved origin and a retained two-Synthetic/two-Inconclusive classification split**. The score mean is a descriptive reconciliation aid, not a majority-rule verdict. The most informative distinction is between strong protocol/process-field realism and recurring application/platform ownership questions. No actual unanimous panel conclusion exists.

## Key Agreements

The following agreements are supported by overlapping statements in the initial reports; their combination is **facilitator-modeled reconciliation**:

- All four describe broadly competent formatting, identity handling or correlation, and none establishes a general native-schema failure.
- Threat, detection and host report successful visible process-identity/lifetime checks within their respective screening scopes. These checks support basic lifecycle coherence without certifying application ownership or every subsecond relationship.
- Detection and network independently report strong sensor-local transport/application relationships and TLS visibility distinctions; threat adds concrete transfer/proxy pivots. None treats good matching as synthetic evidence merely because it is good.
- Threat, detection and host preserve the distinction between a Mac policy observation and successful execution. They also recognize meaningful native fork/exec/process-lifetime distinctions.
- The reports treat behavioral repetition and unusual service placement more cautiously than concrete ownership findings, and reject generic collection-window/source omissions as mandatory repairs.

## Key Disagreements

- **Origin threshold:** threat and network submit Inconclusive with low initial synthetic-confidence; detection and host submit Synthetic at 67. Their different evidence and specialty reach explain much of the split. No report establishes production provenance or an unconditional impossible native lifecycle.
- **Browser evidence strength:** the threat report sees weak repeated command vocabulary; host sees persistent roots with native lifetimes. The latter is more probative of instance state, but profile isolation remains unresolved. The reports did not debate this directly.
- **Weight of specialized ownership findings:** SMSS and snapd findings originate with detection; the browser-root interpretation originates with host. Other reviewers' successful broad checks neither independently confirm nor rebut those exact claims.
- **How much coherence offsets defects:** network's detailed checks strongly support production-like protocol behavior, while detection/host show how a believable collection could still have semantic ownership gaps. This supports informed disagreement rather than cancelling either evidence class.

## Most Convincing Evidence

Ranking below is **facilitator-modeled reconciliation**, not a collective ranking actually voted on by the reviewers:

1. **Windows session-parent identity reuse — synthetic-supporting contract gap.** Detection reports 24 Winlogon creations across six hosts with shared per-host parent identities across sessions, including reproducible DC-02/DC-01 pairs. Exact identity and terminal-session fields make this stronger than missing-event speculation. Sysmon/eCAR agreement is correlated representation of one issue, not two independent confirmations.
2. **Persistent browser roots — synthetic-supporting application contract gap.** Host reports seven visibly overlapping native Mac roots, helper subtrees, and a Windows counterpart. This exceeds raw command repetition. Resolved user-data directories are not exposed, keeping hidden isolation a live qualification.
3. **Protocol-aware transport, proxy and TLS relationships — production-like counterevidence.** Network's broad UID/tuple/interval, body-size, CONNECT byte and certificate-visibility checks, supported in narrower form by detection, remove several plausible protocol objections. They show competent construction or collection, not production origin alone.
4. **snapd task-number reuse — synthetic-supporting contract gap with exporter/version uncertainty.** Detection's 137-row, ten-host pattern conflicts with its cited native allocation semantics. Customized ordinal reporting remains a viable alternative; exact version behavior was not established here.
5. **Credential/session/transfer semantics — production-like counterevidence.** Threat's NewCredentials distinction, RDP transport-before-auth and filename/payload transfer pivots, together with host's SSH phases, show recognizable semantic detail. They are bounded positive examples, not comprehensive absence-of-defect proofs.

Texture observations rank below these five because their real-world alternatives are stronger and their distribution baselines are limited.

## Most Debated Points

These are potential points of debate identified through **facilitator-modeled reconciliation**, not discussion that actually occurred:

- Whether explicit overlapping native Chrome lifetimes outweigh an unobserved profile-isolation explanation.
- Whether a live and consistently referenced Windows parent can nevertheless be the wrong session-bootstrap owner; the detection report says yes on architectural grounds.
- Whether snapd's native-looking taskrunner records contain genuine state-wide task IDs or customized change-local ordinals.
- How to preserve the network review's strong positive results while incorporating endpoint concerns beyond its specialty.
- Where repeated daemon/user behavior becomes informative texture rather than normal repetition. The reports support modest weight, not a universal entropy threshold.

## Improvement Recommendations (facilitator-modeled reconciliation)

No reviewer endorsed a post-deliberation consensus. The priorities below reconcile report recommendations; each names its actual support and uncertainty. They are conditional on synthetic generation and should not be read as proof of origin.

1. **Correct Windows session bootstrap ownership at the identity source.** Following detection's recommendation, create the session-specific SMSS owner for each new session and propagate the same correct PID, GUID/UUID and parent relationship into Sysmon and eCAR. Validate distinct-session bootstrap relationships as well as ordinary live-parent bounds. Other reports' good lifecycle checks are compatible with this repair but do not constitute their endorsement of this specific finding.
2. **Retain browser instance state per host, user and resolved user-data directory.** Following host's recommendation, route routine new URLs/windows to an existing instance; make any forwarding launch short lived, and create an additional persistent root only for concrete isolation. Preserve native fork/exec/exit distinctions. Threat's actual caution supports avoiding raw CREATE-count inflation, while host supplies the application-state diagnosis. Do not add launches merely to diversify repeated strings.
3. **Use persistent snapd task identity separately from change identity.** Following detection's recommendation, retain stable task-to-change/snap associations and allocate native IDs from the appropriate persistent state. If the source intentionally reports ordinals, distinguish that logging contract explicitly rather than silently relabeling native task IDs. Confirm release/exporter semantics before deciding which interpretation needs correction.
4. **Improve only the specific behavioral texture supported by the reports.** Host recommends application-owned PDF/Office viewing when that is the intended action, retaining `cat` for intentional raw reads and tying duration to the actual operation. Threat recommends widening manually entered Mac inspection vocabulary where it represents general user activity, while preserving legitimate repeated checks. Detection recommends irqbalance output driven by changing affinity/load or a quieter observation profile. These are separate specialty recommendations; no unanimous recommendation or defect is claimed. Extra unrelated noise is not the remedy.
5. **Check service placement against a concrete inventory before changing traffic.** Network recommends retaining workstation 443/8530 activity if those services are intentional, otherwise using appropriate service hosts. This remains a low-priority conditional check, not an established network repair.
6. **Preserve verified strengths while applying targeted changes.** All reports provide reasons to protect shared identities, source-native distinctions and correlated behavior. Retain NewCredentials local/outbound separation, meaningful SSH/RDP phases, transport payload accounting, CONNECT control/tunnel separation, TLS 1.3 certificate opacity, and source-local references. Do not introduce arbitrary sources, failed attack steps or window-boundary records merely to satisfy an authenticity assessment. This preservation priority has broad support in the actual recommendations; its combined wording remains facilitator-modeled reconciliation.

The highest-value follow-up would resolve the three named ownership/identity contracts with the appropriate native semantics and then evaluate their output effects without altering the well-supported transport and session relationships. Such follow-up has not been performed in this report-only reconciliation.
