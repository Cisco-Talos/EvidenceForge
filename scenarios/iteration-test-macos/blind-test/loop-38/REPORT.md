# Loop 38: sudo/PAM timing phases and admission ownership

LinuxSudoSessionActionBundle now plans process lead, PAM open, child readiness,
close and exits through shared named timing relationships and the injected engine
runtime. The canonical phases have microsecond variation; syslog and normalized
process telemetry render those same facts. Close admission derives its maximum
from the same configured windows. Direct callers retain an isolated compatibility
runtime; denied standalone sudo attempts remain outside the allowed-session bundle.

180 focused tests pass, including zero-runtime ordering, replay, seed separation and
baseline/storyline siblings. Broader admission tests exposed an eager sampler lookup
introduced with36's opt-in daemon schedule. Unconfigured entries now skip that lookup
at the profile boundary, preserving their literal-cap behavior. validate-config has
0errors, and whole-repo Ruff/format pass. Revision436 validation/generation/eval pass
96.0944,135878records,119files. Same counts/eval as37 apart from negligible timing score
precision;99/99sudo/PAM pairs used whole-ms gaps in37, now0/99with99distinct gaps and
no nonpositive ordering. FirstHTTP whole-ms0, browser0/267mismatches and both transport
contradiction probes0. This verifies the selected family independently of blind scores.

Remaining priorities: P1 invalid generated PowerShell CIM credential invocation
(Threat36,hard contradiction under standard cmdlet semantics,shared caller builder,
low/mediumrisk); P1 mounted Mac SMB helper terminal truth (Host36,qualifiedcontractgap,
SMB completion->canonical termination owner); P1 per-flow observation consistency
(Network35/36,qualifiedfilegapcontract concern), and P2 SMB baseline cadence. Original
reviewer priority labels were not assigned. Authored Mac inventory/shell timings are
preserved; isolated private metadata and ownership aggregation suspicions remain
qualified rather than treated as established impossibilities.

Correction recorded in42: the saved validate-config invocation failed with an extra
model argument to validate_entry; earlier claims of0errors were incorrect because
later shell commands masked the exit. The data-generation/eval results and scores
remain valid.42 repairs the validator and adds regression/CLI verification.


## Family contract

# Linux sudo/PAM phase timing

Classification: sibling_defect; family_level. Owner: LinuxSudoSessionActionBundle plus named timing relationships. Baseline and any canonical sudo-session caller must consume one scoped microsecond-resolution plan for process lead, command/PAM open, child readiness, close and termination. Native syslog and eCAR render the same bundle phases; emitters add no jitter. Preserve invoking principal, TTY serialization, lifecycle identity and termination ordering. Close-headroom admission derives from the same configured upper bounds rather than a stale fixed bound. Denied standalone commands remain outside this allowed-session bundle. Direct bundle callers receive an isolated compatibility runtime; production explicitly injects the engine runtime. Verify all phases, same-seed replay, changed seed separation, zero-runtime boundary, configured headroom and baseline/explicit-source siblings. This does not change authored Mac command offsets or SSH authentication phases.

Secondary exact regression: unconfigured syslog entries must not resolve the opt-in
arrival sampler. Broader admission fixtures caught an eager runtime access added in36;
keep the optional profile boundary lazy and preserve literal-cap sibling execution.


## Individual expert summaries

**Threat Hunter:** Inconclusive; verdict confidence 76; synthetic-confidence score 40. The collection supports technically useful hunting across endpoint, authentication, network, file-server, and proxy evidence. I found a modest repeated timing/command texture in the two Mac shell histories, but the inspected intrusion pivots and process lifecycles hold together; that limited texture does not establish synthetic origin. The score reflects mostly realistic telemetry with an explainable behavioral artifact, rather than a demonstrated hard contradiction.

**Detection Engineer:** Inconclusive; verdict confidence 83; synthetic-confidence score 38. Most supplied telemetry should parse and correlate credibly in a SIEM. I found a small Windows native-schema extension and some questionable repeated command behavior, but no demonstrated impossible lifecycle or network accounting relationship in the automated checks; these findings do not justify a confident synthetic verdict.

**Network Forensics:** Synthetic; verdict confidence 77; synthetic-confidence score 62. The network telemetry is broadly coherent and substantially production-like: connection states, sensor-specific loss, proxy topology, DNS variety, TLS certificate relationships, and service-dependent durations withstand several consistency checks. My synthetic verdict rests on a narrowly scoped but concrete DNS-over-TCP contradiction: a decoded successful IPv4 answer is attributed to a connection containing too few response bytes to carry even the smallest such response. This is a localized defect, not evidence that the wider dataset has uniformly poor realism.

**Host Forensics:** Synthetic; verdict confidence 88; synthetic-confidence score 69. The endpoint evidence has convincing process identities, platform distinctions, session metadata and ordinary background activity. My synthetic verdict rests principally on reproducible timing patterns in otherwise unrelated endpoint actions: six Mac inventory processes have exactly identical fork-to-exit durations, the two Macs repeat the same inter-command cadence across different commands, and one Linux developer repeatedly changes editors at almost identical intervals. I did not find a demonstrated impossible process lifecycle or a dataset-wide schema failure; the score therefore remains in the “likely synthetic” band.


## Scores and comparison

Automated eval 96.0944; standalone synthetic-confidence average 52.25 (mixed/inconclusive), prior loop 44.25. Lower is more production-like. Scores are standalone reviewer measurements; physical/semantic probe outcomes independently verify the selected family.

Facilitator-modeled deliberation averages 62.25; see deliberation.md. Modeled revised positions are excluded from standalone and rolling averages and are not reconvened expert votes.
