# Deterministic ground truth

Generation makes no LLM calls. Scenario descriptions may have been written with AI
assistance, but descriptions document authored intent and do not configure execution.
For example, the word “blocked” does not establish a firewall or proxy denial.

## Artifacts and authority

New bundles use ground-truth schema **5**. `GROUND_TRUTH.json` contains compact
authored-action summaries, independent intent reconciliation, intent outcomes, background
counts, a `source_expectation_summary` with presence/absence counts by source and exclusion reason, and an integrity reference to `GROUND_TRUTH_EVENTS.jsonl`. Its existing `events`
array remains an authored-action compatibility summary, including skipped/no-op entries;
it is not the complete occurrence census. Bounded destination samples in that summary
are supplemented by the full occurrence stream. Markdown IOC sections derive from committed
facts and sample at most 128 new indicators per intent, explicitly linking to the complete
stream. Synthetic spillage command lines remain excluded from the human-readable IOC list;
the detailed stream retains the factual command.

`GROUND_TRUTH_EVENTS.jsonl` schema **2** contains deterministic, chronologically ordered
canonical occurrences from authored storyline/red-herring activity and their consequences.
Each row carries occurrence/action/intent identities, canonical time and facts, outcome,
relationships, and per-source expectations. Presence in this stream means the occurrence
happened; it has no redundant `occurred` flag. Native source identifiers remain distinct
from internal occurrence IDs. Process, session, and lifecycle references link consequences
to their owning action without labeling all subsequent activity of a borrowed service as
attacker activity. Unrelated background activity is summarized separately.

The generation manifest covers the stream. Evaluation validates its schema, count, digest,
and ordering and independently reconciles observed DNS, HTTP, and transport consequences
and process lifecycle consequences against parsed source records. Existing source-native
and cross-source evaluation gates
continue to cover their respective contracts. Schema-3 and schema-4 bundles remain readable/evaluable;
they do not gain historical occurrence detail retroactively.

The journal is disk-backed and uses incremental SQLite checkpoint deltas. Recovery restores
captured facts and source decisions before continuing. Final JSONL export streams rows rather
than constructing a duration-growing Python list. A changed checkpoint participant set cannot
reconstruct facts omitted by an older runtime; older checkpoints may therefore fail restoration
at that state-contract boundary. This does not prevent evaluation of completed schema-3 bundles.

## Outcomes and observation

An attempted action can occur while its intended consequence is prevented. A denied process
launch is an attempt, not a process creation. Ground truth records prevention separately from
source observation, including enforcing entity, mechanism, operation, stage, and reason when
the canonical owner supplies them. Unknown native cause/stage remains unclassified.

The existing modeled families include firewall/proxy denial, DNS resolver refusal, authentication rejection,
SMB authorization denial, application-control refusal, and mail rejection/quarantine/attachment
stripping. Attachment stripping is partial delivery. Ordinary DNS failure, missing files,
sharing violations, executable failure, and HTTP server errors are not automatically security
prevention. DNS REFUSED records refusal with an unclassified cause; it does not invent a
particular filtering policy. File/registry sources without a modeled denial outcome cannot imply prevention.
Origin HTTP 401/403 describes origin authorization, separately from proxy policy.

Each applicable source instance/format declares expected **presence or absence**. This is a
prediction from committed facts and collection policy; it does not assert that an evaluator
found the evidence. Actual matches and mismatches appear only in the evaluation report.

Expectations carry stable occurrence/source/format/role/phase identity, native matching keys,
required facts, timing tolerance and cardinality. Sysmon DNS uses its frozen native envelope time and query identity to distinguish adjacent A/AAAA/lookaside lookups; empty `QueryResults` is normalized from its native `-` representation. Connection legs and transaction phases remain explicit; a firewall build/close pair is one required source projection. Native Sysmon include/exclude rules and sparse Windows SMB audit policy are
captured separately from export selection. Repeated registry operations use the native
observation clock together with process/key identity; module observations include the owning
process as well as binary identity. The run-level `expectation_contract` binds the
resolved scenario, source policies, observation profile, and native rule snapshot. Metadata
capture uses local deterministic derivations and consumes no generation RNG draws.

The `conditions` array preserves deployment, placement, capabilities/encryption, collection
windows, loss, native source filtering and export selection separately. The first excluded
condition is decisive; other restrictions remain visible. A loss stage that was never sampled
is explicitly unknown. Missing families are `coverage_gaps`, without invented sensor names.
An explicitly empty sensor deployment differs from an unspecified deployment. Configured
sensors are enumerated even when off-path, downstream of enforcement, disabled, or unexported.
Source publication failures remain errors.

Process transitions retain canonical current/previous execution IDs and operation-specific
image, command, credential and job-control facts. eCAR matching uses process/execution
identity, operation and native clock precision; neighboring execs in the same PID are
distinct occurrences. Required facts are checked separately, so a changed image remains a
disagreement and an actual duplicate remains a cardinality error. Literal POSIX argument
equivalence accepts harmless quoting changes without interpreting shell programs.

Finalized source projections retain bounded process timing witnesses under
`provenance.timing`: canonical/native times, phase, identities, policy and predecessor
anchors. Timing policies are bound in `expectation_contract.source_rules.process_timing`.
Preferred create candidates are identified separately from finalized observations. A process
frontier can reference its own evidence or a direct child's creation; session readiness
references the actual source login phase. These planning witnesses are not extra occurrences.
Evaluation checks predecessor identity/existence, ordering and policy bounds independently;
a long inherited readiness delay cannot justify itself. Referenced pre-window process
entities retain canonical start times without fabricating retrospective observations.
Historical feature bundles missing these facts retain explicit verification limitations;
unsupported timing is not converted to a successful zero-check case.

Generation and evaluation share declarative semantic contracts, not renderer execution.
The semantic contract is current engine policy; a resolved generation configuration cannot
silently restore an older verifier. Linux SSH logoff supports syslog only when its canonical
context supplies it. Launch-item stages have separate consequence contracts: registration
and dormant unload can retain `job_control` with no native evidence, while activation,
file changes and process exit still require their corresponding occurrences.

History source ownership follows the supported host/user layout rather than the format
subdirectory. Generated ASA RFC3164 timestamps are UTC despite having no printed offset.
UDP packet/IP-byte accounting is finalized canonically before capture and rendering; Zeek
does not silently repair those shared values. Scan refusal/no-response is a transport
outcome, not automatic firewall prevention. An enforcing firewall must come from the
actual policy decision/path; an adjacent source-side gateway does not establish enforcement.

Per-source `source_views` retain the sensor's capture profile, transport timing, packet/byte
accounting and file visibility. Evaluation independently verifies these receipts against the
captured capture policy. Packet loss can reduce captured payload or suppress analyzers without
dropping the connection record; this differs from source collection loss. These facts remain
on disk in the occurrence stream rather than accumulating in the compact summary.

Authored `raw` escape hatches retain a versioned source-local receipt under their intent
outcome rather than inventing a canonical occurrence or sensor identity. Literal source
fields, host, timing, cardinality and the named profile's loss decision are checked. Native
normalization that cannot be independently reconciled is reported as a contract disagreement;
it cannot earn a zero-check success. Use typed activities for correlated behavior.

Placement applies per phase and connection leg. A sensor upstream of a firewall can see
an unsuccessful attempt that a downstream sensor cannot see. A proxy denying before origin
access creates no origin transfer. Successful CONNECT 200 followed by inspected request
denial is valid: those responses describe different phases. Opaque HTTPS does not create
an observable HTTP payload transaction.

## Domain/address and other relationships

DNS facts preserve every answer actually returned and its TTL. `dns_answer_set` identifies
the subset used by captured authored connections; `dns_answer_use` links each connection
to its concrete lookup, selected address, resolver, client, resolution time, and lookup/cache-hit
mode. Actual DNS/cache consumption is recorded at its owner; a compatible answer set alone
does not establish use. Cached connections can share one earlier answer reference without
fabricating another lookup. Alias strings remain in the actual answer set. Each connection
attempt names its attempted address and transport; repeated attempts share their canonical
action ownership rather than treating every available address as contacted.
Unrelated answers are not labeled as contacted infrastructure.

Canonical connection targets, proxy client/origin legs, NAT translations, requested/expanded
mail recipients, and individual SMTP recipient attempts retain distinct facts. These are
execution relationships; reverse-DNS inference does not establish an authored domain or
malicious ownership.

Exact DNS cache-consumption/expiry provenance remains a separate follow-up. The current
cache check compares the recorded answer lifetime with connection timing; a reported TTL
boundary discrepancy needs that additional provenance before its cause can be established.

## Intent failures and authored HTTP statuses

Unexpected missing prerequisites or an unaccounted required intent fail generation. Partial
evidence and `GROUND_TRUTH_DIAGNOSTICS.json` retain the unfulfilled intent; no successful run
manifest is written. Explicit failures/prevention and legitimate no-ops remain valid outcomes.

Explicit authored HTTP status codes on connections and beacon sequence entries take precedence
over automatic public-site redirect defaults. When no status is authored, the existing site
policy can still choose a redirect. Actual proxy enforcement remains authoritative for its leg.
Markdown distinguishes authored narrative from these deterministic factual outcomes.

## Ground Truth Agreement (schema 5)

Evaluation verifies three layers without running a renderer: typed authored actions and their
required canonical consequences; source expectation completeness and policy justification;
and independently parsed emitted records. Declarative semantic contracts are package-owned in
`config/evaluation/ground_truth_contracts.yaml`. Loss samples, source identities, DNS answer/use
relationships, recipient outcomes and proxy/NAT links are verified independently. Deleting an
expectation with its log cannot hide a missing projection. Changing both a log and ground truth
cannot override an explicitly authored HTTP status or required process/download consequence.

All five pillars have **20%** overall weight. Ground Truth Agreement requires **95%** and has
an aspirational target of **100%**. Each authored typed intent is one equally weighted action;
a beacon sequence remains one action. Within an action, a required source projection is one
all-or-nothing check across presence, required facts, relationships, timing and cardinality.
Optional fields add no credit. A defective projection is counted once even if several fields
are wrong. Valid expected absences add neither successes nor failures; contradictory evidence
adds a failure. Unattributable semantic defects add an incorrect check to the affected action.

An action scores `100 * correct / checks`; legitimate zero-check actions score **100%** with
a reason. A valid run without authored actions also reports 100% and zero counts. Missing,
invalid or unsupported contracts cannot earn a zero-check success. The pillar averages action
scores, not records or observations. Full counts, scope, coverage, zero-check reasons and
bounded examples are retained even when the score passes. CLI JSON includes these in
`supplementary.ground_truth_agreement`; CLI text and Studio show the summary and diagnostics.
Authored accounting and integrity/schema gates remain independent requirements.

Reports retain complete rule counts and unique defective-check counts separately. At most
100 detailed examples are selected deterministically across rule/format families, with
displayed counts and explicit truncation. Examples include bounded command predicates,
matching/cardinality counts, timing anchors/deltas and evidence locations. CLI text shows
five examples by default or twenty with `--verbose`; JSON and Studio retain the bounded
representative set. Exported report JSON does not contain an uncapped findings stream.
New diagnostic messages carry a stable `check_id` identifying their scored check. Multiple
rule messages from the same source expectation or action-level semantic check share that ID;
it changes neither scoring nor the example limit. Studio groups these checks into diagnostic
categories that start collapsed, with search across category, action, source, rule and evidence
details. Older saved reports use their available identities for grouping.

Schemas 3 and 4 retain legacy evaluation and their original 30/25/25/20 overall weights.
Their reports explicitly state the coverage limitation; they receive no fabricated fifth score.

## Visibility preflight

`eforge validate` checks important typed facts on the relevant hosts and planned network paths,
without running full generation. Source types are alternatives only when they can express the
fact: an EDR flow cannot prove an authored HTTP denial. Warnings identify the action, fact,
excluded sources and remedy. Certain loss or an intentionally closed collection window retains
the warning; correctly modeled absence is still accepted during evaluation. Optional source
gaps, probabilistic loss and generic segment/DHCP/firewall limitations are informational.
Runtime-dependent routes or timings are labeled conditional. Structural errors remain errors.
Descriptions remain documentation and never establish enforcement or evidence requirements.
