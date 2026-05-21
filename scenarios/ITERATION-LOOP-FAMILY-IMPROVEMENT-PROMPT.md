# EvidenceForge Family-Level Realism Improvement Loop

Use this prompt for the next iteration-test improvement loop when blind reviewers are finding
new sibling defects in the same source families. Do not optimize for automated eval score; assume
the deterministic score is saturated. Optimize for durable reduction in expert blind-review
synthetic confidence by improving the owning realism models.

## Goal

Move from one-off reviewer-finding patches to family-level improvements. A successful loop should
make a whole class of source-native tells harder to produce, not merely remove one reported sample.

Historical loop mining shows that most concrete fixes have tests and tend to stay fixed. The
recurring problem is broader: DNS, TLS/X.509, Sysmon/Windows identity, endpoint/eCAR ownership,
Linux/syslog process semantics, Zeek/network observation, proxy/User-Agent binding, timing profiles,
and storyline neatness keep producing sibling defects. Treat these as model gaps.

## Family-Fix Quality Gate

Before coding, write a short family contract for the selected target. Do this in notes, the loop
report, or `TODO.md`; do not rely on implicit reasoning. The contract must answer:

1. **Owning abstraction:** Which model, planner, state object, config loader, timing profile, or
   canonical event/context owns the truth?
2. **Family invariant:** What must always be true after the fix, independent of the specific
   reviewer sample?
3. **Entry-path inventory:** Which generation paths can create this family of evidence? Include
   baseline, storyline, causal expansion, world planning, source timing, raw escape hatches,
   direct emitter rendering, and any source-specific side effects that apply.
4. **Consumer inventory:** Which logs/renderers/probes/eval rules consume the truth?
5. **Sibling-risk statement:** Which sibling manifestations are expected to be fixed by the same
   change, and which are explicitly out of scope?

If you cannot name the owning abstraction, do not code yet. If the defect can be produced by more
than one entry path, the primary fix must be a shared contract, helper, planner, state transition,
config model, or validation rule. Caller-specific edits are allowed only as adapters into that
shared contract.

## Narrow-Fix Rejection Rules

Reject a proposed fix as too narrow when any of these are true:

- It checks for the exact hostname, username, command, domain, event ID sample, timestamp shape, or
  reviewer artifact instead of the underlying source semantics.
- It changes one emitter even though canonical context, state, routing, timing, or data config owns
  the value.
- It patches one caller while other callers can still create the same class of bad evidence.
- It adds another fixed offset, sentinel value, or hardcoded enumerable pool without modeling the
  source family.
- It makes the latest probe pass but does not define what sibling defects should now be impossible.

Narrow fixes are acceptable only when:

- The family truly has a single owning source-native schema, such as one Windows event's field
  placement.
- The change is an adapter that routes a caller into a newly centralized model.
- The loop report explicitly labels it as temporary containment and creates or names the follow-up
  family fix.

## Required Workflow

1. Read `TODO.md` first and mark this loop item `**IN PROGRESS**`.
2. Inspect the latest loop folder under `scenarios/iteration-test/blind-test/`.
3. Read, at minimum:
   - latest `REPORT.md`
   - all four reviewer reports
   - any `hard_probe*.json`, `reviewer_finding_probes.json`, or `probe_results.json`
   - the prior 10-20 loop `REPORT.md` files for recurrence context
4. Ignore automated eval score movement except for parse failures or hard acceptance failures.
5. Classify every latest finding:
   - `exact_regression`: a previously fixed exact defect reappeared
   - `sibling_defect`: same subsystem/family, new manifestation
   - `new_family`: genuinely new realism family
   - `scenario_polish`: authored names, tidy story, or training-exercise feel
   - `false_positive_or_unproven`: reviewer suspicion not supported by data/probes
6. Pick one or two highest-leverage families, not one or two individual samples.
7. Write the Family-Fix Quality Gate contract for the chosen family before coding.
8. Inventory sibling entry paths with `rg` and code inspection. For example, if fixing Windows
   interactive sessions, list every path that can request or mint such a session before editing.
9. Fix the root cause at the owning layer. Prefer canonical event/context/state, source timing,
   data-driven config, resolver/certificate/process/session models, or observation policy over
   emitter-only patches.
10. If implementation starts turning into multiple caller-specific patches, stop and introduce a
    shared planner/model/config/helper contract first. Then adapt callers to that contract.
11. Add focused tests for new behavior only. Do not spend this loop backfilling old missing tests.
12. Regenerate the iteration-test scenario and run targeted probes that prove the whole family
    improved, not just the reviewer sample. The probe should include at least two sibling paths
    when the entry-path inventory found more than one path.
13. In the final report, classify each fix commit as `family_level`, `adapter_to_family_model`,
    `source_native_single_schema`, `temporary_containment`, or `too_narrow`. Explain every
    non-family classification in one sentence.
14. Save loop artifacts under the next `scenarios/iteration-test/blind-test/loop-N/` folder and
    update `TODO.md` immediately when complete.

## Family-Level Priority Map

Use current reviewer evidence to choose from this priority map. If the latest reports contradict
this order, follow the latest concrete source-native blockers.

### 1. DNS Resolver And Answer Semantics

Recurring symptoms:
- TXT/C2 labels expose generator semantics.
- DKIM/SPF/DMARC answers look placeholder-like or change too freely.
- TTLs vary implausibly for the same resolver/query/RRset.
- AAAA, PTR, SRV, SOA, CDN, and SaaS answer morphology looks simplified.

Owning layer:
- DNS registry/config, DNS answer generation, resolver/cache state, and Zeek DNS rendering inputs.

Expected family fix:
- Create or extend a resolver-aware DNS answer model keyed by resolver, query, qtype, RRset, and
  authoritative/recursive mode.
- Keep domain-owned records stable through appropriate TTL/cache windows.
- Model recursive TTL decrement, cache refresh, NODATA/NXDOMAIN/empty-answer variation, CDN CNAME
  chains, provider-owned PTRs, AD SRV discovery, and long realistic DKIM key material.
- DNS tunnel content should be campaign-stable but not semantically transparent.

Probe expectations:
- No same resolver/query/qtype/RRset large TTL jumps inside cache windows.
- DKIM keys are long base64-like material, not short hex tokens.
- AD domains show plausible SRV discovery when Kerberos/LDAP traffic exists.
- Public PTRs do not simply mirror customer forward names.

### 2. TLS/X.509/OCSP Chain Coherence

Recurring symptoms:
- Issuer/subject chain breaks.
- Key type, signature algorithm, subject name, and issuer profile disagree.
- Validity windows are impossible or too clustered.
- Repeated or tiny chain pools look generated.
- OCSP status is decorrelated from client/proxy behavior.

Owning layer:
- TLS realism config/loaders, certificate profile generation, canonical X.509 context, Zeek
  SSL/files/x509/OCSP event construction.

Expected family fix:
- Generate a coherent certificate-chain object once, then render all Zeek SSL/files/x509/OCSP rows
  from that object.
- Enforce `leaf.issuer == intermediate.subject`, parent validity windows containing child validity
  windows, and key/signature/profile compatibility.
- Cache certificate identity by hostname/profile where appropriate while retaining realistic
  rotation and chain diversity.
- Keep OCSP revoked/unknown rare and behaviorally coupled to failures, denials, or explicit
  suspicious certificate narratives.

Probe expectations:
- Zero issuer/subject mismatches across emitted chains.
- Zero child certificates outliving parent validity windows.
- Zero RSA/ECDSA profile contradictions.
- Repeated hostnames reuse stable certificate identity within the modeled validity/cache period.

### 3. Source Provider Timing And Observation Shape

Recurring symptoms:
- Security/Sysmon/eCAR timing has impossible order, then after fixes becomes a fixed-margin tell.
- Zeek analyzer rows, files, x509, HTTP, SSL, and connection lifetimes need repeated ordering fixes.
- Multi-sensor Zeek offsets are either duplicated too perfectly or jittered too mechanically.

Owning layer:
- `SourceTimingPlan`, `timing_profiles.yaml`, canonical event relationships, dispatcher/source
  observation policy, and source-specific renderer inputs.

Expected family fix:
- Replace fixed offsets with bounded distributions that preserve causality but vary by source,
  host, event class, process class, sensor, and relationship.
- Ensure source-specific observation delay is planned once and reused consistently by all emitters.
- Model partial/incomplete source coverage through observation profiles, not ad hoc row deletion.

Probe expectations:
- Zero dependent rows before source-native initiators.
- No large clusters at exact offsets such as `+0.250s`, `1.2s`, or same microsecond.
- Multi-sensor observations have stable sensor-local skew plus per-flow capture variance.

### 4. Windows/Sysmon Native Identity

Recurring symptoms:
- Sysmon `ProcessGuid` looks UUID-like, counter-like, PID-encoded, or time-slope encoded.
- Windows `LogonGuid`/`LogonID` morphology improves one loop but leaks another pattern later.
- Event version/field order/field placement issues recur for specific Windows events.

Owning layer:
- StateManager identity allocation, Sysmon GUID helpers, Windows Security rendering context,
  source timing profiles, and OS-build-specific format data.

Expected family fix:
- Model native identifier families explicitly: host boot seed, process start time component,
  per-host counters with realistic gaps/bursts, and OS-build-aware event schemas.
- Keep deterministic replay, but avoid globally smooth slopes or generic UUID randomness.
- Centralize identity generation so `ProcessGuid`, `SourceProcessGUID`, `TargetProcessGUID`, and
  `LogonGuid` cannot drift by emitter.

Probe expectations:
- Sysmon GUID fields pass shape/morphology probes across all GUID field names.
- Windows event versions and EventData/UserData shapes match modeled OS build.
- LogonID/LUID allocation is ordered but bursty, not wall-clock-linear.

### 5. Endpoint/eCAR Process And Flow Ownership

Recurring symptoms:
- eCAR rows reference stale, wrong, or overly normalized process ownership.
- Local commands create network flow side effects that do not make source-native sense.
- Process parents, children, and terminations need repeated one-off ordering repairs.

Owning layer:
- Canonical process/session state, ActivityGenerator process/network ownership, eCAR emitter
  source-native rendering, process lifetime planner.

Expected family fix:
- Introduce or extend an executable-class process lifecycle model: one-shot utilities, shells,
  services, agents, browsers, helpers, and daemons should have different lifetime and parent rules.
- Attach network effects to the process that actually owns the action. Local-only tools should not
  sprout proxy/network flow rows unless the command semantics require it.
- Preserve parent/child lifetime constraints at canonical process planning time.

Probe expectations:
- Zero child or dependent eCAR rows before visible parent process creates.
- Zero process terminations before later same-process telemetry.
- Browser/curl/Docker/PowerShell-like traffic is owned by compatible processes.
- One-shot commands do not parent later unrelated one-shot commands.

### 6. Linux/syslog/Bash Session Semantics

Recurring symptoms:
- `systemd-logind`, PAM, sudo, cron, sshd, bash history, and eCAR process rows reveal separate
  synthetic PID/session models.
- Bash history has repeated command pools or isolated typos without session-local correction.

Owning layer:
- Linux session/PID allocator, syslog family renderer, bash command pool/config, eCAR Linux process
  ownership, baseline/storyline shell command planning.

Expected family fix:
- Use one Linux session/process identity model for syslog, eCAR, bash history, and network effects.
- Allocate cron/sudo/sshd invocation PIDs per job/session and bind PAM open/close/command rows to
  the same source-native identity.
- Replace evenly sprinkled typo tokens with session-local command habits, immediate corrections,
  copy/paste residue, and abandoned starts.

Probe expectations:
- No `systemd-logind` new sessions without nearby legitimate initiators when the session starts
  inside the visible window.
- Sudo command rows are bracketed by same-PID PAM open/close rows.
- Cron PIDs do not multiplex unrelated users/sessions.
- Bash command repetition is lower across unrelated users/hosts.

### 7. Host Role, Proxy, User-Agent, And Software Inventory Binding

Recurring symptoms:
- Domain controllers receive workstation-like browser/proxy/software baseline.
- Vendor User-Agents pair with incompatible domains.
- Endpoint/VPN/security-agent stacks are uniform across many workstations.

Owning layer:
- World model host roles, application catalog, host activity profiles, proxy/browser session
  generation, user-agent/domain binding config.

Expected family fix:
- Bind software inventory to host role and persona once, then derive proxy, process, module-load,
  update, and agent traffic from that inventory.
- Vendor updater UAs should only talk to compatible vendor domains and paths.
- Servers and DCs should have server-appropriate background traffic unless the scenario explicitly
  models desktop use.

Probe expectations:
- Zero vendor UA/domain mismatches for known enterprise agents.
- DC/server baseline traffic excludes workstation-only SaaS/browser/updater patterns.
- Workstation software stacks vary by persona/host without all-agents-everywhere behavior.

### 8. Scenario Narrative And Attacker Messiness

Recurring symptoms:
- Reviewers call the chain tidy, pedagogical, fully observable, or artifact names too meaningful.
- Even after source-native fixes, the story feels like an exercise.

Owning layer:
- Scenario prompt, storyline defaults, command/artifact naming, observation profile.

Expected family fix:
- Prefer ambiguous, boring, or reused names over semantically obvious malicious labels.
- Add operator hesitation, retries, wrong turns, irrelevant but plausible residue, and partial
  cleanup.
- Do not make every pivot perfectly visible in every source unless the scenario explicitly needs
  classroom clarity over blind realism.

Probe expectations:
- At least one wrong turn or ambiguous residue in each major attack phase.
- Fewer literal labels like `rogue`, `health`, `sync`, `cache`, `exfil`, or obvious C2 domains.
- Some evidence is delayed, filtered, partial, or source-local while remaining huntable.

## Selection Rule

Choose the next loop target using this order:

1. Confirmed P0/P1 source-native contradiction with probe evidence.
2. Same family recurring in at least 3 of the last 20 loops.
3. Multi-reviewer agreement across different roles.
4. Fixable at a canonical/model/config layer.
5. Can be proven by a family-level probe.

Do not choose a subjective scenario-polish issue ahead of a concrete source-native contradiction.
Do not choose a narrow sample if a family-level model change would remove the whole class.

## Done Criteria

A loop is done only when all of these are true:

- The report names the selected family, owning abstraction, invariant, entry paths, and consumers.
- The code change is primarily at the owning abstraction or clearly adapts callers to it.
- Tests cover both the central invariant and at least one non-sample sibling path.
- Rendered-output probes check family behavior, not just absence of the original reviewer example.
- The loop report identifies residual sibling risks instead of implying the family is solved.
- The score movement discussion distinguishes latest-fix regression from deeper issue surfacing.

If any item is missing, state that the loop delivered a partial fix and make the missing item the
first candidate for the next loop.

## Implementation Rules

- Follow `AGENTS.md` and `TODO.md` workflow.
- Use `rg` for search.
- Fix root causes at the owning layer.
- Keep enumerable pools data-driven in `src/evidenceforge/config/activity/`.
- Preserve deterministic generation through scoped stable seeds.
- Keep generation LLM-free.
- Do not add broad abstractions unless they reduce repeated sibling defects.
- Add or update focused tests for the new family behavior; do not backfill old missing tests in
  this loop.

## Required Output

At the end of the loop, produce a short report that includes:

- Findings classified by `exact_regression`, `sibling_defect`, `new_family`,
  `scenario_polish`, and `false_positive_or_unproven`.
- The selected family or families and why they outranked the rest.
- Root-cause layer changed.
- Tests added or updated.
- Probes run and exact before/after counts where available.
- Any remaining sibling defects in the same family.
- The next best family-level target.
