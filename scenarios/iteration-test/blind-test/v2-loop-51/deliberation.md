# EvidenceForge Assessment Loop 51 — Expert Panel Deliberation

## Deliberation Scope and Method

This deliberation synthesizes only the four independent Loop 51 reports submitted by the Threat
Hunter, Detection Engineer, Network Forensics Analyst, and Host/EDR Forensics Analyst. The
facilitator did not inspect the log corpus or any scenario, ground-truth, manifest, source-code,
history, worklog, probe, or prior-loop material. Evidence judgments below therefore concern the
specificity, corroboration, alternatives, and internal consistency of claims in those four reports;
they are not new forensic findings.

The initial verdicts, verdict confidences, and synthetic-confidence scores are preserved exactly as
reported. Final positions represent each specialty's reasoned response to the other three reports.

## Round 1 — Findings Summary

### Threat Hunter

**Initial position:** Synthetic; verdict confidence **77**; synthetic-confidence **63**.

The Threat Hunter judged the operational environment highly realistic but gave greatest weight to
three implementation-shaped artifacts:

1. A successful proxy upload reports about 44 MB on the client-facing leg but only about 18.8 MB on
   the proxy-to-origin Zeek leg, with the same disparity reflected by ASA and no reported missed
   bytes, denial, truncation, or retry.
2. Zero-padded 32-bit-style identifiers recur in 190 of 412 sampled eCAR FILE records and also
   appear in proxy tunnel IDs, exposing a shared construction pattern across nominally unrelated
   families.
3. SYSVOL paths use year folders, review suffixes, generic stems, and interchangeable extensions
   instead of a recognizable domain/GPO hierarchy.

The specialty-unique observations were the cross-leg payload-conservation failure, the
cross-family identifier morphology, and the combinatorial SYSVOL vocabulary. The report also noted
a service binary that executes without visible staging, while acknowledging that the binary could
have predated the collection window.

### Detection Engineer

**Initial position:** Synthetic; verdict confidence **72**; synthetic-confidence **56**.

The Detection Engineer's strongest findings were:

1. Security Events 4697 and 4698 use version-0 payloads on domain controllers whose visible
   Microsoft binary versions indicate Server 2022-class build 20348; expected version-1 process/RPC
   fields are absent.
2. One Security 4800/4801 pair locks and unlocks the same session only about 0.635 ms apart, an
   implausible human lifecycle interval.
3. All five reviewed Event 4779 RDP disconnects suppress `ClientName` even where the same LogonID's
   type-10 logon identifies a workstation and the disconnect retains a concrete client address.

The build-to-event-version mismatch and systematic RDP client-name loss were unique to this
specialty. The report otherwise found strong event-specific schemas, process causality, hash
stability, Zeek references, and source-native auxiliary formats.

### Network Forensics Analyst

**Initial position:** Real; verdict confidence **82**; synthetic-confidence **24**.

The Network analyst found no P0 or P1 network contradiction and emphasized:

1. Three Zeek views have distinct UIDs, stable but jittered sensor-clock offsets, and occasional
   sensor-local counter/history differences rather than cloned observations.
2. Connection states, packet accounting, protocol-child timing, TLS visibility under packet loss,
   DHCP renewals, DNS behavior, and endpoint/network outcomes are internally coherent at scale.
3. The ASA stream is source-native per record but limited to nine message IDs, while one public TLS
   source sustains a homogeneous 399-flow workload and two repeated DNS answers show small TTL
   discontinuities.

The unique positive evidence was the detailed multi-sensor skew/loss analysis and the validation of
TLS certificate visibility against `missed_bytes`. The bounded ASA vocabulary, homogeneous TLS
client profile, and TTL observations were explicitly treated as low-impact because filtered export,
stable client implementation, and resolver policy are plausible explanations.

### Host/EDR Forensics Analyst

**Initial position:** Synthetic; verdict confidence **87**; synthetic-confidence **68**.

The Host/EDR analyst's strongest findings were:

1. Forty-seven adjacent duplicate Sysmon Event 10 payloads across eight hosts and six adjacent
   duplicate Event 13 payloads across three hosts occur within 0–3 ms, retaining identical process,
   access, call-trace, registry-object, and detail fields.
2. Outlook repeatedly writes `ShownFirstRunOptin=1` in exact doublets or triplets, including
   repeated three-record shapes on one workstation and equivalent bursts on other workstations.
3. The same sub-millisecond 4800/4801 lock/unlock pair identified by the Detection Engineer is a
   localized lifecycle defect; separately, 840 of 841 UFW blocks come from eight sources with fixed
   per-source packet fingerprints and a compact destination-port pool.

The cloned Sysmon microbursts and repeated first-run registry writes were unique and high-impact
host findings. The report also identified round-number process-lifetime anchors as weak evidence,
while finding strong process, session, SSH, role, and cross-source integrity overall.

## Round 2 — Cross-Examination

### 1. Proxy payload conservation versus general network coherence

The clearest friction is between the Threat Hunter's exact upload transaction and the Network
analyst's broader statement that client and proxy-origin legs preserve payload relationships. The
Network report presents extensive aggregate and sampled support for packet accounting, loss-aware
HTTP behavior, protocol-child linkage, and multi-sensor consistency, but it does not address the
specific 44 MB-to-18.8 MB upload cited by the Threat Hunter.

On the reports alone, the Threat Hunter's evidence is stronger for that transaction: it names the
same successful operation across proxy, Zeek, eCAR, and ASA; distinguishes the client-facing and
origin-facing tuples; and identifies the absence of missed bytes or a failed terminal outcome. The
agreement between Zeek and ASA on each side makes a mere one-source parsing error less persuasive.
Re-encryption overhead cannot reasonably explain a roughly 57% reduction of an already compressed
ZIP upload. This does not invalidate the Network analyst's corpus-wide positive findings, but it
does establish a material exception to the general claim of payload preservation.

**Deliberative resolution:** accept the proxy mismatch as a high-strength localized contract gap,
while retaining the Network report's broader conclusion that most network accounting and
correlation is production-like.

### 2. Source-native Windows quality versus repeated endpoint construction artifacts

The Detection Engineer found Windows and Sysmon schemas generally excellent and did not report
duplicate Event 10/13 bursts. The Host/EDR analyst found dozens of adjacent full-payload clones
across unrelated hosts. These positions are compatible: schema correctness, PID/GUID integrity,
and causal ordering do not test whether valid records are generated in mechanically repeated
microbursts.

Could the duplicate ProcessAccess records be legitimate repeated calls? Yes, and identical
registry writes can arise from retries or notification behavior. The stronger concern is the
combination of corpus scope, full-payload identity including call traces, 0–3 ms spacing, and the
same construction shape across many hosts. The Outlook evidence is stronger still because a
first-run opt-in behaves like state yet is reasserted in identical doublets/triplets on repeated
launches and across users. The Host report supplies counts and concrete examples, while no report
offers an application-specific mechanism that explains the recurrence.

**Deliberative resolution:** treat the clone bursts and repeated first-run writes as strong
distribution-texture evidence. They supplement, rather than overturn, the Detection Engineer's
finding that the individual records are structurally valid.

### 3. The sub-millisecond lock/unlock pair

The Detection and Host/EDR reports independently identify the same session, record pair, and
approximately 0.635 ms interval. Both also note that other lock intervals last minutes. A logging
delay cannot make a human lock-to-unlock interaction complete in less than a millisecond when the
source timestamps themselves assert that lifecycle ordering. A duplicated or malformed event might
explain the artifact operationally, but that would still leave an implausible source-native pair in
the corpus.

Its limitation is scope: it is one pair, and neither reviewer found a general inversion of session
lifecycles. The reports label it P1 and P2 respectively, reflecting different views of severity,
not disagreement about the evidence.

**Deliberative resolution:** accept it as the panel's strongest hard timing contradiction, but do
not generalize it into a dataset-wide timing failure.

### 4. Server build evidence versus Security event versions

The Detection Engineer ties build-20348 Microsoft binaries on both domain controllers to version-0
4697 records and a version-0 4698 record. The other specialists did not assess those event schemas.
An alternative explanation would require old payload schemas to be produced or retained despite
the visible modern OS generation, or a collection/normalization path that selectively strips newer
fields while preserving native XML presentation. No report provides evidence for either
explanation.

The finding is only four records, but it spans both domain controllers and two event families. Its
value is source specificity: a small number of structurally wrong native records can be more
diagnostic than a large number of plausible generic records.

**Deliberative resolution:** retain this as a strong, localized source-native schema fingerprint,
with slightly less overall weight than the cross-source payload mismatch and cross-host clone
pattern because only one reviewer tested it.

### 5. Identifier morphology versus acceptable opaque identity

The Detection Engineer found eCAR identifiers collision-free and causally coherent and considered
variation among opaque object forms acceptable. The Threat Hunter instead evaluated identifier
distribution and found the same zero-padded upper-half form in 190 of 412 FILE records and in proxy
tunnel IDs.

These claims test different properties. An opaque ID can be unique and operationally usable while
still exposing an implementation recipe. The Threat Hunter's count and cross-family example make
the morphology concern more specific than the Detection report's general acceptance. Conversely,
structured or counter-derived identifiers are not inherently impossible, and the reports do not
establish what collector assigned every eCAR object ID.

**Deliberative resolution:** treat zero padding and mixed schemes as strong supporting
schema/distribution evidence, not a hard contradiction. The cross-family appearance raises its
weight; uncertainty about producer ownership keeps it below the payload and clone findings.

### 6. Firewall and scanner populations

The Network report finds only nine ASA message IDs in 18,175 lines, but correctly notes that exact
build/teardown family counts naturally follow paired connection lifecycles and that a traffic-only
export could explain the narrow vocabulary. The Host report identifies a different but related
texture: eight public sources generate nearly all UFW blocks over six hours, with stable per-source
packet fingerprints and a compact port pool. Stable fingerprints are realistic for persistent
scanners; source sanitization or filtering could reduce apparent diversity.

The two reports therefore reinforce a general concern about deliberately bounded perimeter noise,
but they do not corroborate the same records or establish a contradiction. The Network analyst's
homogeneous TLS-source observation also has a plausible stateful-client explanation.

**Deliberative resolution:** retain perimeter source/population breadth as medium-to-low-weight
distribution evidence. Do not use exact paired ASA counts, stable scanner fingerprints, or a
homogeneous client implementation as synthetic indicators by themselves.

### 7. Missing service-binary staging and other weak signals

The Threat Hunter explicitly allows that `DeviceSyncSvc.exe` may predate the visible window. No
other reviewer reports a contradictory file lifecycle, and the Host analyst found dependent events
owned by valid processes. The absence of a visible create or transfer is therefore not proof of a
generation gap. Likewise, the Threat Hunter's repeated Linux commands, Host analyst's round-number
lifetimes, Network analyst's two TTL jumps, and Network analyst's scanner homogeneity all retain
credible operational alternatives in their originating reports.

**Deliberative resolution:** none of these weak or bounded-window-sensitive observations materially
drives the consensus verdict. They remain useful lower-priority realism checks.

## Round 3 — Revised Positions

### Threat Hunter — revised position

**Final position:** Synthetic; verdict confidence **85**; synthetic-confidence **71**.

The verdict does not change. Confidence and synthetic-confidence rise because the Host/EDR report's
cross-host cloned Sysmon payloads and state-incoherent Outlook writes provide an independent
implementation-shaped family, while the Detection and Host reports independently corroborate the
sub-millisecond lock/unlock pair. The Network report's strong positive findings keep the score well
below “confidently synthetic”: most transport, timing, sensor, and lifecycle behavior remains
convincing.

### Detection Engineer — revised position

**Final position:** Synthetic; verdict confidence **83**; synthetic-confidence **67**.

The verdict remains Synthetic. The exact proxy transaction adds a cross-source contract failure
outside the initial schema-focused review, and the Host/EDR duplicate-burst counts reveal that
individually valid Sysmon schemas are being populated with repeated construction shapes. The
Network analyst's detailed validation of Zeek references, packet accounting, and loss behavior
prevents a larger increase and reinforces that the defects are concentrated rather than global.

### Network Forensics Analyst — revised position

**Final position:** Inconclusive; verdict confidence **74**; synthetic-confidence **45**.

The initial Real verdict changes to Inconclusive. The Threat Hunter's exact four-perspective upload
accounting is a stronger test of one proxy transaction than the Network report's general payload
relationship assessment, and it establishes a network-relevant exception that cannot be dismissed
as TLS overhead. Independent endpoint findings—especially cloned Sysmon microbursts and the
corroborated lock/unlock pair—also matter to a corpus-level authenticity verdict even though they do
not diminish the report's positive network analysis. Synthetic-confidence remains below 50 because
the large-scale Zeek, DNS, TLS, DHCP, loss, and multi-sensor evidence still looks production-like.

### Host/EDR Forensics Analyst — revised position

**Final position:** Synthetic; verdict confidence **91**; synthetic-confidence **75**.

The verdict remains Synthetic. The Detection Engineer corroborates the lock/unlock defect and adds
a separate build-aware Security schema mismatch; the Threat Hunter adds cross-family identifier
construction and a cross-source payload invariant failure. These are independent of the Host
report's primary clone findings, so confidence rises. The score remains below the confidently
synthetic band because process trees, PID/GUID ownership, SSH, session lifecycles, and cross-source
endpoint correlation were strong in both endpoint-focused reports.

## Round 4 — Consensus Summary

# Deliberation Summary

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|--------|----------------|----------------------------|------------------------------|---------------|--------------------------|----------------------------|
| Threat Hunter | Synthetic | 77 | 63 | Synthetic | 85 | 71 |
| Detection Engineer | Synthetic | 72 | 56 | Synthetic | 83 | 67 |
| Network Forensics | Real | 82 | 24 | Inconclusive | 74 | 45 |
| Host/EDR Forensics | Synthetic | 87 | 68 | Synthetic | 91 | 75 |

The panel's final majority assessment is **Synthetic**, with one informed **Inconclusive** position
and no remaining Real verdict. The mean synthetic-confidence score moves from **52.75 initially**
to **64.5 after deliberation**. This is not unanimous proof of synthesis: all four specialties agree
that large portions of the corpus are technically strong and production-like, and the Network
analyst continues to place substantial weight on that evidence.

## Key Agreements

- The corpus has strong process/session causality, source-native field structure, cross-source
  identity, network protocol linkage, and varied background activity. Completeness and correlation
  were treated as strengths, not as synthetic indicators.
- The 0.635 ms lock/unlock pair is a concrete visible timing defect. It is localized rather than
  evidence that all session timing is defective.
- The proxy upload mismatch is a material transaction-contract gap because the reports identify a
  successful transfer, two independently corroborated byte totals, and no loss or failure state
  that explains the difference.
- The cloned Sysmon Event 10/13 microbursts and repeated Outlook first-run writes are stronger than
  ordinary duplicate-event noise because identical payload shapes recur within milliseconds across
  unrelated hosts and users.
- The Server 2022-era 4697/4698 version mismatch and zero-padded cross-family ID morphology are
  credible source/schema fingerprints, although each carries narrower scope or producer-ownership
  uncertainty than the leading findings.
- Narrow firewall/scanner populations, repeated commands, round-number lifetimes, isolated TTL
  behavior, and absent service-binary staging have plausible alternatives and should not drive the
  verdict by themselves.

## Key Disagreements

- **Overall authenticity:** Three experts conclude Synthetic after deliberation; the Network
  analyst remains Inconclusive because extensive packet, protocol, loss, clock-skew, and
  multi-sensor checks are production-like and the strongest contradiction is localized.
- **Weight of identifier morphology:** The Threat Hunter views zero-padded IDs crossing FILE and
  proxy families as high-value implementation leakage. The Detection perspective accepts the IDs'
  uniqueness and operational coherence. The panel agrees they are suspicious but not impossible
  without clearer producer semantics.
- **Perimeter diversity:** The Host analyst sees a finite scanner pool, while the Network analyst
  finds stable client traits and a traffic-only export plausible. The panel agrees on improving
  population breadth but does not treat current breadth as dispositive.
- **Severity of the lock/unlock pair:** The evidence is agreed; the disagreement is whether one
  physically implausible pair warrants P1 or P2 weight in an otherwise coherent session corpus.

## Most Convincing Evidence

1. **Successful upload payload non-conservation.** Approximately 44 MB enters the proxy but only
   about 18.8 MB leaves toward the origin, with each side corroborated by Zeek and ASA and no
   reported loss or failed outcome. This is the strongest shared-truth contract finding.
2. **Cross-host cloned Sysmon microbursts and repeated state writes.** Dozens of identical Event 10
   payloads and repeated Event 13/Outlook first-run shapes recur within 0–3 ms across multiple
   hosts, exposing a repeated construction pattern despite valid individual schemas.
3. **Sub-millisecond lock/unlock lifecycle.** Two independent reviewers identify the same session
   transitioning from locked to unlocked in about 0.635 ms; no report offers a viable human or
   source-timing explanation.
4. **Build-incompatible Security event versions.** Server 2022-class binary evidence appears beside
   version-0 4697/4698 payloads that omit the modern process/RPC fields expected for that OS
   generation.
5. **Cross-family zero-padded identifier morphology.** A high proportion of eCAR FILE IDs and a
   proxy tunnel ID expose the same fixed upper-half pattern. This is strong supporting evidence,
   tempered by uncertainty over collector-assigned opaque-ID conventions.

The most convincing evidence for reality remains the broad set of successful negative checks:
valid process and session ordering, source-specific multi-sensor UIDs and clock offsets, realistic
packet-loss consequences, coherent protocol children, stable process/hash identity, and strong
endpoint/network correlation without fixed timestamp cloning.

## Most Debated Points

- Whether one high-value proxy transaction should outweigh corpus-wide network coherence. The panel
  concluded that it changes the corpus verdict but does not erase the positive network evidence.
- Whether identifier regularity is generator leakage or an acceptable opaque collector convention.
- Whether repeated full Sysmon payloads can be normal application behavior. Repetition is possible;
  cross-host clone counts, exact call traces, and millisecond cadence make these examples harder to
  explain naturally.
- Whether narrow ASA/UFW populations reflect generation limits or a filtered collection profile.
  The absence of an in-band collection explanation preserves suspicion but not contradiction.
- How much weight to assign isolated defects. The panel distinguished the localized lock pair and
  four versioned events from dataset-wide timing or schema failures.

## Improvement Recommendations (Consensus)

1. **Enforce one payload-size truth across proxy transactions.** Compute request-body size once and
   carry it through endpoint file read/upload evidence, proxy access records, client-to-proxy and
   proxy-to-origin flows, and firewall byte totals. Any compression, decoding, retry, truncation,
   cache behavior, capture loss, or denial must be an explicit transaction outcome with
   source-visible evidence. Add a cross-leg validation that successful forwarded uploads conserve
   payload within separately modeled protocol overhead.
2. **Deduplicate process-access and registry-effect intent before rendering.** Treat repeated calls
   as distinct operations only when a caller-owned retry or notification mechanism exists; give
   real repetitions defensible differences rather than cloning every source/target/call-trace or
   registry payload at a fixed millisecond cadence. Add corpus-level checks for adjacent normalized
   Event 10/13 payload clones across sibling hosts.
3. **Model Office registry effects as state transitions.** Emit `ShownFirstRunOptin=1` only when the
   modeled profile transitions into that state. Do not reassert it on every Outlook launch or in
   doublets/triplets unless a specific mechanism owns the repeated writes.
4. **Make Windows Security rendering build-aware.** On build-20348 systems, emit the appropriate
   4697/4698 version and populate added client-process/RPC fields from the same process/session truth
   used by Sysmon and eCAR. Preserve version 0 only for modeled releases that legitimately use it,
   and test both modern and legacy paths.
5. **Prevent human session dwell from collapsing into telemetry jitter.** Give 4800-to-4801
   transitions a broad, non-uniform, human-operable duration measured in seconds or longer; retain
   legitimate bounded-window singletons. Add an invariant rejecting same-session unlocks at
   sub-human intervals unless an explicit non-human mechanism is modeled.
6. **Use source-scoped, source-native identifier schemes.** Avoid leaking one zero-padded
   counter/hash recipe into unrelated FILE and proxy families. Test morphology and entropy per
   source family in addition to uniqueness and referential integrity.
7. **Populate RDP disconnect identity from established session state.** Carry `ClientName` from the
   correlated type-10 session into Event 4779 when known; reserve `-` for explicitly unresolved
   names and vary that outcome according to modeled name resolution or collection conditions.
8. **Replace generic SYSVOL filename matrices with native hierarchy.** Generate domain and
   `{GPO-GUID}` paths with constrained, recognizable Group Policy substructure and artifacts. Use
   year folders, review suffixes, and generic document extensions only when a modeled process or
   administrator explicitly creates them.
9. **Broaden perimeter texture without adding decorative noise.** Preserve stable per-scanner
   fingerprints and valid ASA connection/NAT pairing, but add campaign-specific lifetimes and port
   sets, source churn, and a long tail of one-off scanners. Either include low-volume ASA
   operational families consistent with the modeled appliance or make a traffic-only collection
   boundary explicit in-band.

The panel does **not** recommend forcing visible service-binary staging when the file may predate the
window, perturbing strong cross-source correlation merely because it is complete, or adding random
variation to coherent sensor offsets, packet-loss effects, scanner traits, and process identities.
Those changes would obscure rather than address the concrete findings.
