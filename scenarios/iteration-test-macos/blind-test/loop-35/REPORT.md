# Loop 35: loaded browser release and external RDP reconnect identity

The canonical Windows root-process execution path now captures the loaded executable
release. The shared browser client helper consumes that release for Chrome, Firefox
and Edge User-Agent majors in baseline browsing and network planning; dispatcher
projection resolves the loaded image instead of later installed content. Unknown
identities and non-browser tool policies remain explicit. This is a family fix with
caller adapters, not a renderer rewrite. The same tuple/ProcessGuid/FileVersion probe
finds134 mismatches among315 matched requests in34, and0 among381 in35.

The first generation exposed the external-source RDP reconnect re-keying diagnosed
in33. The repaired exact graph authenticates an existing-session-only ACTIVE patch
without a source-process allocation batch. NEW/PREALLOCATED/SSH allocations and empty-
batch rejection remain strict; manager-owned sessions cannot fall through legacy
re-key publication. Native tests preserve session start/identity, existing process
identities, PID counters and checkpoint restoration, with one initial4624 and a4778
reconnect. Failed432 console and behavior snapshots are retained; accepted retry433
passes all lifecycle assertions. Seventy native RDP tests and508 focused authority,
composition, process, deployment and proxy tests pass. A recovery test stub was updated
to declare its absent Mac ingress; its recovery/order assertions remain intact.

Ruff/format pass. Validation/generation/eval pass96.7114,132927records,118files. Both
transport-family rendered probes remain0. This repairs an architectural reconnect
identity failure and browser release inconsistency; it does not calibrate aggregate
protocol distributions. Score comparisons combine changed counts/activity and fresh
reviewer variance, so direct probes carry the causal verification.

Next targets: P1 configured Linux daemon quota saturation (Detection/Host33, repeated,
baseline/config owner, medium risk); P1 first-HTTP phase millisecond quantization
(Network34, repeated, canonical phase owner, low/medium risk); P1 authenticated SSH
phase packet accounting (Threat32, contract gap, medium risk). Reviewer original
priority labels were not assigned for these carried findings. Scenario-authored Mac
timing is preserved, and private-build/zero-exit suspicions remain unproven.


## Family contract

# Browser identity and loaded executable version

Classification: sibling_defect; family_level plus adapters. Canonical Windows process roots capture exact known binary version, as Mac roots already do. Browser UA major consumes that same loaded release/PE metadata via one shared ActivityGenerator helper used by baseline browsing and network binding. Unknown/virtual identities remain unbound; no emitter derives versions. Cover Chrome/Firefox/Edge, ordinary Windows process sibling, existing Mac identity, tool/command UA policies and loaded-version recovery. No scenario or app-version changes. Medium risk: earlier content binding must preserve publication and checkpoint ownership.

Additional root family: exact external-source RDP reconnect. Diagnostic reproduces the
same external reconnect re-keying found in33: parent token uses the new LUID while its
lifecycle session retains the original LUID. Extend the authenticated ACTIVE RDP graph
to permit an existing-session-only State patch with no allocation batch/source process.
NEW/PREALLOCATED sessions and SSH still require their exact nonempty batches; ordinary
empty batches remain invalid. Bind the no-allocation variant into integrity tokens,
composition proofs, exact dependent reconnect occurrence and manager generation.
Session identity/start remain unchanged and existing lifecycle assertions stay intact.
Test native external reconnect, forgery/type rejection, ordinary modeled-source sibling,
checkpoint continuation and existing Type9 parent handoff.


## Individual expert summaries

**Threat Hunter:** Inconclusive; verdict confidence 78; synthetic-confidence score 48. The collection supports useful hunting across a mixed fleet, and the major process, authentication, and transfer chains I tested work together technically. Several baseline command patterns look templated, especially shell manipulation of binary business documents on both Macs, but I did not establish an impossible same-identity lifecycle or source-native contradiction strong enough to distinguish synthetic data confidently from a selected, sanitized production collection.

**Detection Engineer:** Synthetic; verdict confidence 95; synthetic-confidence score 77. The records are structurally convincing and most explicit identity and protocol relationships survive programmatic checks. My synthetic verdict rests on two measurable timing fingerprints: all 115 Linux sudo command/PAM-open pairs preserve exactly the same sub-millisecond timestamp remainder, and 41 of 100 macOS ES fork observations occur in repeated microsecond-phase groups. These are strong distribution artifacts, rather than demonstrated impossible lifecycles or missing-source assumptions.

**Network Forensics:** Inconclusive; verdict confidence 78; synthetic-confidence score 42. The network evidence is substantially production-like: connection state, packet accounting, protocol companions, certificate identity and sensor-specific observations generally agree. A small cluster of file-versus-transport observation inconsistencies and infrastructure traffic choices raises suspicion, but I did not establish a decisive impossible protocol sequence or generator identity leak.

**Host Forensics:** Inconclusive; verdict confidence 79; synthetic-confidence score 43. The endpoint evidence is substantially production-like: Windows process identities and binary hashes are stable, visible process lifecycles are coherent, and macOS telemetry distinguishes forks, successive executable images, and process termination. A shared, narrow administrative vocabulary across otherwise different Linux hosts raises a moderate texture concern, but I did not establish an impossible endpoint lifecycle or source-native contradiction sufficient to confidently classify the collection as synthetic.


## Scores and comparison

Automated eval 96.7114; standalone synthetic-confidence average 52.50 (mixed/inconclusive), prior loop 59.25. Lower is more production-like. Scores are standalone reviewer measurements; physical/semantic probe outcomes independently verify the selected family.

Facilitator-modeled deliberation averages 66.25; see deliberation.md. Modeled revised positions are excluded from standalone and rolling averages and are not reconvened expert votes.
