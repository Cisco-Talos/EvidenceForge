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
