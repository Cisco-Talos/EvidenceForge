# New assessment epoch — loop 20

Behavior 555 resolves native macOS process generations using the existing canonical
host-wide hidden process-birth history. Scenario, four authored hashes, seed 42,
default target, pack and complete reviewer instructions remain unchanged. This is
not a calibrated kernel workload model, and it does not invent unobserved execs.

## Scores and review

Automated evaluation passed **98.41037730212695** for **144,748 records**, above
acceptance and dynamic guardrails. JSON ran once; human-readable text was derived.
Four fresh, independent fork-none experts reviewed 116 SHA-verified neutral
data-only files. No scenario, code, ground truth, earlier results or targeted
examination requirements were supplied. All neutral files were reverified after
review.

| Expert | Initial verdict | Verdict confidence | Initial synthetic-confidence score |
|---|---|---:|---:|
| Threat Hunter | Synthetic | 78 | 62 |
| Detection Engineer | Synthetic | 78 | 63 |
| Network Forensics | Real | 65 | 28 |
| Host/EDR | Inconclusive | 77 | 49 |
| Mean | | | **50.50 — mixed/inconclusive** |

Lower synthetic-confidence is better. Initial mean increased 12.75 from loop 19;
the five-loop rolling mean is **42.60**. This is reviewer attention/variance and a
new deeper Windows duration finding, not a demonstrated regression from the Mac
history repair. A data-only delta proves that only four files changed from 19:
two Mac ES files' audit-token PID versions and two Mac eCAR files' current/previous
PID versions. Every other data file is byte-identical; rows, timing, process
counts, Windows lifetimes and authored Mac fork phases are unchanged.

Threat Hunter found a shared lower edge across 774 matched Sysmon process pairs,
minimum 3.029 s and 25 between 3.029–3.298 s, while finding credible operational
pivots. Detection primarily identified three exact-phase Mac fork bursts plus a
weak cups-browsed location-value concern; native schemas and actor/target joins
otherwise held. Network found production-like protocol outcomes, DNS/TLS/HTTP
semantics and one qualified unmatched SMB reference. Host found repeated daemon
vocabulary, a concentrated Windows server process mix and weak local Mac job-control
texture, while finding coherent endpoint identity and source-specific lifecycles.

Verdict disagreement and a 35-point initial spread triggered deliberation. The
original four experts independently rechecked the other original reports and raw
data, then wrote their own responses. A fresh facilitator summarized those actual
responses: **70 / 72 / 64 / 72**, mean **69.50**, all Synthetic. These revised scores
are separate from the initial trend. Detection confirmed the duration concern but
qualified it: Security has 773 matched pairs, minimum 2.722882 s, four under 3 s;
eCAR has 765 pairs, minimum 2.722 s, eight under 3 s. Neither has an under-one-second
pair. Thus the exact three-second boundary is strongest in Sysmon, rather than a
universal hard process impossibility. The Mac fork phases remain a strong texture
concern with deliberately scheduled activity as an alternative explanation.

## Selected family contract and owner

Classification: **family_level**. `MacosAuditIdentityLedger.seal()` formerly densely
ranked committed fork/exec facts chronologically. State's audit PID-version values
are opaque reservation handles used by authenticated proofs, not the native output
numbers. The fix preserves those handles and resolves one shared native map from
the chronological canonical facts plus existing State POSIX hidden-birth history
since the registered boot. Hidden births legitimately consume generations; hidden
execs are not guessed. Different hosts retain their own boot/history namespaces.

An optional frozen `native_generation_history: posix_hidden_births` policy selects
this behavior; absence preserves exact legacy dense resolution. The shared State
sealing adapter is used by both engine close/retry (including eCAR-only) and native
ES ingress finalization. Engine close restores the run's frozen configuration and
generation-seed scopes. Configuration is loaded before the State lock. Normal
engine finalization requires a known boot; raw unknown-boot compatibility remains
explicit. No new persistent State field, history cache or resource ceiling exists.

The SQLite resolution streams through the existing 1,024-row page bound and is
atomic. Invalid negative, boolean, decreasing or overflowing history rejects
without a partial sealed result. Fork/exec order, same-time deterministic ties,
uint32 bounds, native parent/responsible/target tokens and eCAR current/previous
versions all use the same map. Existing canonical ledger, boot and hidden-birth
checkpoint state rebuild that map after recovery; source filtering does not
allocate identity. State/materialization/cohort, baseline/storyline/causal/boot,
native-only, eCAR-only and restored runs consume the same owning truth.

## Output proof and verification

Mac 01 now exposes 101 unique generations spanning **2,482,477–2,521,078** rather
than 12–112; Mac 02 exposes 122 spanning **6,461,355–6,511,896** rather than 12–133.
These values come from the already-modeled host process history. This is a lower
bound on total kernel generation consumption, not a native rate calibration.
The change-scope probe compares all 116 files and reports only the four PID-version
files/fields above. Installed inode population, root metadata and exact authored
fork phases retain their prior values. No unrelated repair credit is claimed.

Gates: 43 central cases then 44 owner-scope/nondefault-seed cases; 37 stamped
manifest/history cases; dedicated slow global temporal RNG policy 3 passed with
unchanged census; public native job full/native-only equivalence and active-job
checkpoint 2 passed in 112.37 s; native Mac workspace checkpoint 1 passed in 138.79 s;
supported partial-coverage eCAR-only diagnostic consumer 1 passed in 11.35 s.
Configuration validated 105 files with zero issues; Ruff/check-format passed for
1,673 files. Counts overlap. No full routine suite or release gate is claimed.

An initial attempt to exclude native ES from an explicitly COMPLETE-native test
fixture correctly rejected that unsupported profile. The failure is preserved;
the original complete full/native-only test was restored, and a separate supported
PARTIAL eCAR-only profile proves that sealing path. No production coverage guard
or benchmark coverage was weakened. Actual generation session 19620 and
postprocessing session 35423 both exited 0 before any loop 21 engine change.

## Prioritized findings and recommendations

Categories and priorities below are synthesis; reviewers supplied no P0–P4 labels.

| Priority | Finding | Category / classification | Scope, leverage, owner, risk and action |
|---|---|---|---|
| P1 | Windows process-duration lower tail | distribution_texture / new_family | Threat Hunter, independently confirmed in all actual cross-examinations. High leverage, medium risk. Inspect shared lifetime policy and source close constraints; preserve source-specific timing and ensure lightweight commands have an operation-appropriate short tail. The Sysmon boundary is not an exact universal canonical floor. |
| P1 | Repeated Mac fork phases | distribution_texture / carried sibling_defect | Detection, confirmed in deliberation: ten forks in three bursts among 103. High impact but explicit zero-jitter authored offsets own these times. Keep the approved scenario and native birth/wall/Mach truth fixed through loop 30; any deliberate benchmark revision starts a separate epoch. |
| P1 | Linux console handoff | contract_gap / carried new_family | Confirmed by loop 19 and owner audit, not rediscovered by this panel. Loop 21 adapts ordinary console auth into canonical same-lifetime exec and session-owned parent/teardown. Preserve GDM/SSH and bounded-window interpretation; native closing and full idle-getty supervision remain qualified residual scope. |
| P2 | cups-browsed numeric printer locations | weak_signal / new_family | Detection found ten messages across three clients with bare six-digit values after printer-location wording. Medium potential leverage, low-medium risk after upstream qualification. Inspect shared parameter rendering and source-native message contracts; do not merely substitute arbitrary strings. |
| P2 | Windows server background process mixture | distribution_texture / new_family | Host found four families composing 67–90% of creates on four servers, with repeated balanced counts. Medium leverage/risk; shared service/workload selection owns it. Managed software and source filters remain alternatives. Qualify before changing counts or adding noise. |
| P2 | Repeated Linux daemon vocabulary | distribution_texture / carried new_family | Host found four irqbalance messages and similarly sized daemon populations across hosts. Medium-low leverage. Qualify actual daemon messages, verbosity and persistent state before changing shared activity/config; finite real logging vocabularies are legitimate. |
| P3 | Local Mac foreground process groups | weak_signal / new_family | Host found 55 direct local-zsh command execs retaining login groups while SSH tty commands use separate groups. Low-medium leverage, potentially high native scope risk. Inspect job-control intent and shared qualified terminal command owner; disabled MONITOR is a valid alternative. |
| P3 | Unmatched SMB mapping | weak_signal / false_positive_or_unproven | Network found 1/141 mappings without a visible conn row. Slicing, retention and collection loss remain plausible. Do not manufacture a duplicate transport or count missing pre-window initiation as a defect. |
| P2 | Installed Mac filesystem population | distribution_texture / carried sibling_defect | Earlier engineering census still shows 29/31 installed paths in spans 96/108 with ordered birth times. Not rediscovered here and not repaired by PID-version history. A coherent installed filesystem/snapshot population owner requires separate qualification. |

Continue the already-qualified console adapter for 21; prioritize the newly
corroborated Windows duration family next. Keep weak collection and daemon hypotheses
separate from confirmed ownership gaps. Automated evaluation remains a guardrail;
it does not assess the source-population texture driving these blind scores.

## Provenance

Behavior 555, surface SHA256
`5ac45fb2c8362a80856894255a62f202b43deef97fea28bdabe5717a51892e0f`.
Neutral study `/private/tmp/authenticity-study-as2dgysj`, 116 verified data files.
All four authored hashes and briefing/persona source hashes are unchanged; technology
pack 1.0.0 is unchanged. No old/candidate epoch scores are inherited. Requested total
remains 30; dashboard is generated only after the final requested loop.
