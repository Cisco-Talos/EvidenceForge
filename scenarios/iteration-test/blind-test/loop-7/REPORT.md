# New assessment epoch — loop 7

Unchanged expanded canonical scenario and existing full reviewer instructions.
Behavior540 repairs canonical explicit-proxy CLI request ownership and adapts
transport-only gateway failures to the shared network contract.

## Scores

Automated evaluation **PASS98.4294**, **141,420records**. Parseability100,
plausibility96.8475, causality99.5381, timing98.6644, ground truth97.0969. JSON once,
human text derived; no automated regression guardrail breach.

| Expert | Initial assessment | Verdict confidence | Initial synthetic confidence | Actual deliberation |
|---|---|---:|---:|---:|
| Threat Hunter | Synthetic | 74 | 62 | 68 |
| Detection Engineer | Inconclusive | 78 | 35 | 64 |
| Network Forensics | Real | 64 | 30 | 65 |
| Host/EDR | Synthetic | 83 | 66 | 66 |
| Mean | | | **48.25—mixed/inconclusive** | **65.75—likely synthetic** |

Lower synthetic confidence is better. Initial mean increased2.75 from loop6;
rolling last-five initial mean47.2. Deliberation is excluded from the independent
trend. Actual reviewers reconsidered differing initial verdicts, then a fresh
facilitator synthesized their submitted positions. All final verdicts Synthetic,
with final verdict confidence TH83/DE76/NF78/HF83. No fabricated votes or report
rewrites; originals and all actual responses are preserved verbatim.

## Individual expert summaries and deliberation

Threat's original main concerns were policy-share file-size texture (15/51
size-bearing SYSVOL/NETLOGON observations above1MiB, including8.7MB registry.ini,
9.9MB policy.ps1 and2.8MB startup.bat) and seven Mac binary-document cat reads,
confirmed in native ES argv. It credited real SSH lifecycle staging, proxy paths,
Mac process distinctions and hunting pivots. It revised to68 after rechecking
Host's PID finding. It qualified automation, contents and collection alternatives.

Detection initially found realistic native schemas,933 Sysmon creates/786 exits,
397 matched nonbuiltin Windows sessions and13,404 protocol/connection joins, with
no demonstrated lifecycle contradiction. Mac document cat/long read intervals were
weak, related signals: storage/output/source semantics are unknown. It revised
from35 to64 primarily after independently reproducing the native Linux PID floor;
policy sizes added modest support, not a standalone impossible-file claim.

Network's initial Real verdict had moderate confidence64 and score30. Detailed
TLS key/version/chain, byte/file budgets, DNS wire minima, proxy control-versus-
payload and SSH ordering checks held. Its two weak concerns were7/8 initial DHCP
renewals near13:00–13:08 and platform-concentrated browser versions. Workday startup
and fleet policies remain credible; first-visible DNS-after-connect and missing
SMB connection rows were not scored without a collection/cache contract. Actual
rechecks of PID and policy sizes changed its verdict, score65; network strengths
remain intact.

Host independently found the Linux PID floor again:360 native CRON observations,
350 adjacent pairs,67 exactly940, identical minimum940 across ten unrelated hosts.
All Windows/eCAR process identity and lifecycle checks remained coherent. Actual
reconsideration retained66 and qualified common hidden workload/sanitization
alternatives. All actual deliberators reproduced the PID population. All also
accepted a modest policy-size reservation while recognizing repeated observations
are not unique files. Cat behavior remains one correlated family, not several
independent defects; DHCP/UA concerns remain weak. No hard contradiction emerged.

## Family repair, root ownership and proof

Classification **family_level**, scoped to literal curl/wget non-body HTTP intent
and shared proxy helper resources. Owner shared HTTP command-intent helpers and
ActivityGenerator canonical explicit-proxy caller attribution/materialization.
The old caller guard compared a real downloader command to a generic helper string
that always named '/'; failure substituted a second process for the socket.

A live caller is now matched against known destination, effective port, path/query
and method, after existing session/lifetime checks. Output/proxy/referer/header
URLs do not become request destinations. curl-I is distinct from-i; unknown config
or target overrides/body semantics are not newly accepted. CONNECT-only views bind
authority without pretending to know a hidden path. Existing explicit multipart
ownership, browser/package/service contracts and raw identities remain intact.
Fallback commands preserve known origin resource, and curl/wget methods. Arbitrary
shell/Python/PowerShell program evaluation is not claimed. family-contract.md
records entry paths, consumers, layer rationale and residual risks.

Rendered eCAR proof: Windows PID7508 and Linux PID2959192 each now own the output
FILE/CREATE and one client FLOW, with **zero nearby second-owner helpers**. Earlier
loops showed original writer/no FLOW plus a distinct helper whose root-URL command
disagreed with the inspected resource. Native Windows proof independently joins
PID7508/one ProcessGuid across Sysmon1,11,3 and WFP5156. Both probes are saved.
No generated rows were edited or supplemented after generation.

A second scoped repair is **adapter_to_family_model**: proxy phase planning owns
whether an origin application exchange occurred. The existing failed-CONNECT test
revealed that gateway-only attempts inherited success-request service/byte budgets;
behavior538's legitimate reset-progress support then inferred TLS from that bad
canonical input. This is an exact regression, not an eval defect. Transport-only
failures now pass empty application service, zero application payload and suppressed
inferred application side effects into the network bundle. Failed TCP attempt/close
and client HTTP error body remain. Eight state/port controls coverS0/REJ/RSTO/RSTR
on80/443, with noD/d application history or invented HTTP/TLS. Genuine reset/half-
close exchange support remains; the new protocol family was not reverted.

Validation: **679 focused checks passed**,4deselected,26.95s; related protocol/
native/timing siblings81 passed,3deselected (overlaps not added); targeted native
proxy storyline1 slow passed,2soak deselected,58.73s. The two older assertions
requiring HTTP reset→SF and erasing explicit responder payload were updated to the
new intended contract; one-sided unknown payload still has a negative control.
Before-failure and final logs remain. Gateway history controls8 passed separately
(overlap). Ruff/format1644 and behavior surface passed. No broad routine/release pass.

## Prioritized reported issues

Priorities/classifications below are synthesis; reviewers supplied no P0–P4 labels.

| Priority | Issue / classification | Reviewers, scope and alternatives | Owner / next action / leverage and risk |
|---|---|---|---|
| P1 | POSIX PID allocation floor; recurring new_family from loop6, distribution_texture | Host independently first this panel; all actual deliberators reproduce67/350 exact940 and shared minimum on ten hosts. Native CRON identity agrees. Common workload/sanitization remains possible. | Shared StateManager hidden churn clipping. Loop8 selected/adopted admissible count-support repair after443 focused checks, RNG policy and normal/nativeMac checkpoint gates. High leverage, medium/high identity scope risk; preserve lane capacity, preview/live, reservations/wrap/restore. |
| P2 | Policy/script file-size distribution; new_family, distribution_texture | Threat first; all actual deliberators recheck15/51 records above1MiB. Repeated accesses amplify counts; contents unknown, so no impossible-file claim. | StorageWorld canonical file-size modeling: dc_policy currently falls through generic1KB–12.6MB sampling. Bind auto-generated size distributions to file purpose/type via config; preserve explicit seed sizes, stable identity/hash and transfer-byte budgets. Medium/high leverage, medium risk; probe unique files as well as observations before implementation. |
| P2 | Windows CLI repeated launch lead; recurring unfixed family, distribution_texture | Earlier Host/panel6, not newly discovered here. Same actor/destination gaps recur across fresh terminals. | Canonical parent placement timing lacks invocation identity. Loop9 draft/prototype uses typed invocation scope and causal parent window; preserve native/source/session/transport admission. Medium leverage/risk. |
| P2 | RDP bootstrap/auth concentration; carried sibling_defect | Panels4/5 quantified target-specific transport/auth gaps and11 bootstrap499–500ms pairs. Not newly established by panel7. | Shared RDP readiness/negotiation/bootstrap graph. Draft10; retain reconnect/deadlines/source-client holds. Medium leverage/risk. |
| P2 | Attack-associated routine TXT cohort; carried new_family | Panel6 quantified34 routine records21clients isolated late in slice; not a new panel7 claim. | Routine DNS ownership/causal handler. Remove attack-owned camouflage; retain genuine workload-driven baseline and explicit attack TXT intent. Medium leverage/risk. |
| P3 | Mac binary-document reader selection/runtime; recurring sibling_defect with unproven timing claim | Threat moderate, Detection weak; native ES confirms7cat argv. Storage/output/diagnostic/collection explanations survive. | Workload intent/qualified capabilities, not an emitter rename. Avoid invented GUI execution and exact-sample changes. Medium scope risk; no proof of impossible commands. |
| P4 | DHCP initial-renewal cohort; weak_signal, false_positive_or_unproven | Network7/8 first rows near slice start; mixed lease periods valid. Common startup plausible. | Lease/host lifecycle initialization. Require stronger boot/lease contract before changing collection phase. |
| P4 | Browser version concentration; weak_signal, false_positive_or_unproven | Network platform version cohorts, HTTP observations rather than independent installations. Managed images plausible. | Host software inventory/profile binding; no unqualified native versions or extra entropy solely for scoring. |
| P4 | Missing SMB/early visible DNS; false_positive_or_unproven | Explicitly not scored by Network due window/cache alternatives. | No absence-only defect or added reviewer requirements. |

Previous native Mac fork phase preservation, Linux editor/snapd preferences and
exit outcomes remain bounded leads, not new panel7 impossibilities.

## Interpretation, quantitative limits and provenance

The higher initial mean does not establish a regression from the proxy repair.
Root probes demonstrate its actor/resource contract improvement; new reviewers
measured other file/identity populations. Changed canonical process choice also
changes later RNG-dependent activity, so this is not a matched-flow A/B experiment.
Keep the original initial scores and do not replace them with favorable rechecks.

Automated eval checks structural/causal/receipt consistency; it does not currently
penalize shared PID floors, generic policy file-size distributions or reader-choice
texture. Blind protocol/identity checks support realism but cannot authenticate
origin. Preserve both evidence types and collection qualifications.

Behavior540 digest5efb4b01a129a8e57bf15826903e5524a6879369188ef0981f21b87c8034e6bc,
seed42, four authored hashes unchanged. Generation exited0, authoritative manifest,
eval accepted. Fresh verified neutral study/private/tmp/authenticity-study-57n1ht2w
contains **118data files**; four fresh fork-none experts followed unchanged full
briefing/personas/examination requirements. No code, previous reports or engineering
hints were supplied. Candidate history and old epoch remain excluded from trends.

Post-panel metadata probe separates repeated reads:14/48 distinct UNC-path/size
versions on policy shares exceed1MiB (15/51 observations). This confirms the
large-size population is not solely repeated access to one large file. It does
not identify independent GPO content or prove any file impossible. Root probe
is retained in loop-12/prior-policy-file-size-probe.json.
