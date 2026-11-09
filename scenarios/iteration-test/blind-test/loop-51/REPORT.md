# Mac-series loop51: assessment and root-cause repair

Completed fresh validation, generation, authoritative evaluation and four independent data-only reviewers. Continuation loop8 of20 (44–63). Scenario, seed and observation/coverage controls remain fixed. Baseline-warning logic is intentionally deferred as user-requested P1 backlog.

Automated evaluation **96.4672**, 136,811 records. Hard acceptance is recorded in [authoritative eval](automated-eval.json) and [audit](artifact-audit.json). Initial synthetic-confidence scores **Threat67 / Detection28 / Network58 / Host32**, mean **46.25** (mixed/inconclusive); lower is more production-like. Prior mean58.00; current rolling5 **55.80**. Verdict confidence is separate.

Verdict/confidence/spread trigger required a fresh facilitator. Facilitator-modeled reconciliation mean **58.75**; [full report](deliberation.md). These are not reconvened votes and are excluded from initial/rolling trends.

## Root cause and source-native contract

The successful Security4698 record carried LogonType ServiceAccount. Microsoft exposes TASK_LOGON_SERVICE_ACCOUNT as a registration API enum, while the XML schema has only S4U, Password, InteractiveToken and InteractiveTokenOrPassword. The optional LogonType must be omitted for the three reserved machine accounts; UserId retains the service principal. The shared ActivityGenerator Task Scheduler XML builder owns this projection before canonical TaskContext construction. The Windows emitter only renders its content. This is an explicit single-source schema repair with shared entry paths, rather than an emitter symptom patch.

The builder now recognizes exact SYSTEM/LOCAL SERVICE/NETWORK SERVICE names and well-known SIDs, preserves SID/UPN identity forms, and retains Password for ordinary local/domain/managed accounts. It does not classify every NT AUTHORITY principal as a service account. SYSTEM and its SID retain HighestAvailable; other reserved machine accounts retain LeastPrivilege. Command/arguments/path XML escaping and schedule construction remain intact. Complete explicitly supplied raw task XML remains caller-owned. No authored scenario, seed or coverage changes.

## Verification

503 focused tests passed, covering the central builder and generator integration,13 service/user/SID/UPN identity variants, hourly parsing and ordinary task paths. The first new test fixture omitted mandatory HostContext fields; that fixture was corrected and the entire focused set passed on rerun. Ruff check and format checks pass. The fresh bundle's only changed data file is DC-01 Security XML;116 of117 files remain bit-identical to50. The one visible SYSTEM task now has no invalid LogonType; its principal and hourly trigger remain correct. Native Mac89forks107execs87exits remain complete with zero aggregate births; mounted helper exits4/4 and six authored inventory durations/fraction controls remain intact.

The four host-wide native Mac fork PID-version reversals remain visible (53 newer allocations below a prior host high-water mark). This patch does not touch native identities. Existing TCP history/capture budgets and ICMP native semantics remain verified. Deterministic evaluation96.4672 and136811 records pass all hard acceptance; the eval does not validate the complete nested task schema, so the explicit semantic probe is needed.

## Retained priorities before fresh review synthesis

P0 native audit-token chronology remains the highest-impact unresolved architectural family (canonical state/allocation/native projection; high risk). Public leaf issuance-era policy is the next bounded shared-owner repair: explicit issuer trust, historical generation and private/CA siblings require data policy and loader validation. Proxy request-header and TLS transport accounting remain related but separable P1 canonical byte-budget gaps verified by Network50. Windows4738 mask-to-token projection and4672 sensitive-rights membership, browser namespace/UA ownership and process-runtime floor remain ranked behind hard contradictions. The SCP/shell attribution observations stay qualified until the normalized direct-owner contract is established. Mac diagnostic repetition and two1ms transitions remain low-leverage weak signals; no arbitrary noise is added.

## Accepted blind synthesis and movement

TH67 / Detection28 / Network58 / Host32 mean46.25 (lower is more production-like), versus50 mean58.00; the only changed file is task XML, so the11.75point change primarily reflects different reviewer coverage. Network independently repeated the public leaf lifetime family (66distinct/258rows in its stricter DMZ subset), while TH independently reproduced the12plain-connect-scan payload tuples. Detection's5140Version0vsVersion1 documentation ambiguity stays weak/unproven pending actual provider manifest. Host's compact pidversion/vocabulary observations remain weak in that report; the independently proven four native counter reversals from prior panels remain an unresolved coordinator P0 despite this panel not proving them. No absence-of-finding is credited as a repair.

A fresh report-only facilitator modeled[70,53,65,47], mean58.75. These are not revised votes and are excluded from rolling trends. All four accepted reports and facilitator disclose only permitted actual neutral inputs/primary references; inherited generic instructions remain a blinding limitation. The17new scheduled-task native-schema failure is verified fixed by objective output comparison, not by the lower standalone score. Priority order remains P0native allocator; next bounded canonical public policy and proxy/scanner byte contracts, with the full Windows/browser/runtime backlog preserved. Reviewers did not assign P0-P4 labels, so original ratings are recorded as not labeled rather than invented.


## Independent reviewer summaries

**Threat Hunter:** Synthetic; verdict confidence 86; synthetic-confidence score 67. The dataset supports useful, technically connected hunts across a mixed fleet, including web-server execution, internal discovery, privileged Windows activity, and archive transfer through an inspecting proxy. My principal authenticity concern is a reproducible mismatch between an explicitly logged TCP connect scan and the application payload attributed to its exact connections; a secondary concern is the repeated manual SMB policy-file retrieval texture across unrelated Linux users. These findings favor synthetic data while leaving much of the operational lifecycle credible.

**Detection Engineer:** Inconclusive; verdict confidence 80; synthetic-confidence score 28. The supplied records are mostly convincing inputs for a detection stack: their formats parse, important native fields have the right types and semantics, and the visible process, session, and network relationships withstand several broad consistency checks. I found one low-confidence Windows event-version concern, but no demonstrated impossible same-identity lifecycle or decisive generator fingerprint; the data alone does not justify a confident origin attribution.

**Network Forensics:** Synthetic; verdict confidence 76; synthetic-confidence score 58. I lean synthetic because the visible public-certificate population repeatedly uses long validity periods inconsistent with the apparent 2026 issuance era across several unrelated named public issuers. This is a qualified environmental finding, not an impossible packet sequence: the flow, DNS, TLS visibility, proxy, and multi-sensor relationships otherwise hold up unusually well under mechanical checks, so the appearance score remains in the mixed range.

**Host Forensics:** Inconclusive; verdict confidence 83; synthetic-confidence score 32. The endpoint evidence is mostly production-like: process identities survive coherent lifecycles, Windows process creation agrees across native sources, and the Mac records distinguish fork, exec, credentials, audit sessions, and process termination. I found a small amount of repetitive command vocabulary but did not establish an impossible visible same-identity relationship or a defensible source-native hard contradiction; the endpoint evidence alone does not justify a confident real-versus-synthetic classification.


## Past ten Mac-series loops

| Loop | Eval | Threat | Detection | Network | Host | Average synthetic-confidence score | Interpretation | Deliberation* | Rolling5 |
|---|---:|---:|---:|---:|---:|---:|---|---:|---:|
| 42 | 96.85 | 38 | 53 | 32 | 65 | 47.00 | mixed/inconclusive | 59.00 | 50.45 |
| 43 | 96.31 | 32 | 54 | 68 | 62 | 54.00 | mixed/inconclusive | 63.75 | 50.80 |
| 44 | 96.31 | 54 | 28 | 83 | 64 | 57.25 | mixed/inconclusive | 72.25 | 54.25 |
| 45 | 96.31 | 35 | 34 | 65 | 29 | 40.75 | mixed/inconclusive | 49.50 | 53.50 |
| 46 | 96.31 | 38 | 67 | 20 | 82 | 51.75 | mixed/inconclusive | 76.25 | 50.15 |
| 47 | 96.31 | 24 | 45 | 90 | 78 | 59.25 | mixed/inconclusive | 84.00 | 52.60 |
| 48 | 96.45 | 30 | 54 | 74 | 38 | 49.00 | mixed/inconclusive | 64.75 | 51.60 |
| 49 | 96.45 | 46 | 82 | 56 | 82 | 66.50 | likely synthetic | 83.00 | 53.45 |
| 50 | 96.47 | 46 | 82 | 72 | 32 | 58.00 | mixed/inconclusive | 79.00 | 56.90 |
| 51 | 96.47 | 67 | 28 | 58 | 32 | 46.25 | mixed/inconclusive | 58.75 | 55.80 |

* Facilitator-modeled reconciliation, not reconvened votes; excluded from initial and rolling trends.

## Artifacts and input limits

[Family contract](family-contract.md), [scores](scores.json), [readable eval](automated-eval.txt), [provenance](provenance.json), [test evidence](test-evidence.json), [artifact audit](artifact-audit.json). All four raw reports remain verbatim. The audit verifies score arithmetic, all117 data hashes across authoritative/loop/neutral copies and unchanged authored inputs. Native Mac census, mounted exits and timing probes retain their separate evidence.

Accepted reviewers were delegated external data-only roles: neutral briefing/data and permitted primary public references; no scenario, source, TODO/worklog or prior reports. Generic inherited operating instructions remain an environmental limitation on strict origin blinding. Input audits rely on reported actual reads, not OS-enforced isolation. Suspicious commands were analyzed as inert log evidence. Final20-loop dashboard is due after63; historical43 dashboard is preserved.
