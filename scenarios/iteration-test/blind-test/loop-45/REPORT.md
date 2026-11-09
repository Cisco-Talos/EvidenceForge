# Mac-series loop45: separate TCP stream extent from captured traffic

Completed fresh validation, generation, authoritative evaluation, four valid fresh blind reviews and triggered facilitator-modeled deliberation. This is continuation loop2 of20 (44–63). Authored scenario, seed, coverage and deferred baseline-warning logic remain fixed.

Automated evaluation **96.3094**, all hard criteria PASS,136,813 records in117 files. Initial synthetic-confidence scores **Threat35 / Detection34 / Network65 / Host29**, mean **40.75**, mixed/inconclusive; lower is more production-like. Rolling5 **53.50**. Verdict confidence mean75 is a separate statistic. Facilitator-modeled positions47/46/65/40 average49.50; these are not reconvened votes and are excluded from trends.

## Root repair and verification

[Family contract](family-contract.md) names source observation as owner. Frozen typed `TcpStreamExtent` retains directional known sequence extent independently of physically captured traffic. Ordinary and persistent SMB final rebinding share the boundary policy. Explicit allowlisted checkpoint migration preserves legacy unknowns. Zeek renders established stream extent while captured packet/IP/gap and HTTP/file content retain their own ledgers. Canonical wire truth is not inflated or recomputed in the emitter. Classification: family_level with renderer/codec adapters; no exact-sample branch.

372 focused owner/protocol/checkpoint tests and133 ASA regression tests pass; Ruff check/format and behavior validation pass at revision444, digest `8dbfb57f508a1ac736f7de2a2e6439febfe4ae68e7229bb029129e619b3f00d4`. Full routine suite was reconciled before the initial push and not repeated for this uncommitted loop.

Only three Zeek conn files change;114 other files match44 byte-for-byte. Across1319 changed rows every non-stream field is unchanged. Conservative complete-flow cross-sensor contradictions fall412/10/47 to0/0/0 at the same eligibility1824/41/191 (overlapping populations). The broader514+56 comparisons also becomezero. Stream gaps remain present; application/file content is not recovered from sequence extent. Missing boundaries retain conservative unknown behavior.

ASA qualified order/reset mismatches remainzero. Native Mac coverage remains89/89 forks,107/107 execs,87/87 expected exits; no aggregate births. Mounted helper exits4/4 and all authored inventory/fraction timing remain unchanged. See [stream proof](stream-capture-repair-probe.json), [scope](data-change-scope.json), [native coverage](native-coverage-probe.json), [timing](mac-timing-probe.json), [tests](test-evidence.json).

## Independent reviewers

**Threat Hunter:** Inconclusive; verdict confidence 78; synthetic-confidence score 35. The supplied six-hour mixed-platform slice is mostly production-like and supports technically coherent hunts across endpoint, authentication, network, proxy, and file evidence. A narrow, repeatedly reused macOS interactive command vocabulary supplies a limited behavioral texture concern, but I did not establish a hard contradiction or a sufficiently strong independent set of defects to decide synthetic versus real reliably.

**Detection Engineer:** Inconclusive; verdict confidence 80; synthetic-confidence score 34. The supplied telemetry is mostly production-like from a detection ingestion and correlation perspective: it parses, preserves meaningful source-specific differences, and survives several broad identity, interval, and lifecycle checks. I found one bounded normalized-session closure gap on a Mac, but no demonstrated impossible process ordering, malformed native identity, or transport/application contradiction sufficient to establish synthetic origin. The low synthetic-confidence score describes the observed realism; the higher verdict confidence describes my confidence that this evidence does not support a decisive origin determination.

**Network Forensics:** Synthetic; verdict confidence 80; synthetic-confidence score 65. The network evidence is operationally convincing: transport state, protocol references, flow byte budgets, proxy behavior, and TLS visibility generally agree. I nevertheless favor synthetic because two recurrent source-native formatting problems occur across many records: DNS answers use zone-style values where Zeek logs different summaries, and SMB tree mappings put share names in the resource-type field. These are concrete rendering defects, rather than judgments about intrusion narrative or collection completeness; undocumented postprocessing of genuine logs remains an alternative explanation.

**Host Forensics:** Real; verdict confidence 62; synthetic-confidence score 29. The endpoint evidence is mostly production-like: process identities survive lifecycle transitions, Linux authentication has meaningful intermediate stages, and macOS fork/exec evidence distinguishes successive images from separate process lifetimes. I found mild repetition in command vocabulary, but no demonstrated impossible same-identity ordering or source-native contradiction strong enough to support a synthetic verdict; the Real verdict is consequently tentative.

## Score interpretation and isolation

The16.5-point mean reduction from57.25 does not establish causal effect: endpoint files are byte-identical, yet host score falls64→29 because the fresh reviewer tests different populations. Network no longer reports the stream contradiction and identifies separate DNS/SMB projection defects. No repaired-family regression is demonstrated. Standalone scores are neither a controlled A/B estimate nor a model capability comparison.

Two attempted reviewers read repository memory before data/scoring; both were discarded unscored and replaced. [Discard record](discarded-review-attempts.json) preserves this. Four accepted reviewers and facilitator report only neutral prompt/data and permitted public documentation reads. Generic harness/AGENTS instructions remain inherited; strict origin blinding is limited. This is a self-reported input-scope audit, not OS enforcement. Future delegated prompts explicitly disallow repository memory and require stopping unscored on contamination.

## Prioritized findings

Priorities are coordinator synthesis; reviewers did not assign P0–P4 ratings. Repeated sensor rows are not independent transactions.

| Priority | Finding / classification | Reviewer and original rating | Scope / leverage | Owner / risk / action |
|---|---|---|---|---|
| P1 | DNS native answer projection / new_family | Network45, not labeled |415 sensor rows, one family; high | Source-native schema; full canonical RDATA is valid for other consumers. Verify pinned native SRV/MX/SOA/TXT handlers then adapt Zeek projection. Low–medium risk; first46 target. |
| P1 | SMB mapping service meaning / new_family | Network45, not labeled |132 core mappings; medium–high | Source-native SMB version projection. Preserve path/share_type; avoid fabricating SMB1 service for SMB2. Low risk after primary verification;46 sibling target. |
| P1 | HTTP literal fragment / sibling_defect | Detection42 carried, not labeled |13 fresh requests; high locally | Shared HTTP/proxy construction; medium risk. Preserve encoded fragments, query and navigation intent. Next bounded family. |
| P1 | Multipart relay/client completion / sibling_defect | Threat44 carried, not labeled |One transaction, related timing facets; medium–high | Action bundle byte availability/process lifetime, medium–high risk. Same-sensor upstream end precedes ingress by0.890498s and curl exits before response; verify buffering/termination alternatives. |
| P1 | Short process runtime bounds / sibling_defect | Host44/43 carried, not labeled |Windows733 min3.004s plus Linux short-stage bounds; medium–high | Runtime profiles/lifecycle owner, medium risk; preserve dependency protection. Not independently retested by45 host. |
| P2 | Missing normalized Mac SSH logout / contract_gap | Detection45, not labeled |One in-window session; medium | Exact session object39502e16-8050-4eaa-99a0-25f8d5ed2185 LUID0x138a1ed4 on MAC-MROSS-02 has native terminal evidence, no eCAR logout. Trace bundle/observation ownership; collection loss remains plausible. Medium risk. |
| P3 | Console parents/storage roles/Mac allocation / false_positive_or_unproven | Prior specialists, not labeled |Carried qualified leads; low–medium | World/process/storage owners. Require native qualification before changing behavior; high risk if guessed. |
| P4 | Repeated diagnostic/developer/COM vocabulary / false_positive_or_unproven | Threat45 and Host45, not labeled |Same-user habits/standard images plausible; low | No arbitrary randomization. Native comparison and role/task intent before expansion. |

## Recommendations

Repair verified Zeek DNS and SMB projection semantics in46 while preserving canonical RDATA and typed SMB facts. Then address request-target construction, proxy timing and runtime-family support. Trace the bounded normalized SSH omission before deciding whether it is generation or collection. Keep the fixed benchmark and explicit warning deferral; no forced noise or arbitrary coverage loss.

## Past ten Mac-series loops

| Loop | Eval | Threat | Detection | Network | Host | Average synthetic-confidence score | Interpretation | Deliberation* | Rolling5 |
|---|---:|---:|---:|---:|---:|---:|---|---:|---:|
| 36 | 96.09 | 57 | 18 | 62 | 65 | 50.50 | mixed/inconclusive | 64.50 | 55.90 |
| 37 | 96.09 | 43 | 32 | 34 | 68 | 44.25 | mixed/inconclusive | 56.25 | 51.20 |
| 38 | 96.09 | 40 | 38 | 62 | 69 | 52.25 | mixed/inconclusive | 62.25 | 51.75 |
| 39 | 96.09 | 44 | 20 | 30 | 66 | 40.00 | mostly realistic | 49.50 | 47.90 |
| 40 | 96.09 | 43 | 35 | 56 | 44 | 44.50 | mixed/inconclusive | 49.50 | 46.30 |
| 41 | 96.09 | 64 | 63 | 84 | 63 | 68.50 | likely synthetic | — | 49.90 |
| 42 | 96.85 | 38 | 53 | 32 | 65 | 47.00 | mixed/inconclusive | 59.00 | 50.45 |
| 43 | 96.31 | 32 | 54 | 68 | 62 | 54.00 | mixed/inconclusive | 63.75 | 50.80 |
| 44 | 96.31 | 54 | 28 | 83 | 64 | 57.25 | mixed/inconclusive | 72.25 | 54.25 |
| 45 | 96.31 | 35 | 34 | 65 | 29 | 40.75 | mixed/inconclusive | 49.50 | 53.50 |

* Facilitator-modeled reconciliation, not reconvened votes; excluded from initial and rolling trends.

## Artifacts

[Scores](scores.json), [eval](automated-eval.json), [readable eval](automated-eval.txt), [deliberation](deliberation.md), [provenance](provenance.json), [audit](artifact-audit.json). Raw reports are preserved verbatim. Audit verifies117 data hashes across authoritative, loop and neutral copies, unchanged authored hashes and score arithmetic. Final dashboard is due after63; historical43 dashboard remains intact.
