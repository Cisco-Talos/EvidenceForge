# Mac-series loop46: assessment and root-cause repair

Completed fresh validation, generation, authoritative evaluation and four independent data-only reviewers. Continuation loop3 of20 (44–63). Scenario, seed and observation/coverage controls remain fixed. Baseline-warning logic is intentionally deferred as user-requested P1 backlog.

Automated evaluation **96.3078**, 136,813 records. Hard acceptance is recorded in [authoritative eval](automated-eval.json) and [audit](artifact-audit.json). Initial synthetic-confidence scores **Threat38 / Detection67 / Network20 / Host82**, mean **51.75** (mixed/inconclusive); lower is more production-like. Prior mean40.75; current rolling5 **50.15**. Verdict confidence is separate.

Verdict/confidence/spread trigger required a fresh facilitator. Facilitator-modeled reconciliation mean **76.25**; [full report](deliberation.md). These are not reconvened votes and are excluded from initial/rolling trends.

## Root repair and validation

[Contract](family-contract.md) classifies the repair as `source_native_single_schema`: valid canonical full DNS RDATA and storage facts were serialized with the wrong Zeek shape. The DNS adapter now renders SRV target, MX exchange, SOA primary name and native TXT/SPF character-string summaries; shared TXT partitioning also owns wire sizing. SMB2/3 mapping omits optional SMB1-only service/native_file_system observations instead of deriving them from share names or backing filesystem. Canonical answers, storage knowledge and already-native raw records are preserved. No exact-sample branches or scenario changes.

203 focused protocol/parser/persistent-publication tests pass, plus the selected slow cross-platform SMB integration test. Config validation covers101 files with no issues; Ruff check/format pass. Revision445 digest `80d4f0147272157c104dcf4b35dd1d17b013a126fd60ebb6b8e6895212294f66`. No additional full routine run for this uncommitted loop; pre-push gate/reconciliation is in the worklog.

[Rendered probe](dns-smb-native-probe.json) verifies exactly415 changed DNS sensor rows (120 SRV,8 MX,3 SOA,284 TXT) and132 SMB mappings; all other fields agree with45. Only four files change;113 are byte-identical. Duplicated sensor rows are not unique transactions. Native Mac forks89/89, execs107/107, expected exits87/87, aggregate births0, mounted helper exits4/4, fraction/inventory timing unchanged. ASA qualified order/reset mismatches remainzero; stream/capture contradiction remainszero. Automated eval changes96.3094→96.3078, above the guardrail with all hard criteria passing and no material regression.

## Fresh findings and score movement

The initial mean rises40.75→51.75. This is deeper issue discovery and reviewer coverage variance:113 files, including every endpoint file, are unchanged. Host's82 identifies a previously qualified but now Apple-source-supported native counter chronology defect. Detection67 identifies browser instance ownership and4672 membership. Network20 finds no high-confidence network contradiction and inspects corrected SRV examples, but this is not exhaustive independent certification of every repaired field. Neither mean movement nor the clean network verdict is a controlled A/B effect estimate. Threat38 questions scanner identifiers and qualifies Linux socket attribution; it does not independently discover the native Mac counter.

## Prioritized reported issues

Priorities and classifications are coordinator synthesis. Original reviewer P0–P4 ratings were not provided. Scope counts below are dependent populations, not separate votes.

| Priority | Finding / classification | Reporter / original rating | Scope and leverage | Owning layer, risk and action |
|---|---|---|---|---|
| P0 | Native Mac audit identity counter chronology / sibling_defect | Host46, not labeled; prior qualified allocation lead |MAC-MROSS-02 new fork versions69→47,84→72,95→88,111→97 while occurrence/mach/global-sequence advance; high |Canonical native identity allocation/planning. Apple pinned XNU fork/exec use a shared counter. Strong new evidence; exact OS-build and sanitizer alternative remain qualified. High architectural risk: planning-order reservation cannot be hidden by emitter renumbering; preserve all parent/responsible/exit/eCAR references. Inventory chronological allocation owner before repair. |
| P1 | Browser profile singleton and ownership / new_family | Detection46, not labeled |Mac01 plus two positively observed Windows pairs; high |Application/world/process lifecycle owner. Same user/profile roots overlap with their own helpers/networking and no distinct data-directory arguments. Preserve handoff and continuing owner; explicit separate profiles must remain possible. Medium–high risk. |
| P1 | Security4672 sensitive privilege membership / sibling_defect | Detection46, not labeled |271/408 rows across10 hosts; medium–high |Auth realism data/loader/native projection. Ordinary token rights leak into event-specific sensitive list. Policy/enrichment caveat retained; medium risk. Validate profile/fallback/direct paths without changing token grants. |
| P1 | HTTP literal fragment / sibling_defect | Detection42 carried, not labeled; fresh coordinator46 |13 proxy requests; high locally |Canonical HTTP/proxy wire context; bounded medium-risk47 repair already selected from carried evidence while46 panel ran. Preserve encoded%23, query, CONNECT, Location and client navigation intent. |
| P1 | Multipart timing and runtime support / sibling_defect | Threat44 and Host43/44 carried, not labeled |One related upload timing case; broad runtime support concern; medium–high |Action bundle byte availability/process lifetime and runtime profiles, respectively. Still unchanged. Threat46 explicitly qualifies file analysis interval as exact application commit; independently verify stronger same-content/transport/process semantics before changing timing. Medium–high risk. |
| P2 | Normalized Mac SSH logout gap / contract_gap | Detection45 carried, not labeled |One session object39502e16-8050-4eaa-99a0-25f8d5ed2185; medium |Source observation grouping. Preliminary code inventory finds remote transport/login tuple grouping omits logoff, allowing different drop/delay. Not repaired or proven yet; test Linux/RDP siblings. Ordinary source loss remains alternative to origin inference. |
| P2 | Nikto test identifier fidelity / new_family | Threat46, not labeled |316 requests,315 identifiers,40 base paths; medium |Scanner catalog/test identity owner; stable test/variant IDs rather than per-request arbitrary labels. Spoofed/custom scanning and multiple tests per path remain possible. Low–medium risk after primary test inventory. |
| P3 | Linux shell socket attribution / false_positive_or_unproven | Threat46, not labeled |One wrapper/network chain; low–medium |POSIX execution/pipeline bundle. Determine whether FLOW claims socket owner or activity ancestor, then preserve real descendant ownership. Missing descendants alone are not proof of collection defect. Medium risk. |
| P4 | S0 single-SYN population, vocabulary and console/storage leads / false_positive_or_unproven | Network46 and carried specialists, not labeled |3,730 TCP S0 observations plus qualified older leads; low |Firewall drops/scans explain S0. No arbitrary retries/noise/parent rewrite. Native references and role context required before change. |

## Recommendations and next steps

Finish the bounded47 HTTP semantic repair already prepared from the reproducible carried contradiction. Treat the newly substantiated Mac counter as highest severity, but do not patch it with source-local renumbering or timestamp edits: it crosses immutable execution identities, retained proofs, parent/responsibility references and multiple sources. Inventory its canonical chronological owner and explicitly label any deferral. The browser-instance family and event-specific privilege catalog are high-leverage subsequent repairs; session observation coherence and scanner test identity are bounded siblings. Preserve fixed scenario, valid transport/capture contracts and complete native Mac coverage.


## Independent reviewer summaries

**Threat Hunter:** Inconclusive; verdict confidence 79; synthetic-confidence score 38. The supplied six-hour slice is operationally credible across Windows, Linux, macOS, network sensors and the explicit proxy. My strongest authenticity concern is localized scanner texture, with a secondary, less certain question about process ownership in normalized endpoint records; I did not establish an impossible visible lifecycle or a native-format contradiction sufficient to call the dataset synthetic confidently.

**Detection Engineer:** Synthetic; verdict confidence 82; synthetic-confidence score 67. The records are highly usable for detection work: the supplied XML and JSON parse successfully, and extensive identity, lifecycle, transport, and byte-accounting joins did not reveal basic causal failures. My synthetic verdict instead rests on two narrower findings: repeated independent Chrome browser instances under the same apparent profile, and widespread inclusion of nonsensitive token privileges in native Security 4672 payloads. These support “likely synthetic,” while the generally strong source formatting and the possibility of unobserved application/audit configuration keep the score below the hard-contradiction band.

**Network Forensics:** Inconclusive; verdict confidence 88; synthetic-confidence score 20. The supplied network records look substantially like production telemetry: packet accounting, DNS transactions, TLS certificate relationships, proxy behavior, and independent sensor observations survive a broad set of consistency checks. I did not establish an impossible network relationship or a strong generator fingerprint; this supports a low synthetic-appearance score, but cannot establish that the records actually originated on a production network.

**Host Forensics:** Synthetic; verdict confidence 93; synthetic-confidence score 82. Most endpoint relationships are convincing: Windows process identities, session ownership, Linux SSH sequences, and macOS fork/exec lifetimes survive direct checks. The decisive exception is a repeated reversal of newly allocated native macOS audit identity versions on MAC-MROSS-02; its timestamps, monotonic clock, sequence numbers, and process start times all establish the order, while the identity allocator runs backward in several blocks.


## Past ten Mac-series loops

| Loop | Eval | Threat | Detection | Network | Host | Average synthetic-confidence score | Interpretation | Deliberation* | Rolling5 |
|---|---:|---:|---:|---:|---:|---:|---|---:|---:|
| 37 | 96.09 | 43 | 32 | 34 | 68 | 44.25 | mixed/inconclusive | 56.25 | 51.20 |
| 38 | 96.09 | 40 | 38 | 62 | 69 | 52.25 | mixed/inconclusive | 62.25 | 51.75 |
| 39 | 96.09 | 44 | 20 | 30 | 66 | 40.00 | mostly realistic | 49.50 | 47.90 |
| 40 | 96.09 | 43 | 35 | 56 | 44 | 44.50 | mixed/inconclusive | 49.50 | 46.30 |
| 41 | 96.09 | 64 | 63 | 84 | 63 | 68.50 | likely synthetic | — | 49.90 |
| 42 | 96.85 | 38 | 53 | 32 | 65 | 47.00 | mixed/inconclusive | 59.00 | 50.45 |
| 43 | 96.31 | 32 | 54 | 68 | 62 | 54.00 | mixed/inconclusive | 63.75 | 50.80 |
| 44 | 96.31 | 54 | 28 | 83 | 64 | 57.25 | mixed/inconclusive | 72.25 | 54.25 |
| 45 | 96.31 | 35 | 34 | 65 | 29 | 40.75 | mixed/inconclusive | 49.50 | 53.50 |
| 46 | 96.31 | 38 | 67 | 20 | 82 | 51.75 | mixed/inconclusive | 76.25 | 50.15 |

* Facilitator-modeled reconciliation, not reconvened votes; excluded from initial and rolling trends.

## Artifacts and input limits

[Family contract](family-contract.md), [scores](scores.json), [readable eval](automated-eval.txt), [provenance](provenance.json), [test evidence](test-evidence.json), [artifact audit](artifact-audit.json). All four raw reports remain verbatim. The audit verifies score arithmetic, all117 data hashes across authoritative/loop/neutral copies and unchanged authored inputs. Native Mac census, mounted exits and timing probes retain their separate evidence.

Accepted reviewers were delegated external data-only roles: neutral briefing/data and permitted primary public references; no scenario, source, TODO/worklog or prior reports. Generic inherited operating instructions remain an environmental limitation on strict origin blinding. Input audits rely on reported actual reads, not OS-enforced isolation. Suspicious commands were analyzed as inert log evidence. Final20-loop dashboard is due after63; historical43 dashboard is preserved.
