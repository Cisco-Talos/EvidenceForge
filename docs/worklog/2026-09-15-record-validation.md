# Unified record validation

## Contract and baseline

- Branch: `codex/record-validation`, based on freshly fetched `origin/dev` at `787fd733`.
- Immutable comparison checkout: `/tmp/eforge-record-validation-baseline` (detached).
- Preserve scenario/pack schemas, overlay precedence, project-root behavior and CLI exit codes.
- Correctness checks apply to every record and gate acceptance at 100%; realism remains diagnostic.
- Validation-only changes must preserve raw generated evidence; any generator correction requires
  separate evidence and a separate commit. Package version remains unchanged.

## Execution

Implementation and the iteration-test follow-up repairs are complete locally. The defects discovered
by the full iteration run are documented below together with their repairs and passing final gates.
External CI awaits explicit publication approval. No generator correction or version bump was made.

## Audit inventory

25 formats: bash_history, cisco_asa, ecar, proxy_access, snort_alert, syslog, web_access,
windows_event_security, windows_event_sysmon, zeek_conn, zeek_dhcp, zeek_dns, zeek_files,
zeek_http, zeek_ntp, zeek_ocsp, zeek_packet_filter, zeek_pe, zeek_reporter, zeek_smb_files,
zeek_smb_mapping, zeek_smtp, zeek_ssl, zeek_weird, zeek_x509.

42 co-occurrence rules: Windows Security 14, conn 4, eCAR 12, syslog 2, Snort 2,
web 2, DNS 2, HTTP 2, bash history 2. Four malformed JSON Logic rules overlap
with these or require semantic correction. Their migration classification and final results
will be recorded below.

## Scope decisions and compatibility

- Format/rule YAML and evaluation thresholds remain package-owned. Supported overlays, pack catalogs,
  scenario schemas, composition precedence, and CWD/explicit project-root resolution are unchanged.
- Native DNS metadata is optional when the corresponding message was not observed. Removed the
  incomplete closed qtype/rcode name pools; known numeric/name pairs must agree. Missing response
  metadata and empty/root query diagnostics remain warnings. Source contract:
  https://docs.zeek.org/en/current/scripts/base/protocols/dns/main.zeek.html
- HTTP CONNECT is supported by existing generation and now by the web field schema as well as the
  record rule. TRACE remains supported. Failed CONNECT responses may carry an error body.
- eCAR FILE/RENAME is retained; object/action pairs share one schema-owned contract.
- Windows Security selectors now come from variant metadata, including aliases, 4778/4779 and
  separate task deleted/disabled/enabled variants. Sysmon address/family checks apply only when both
  fields are observed. Malformed numeric Windows fields are parse failures; native absent-port
  sentinels retain their documented conversion.
- Windows identity/privilege/session enrichment rules remain context-dependent diagnostics. Sparse
  metadata and deliberately unusual certificate/OCSP intervals must not be mistaken for impossible
  records. Cross-record lifecycle, visibility, cryptographic and causal checks remain specialized.
- Dependency removal changes runtime checkpoint fingerprints. Existing exact-resume compatibility
  policy is retained; an older checkpoint cannot silently ignore a changed dependency/runtime
  fingerprint. The behavior revision declares no rendered-evidence change, supported by byte checks.
- Canonical skill sources and reference mappings were updated; project skills were regenerated with
  `eforge install-skills --agent chatgpt`. No installed artifact was edited by hand.

## Format review matrix

| Format | Record contract / retained specialized ownership |
|---|---|
| bash_history | Nonempty command and username; parser owns history timestamp syntax. |
| cisco_asa | Existing source message parsing and field schema retained; firewall correlation stays specialized. |
| ecar | One object/action relation including FILE/RENAME; conditional required identity/network fields; sparse enrichment diagnostic. |
| proxy_access | Finite, nonnegative traffic/tunnel counters; existing proxy routing and transactions stay specialized. |
| snort_alert | Priority bounds and endpoint presence; existing IDS canonical/cryptographic checks retained. |
| syslog | Nonempty message/hostname; Linux message-specific lifecycle checks retained. |
| web_access | Status range, reconciled methods, finite/nonnegative counters. |
| windows_event_security | Metadata selectors/aliases, task variants, ClientPort conversion; contextual logon enrichment diagnostic. |
| windows_event_sysmon | Variant selection, source/destination address types and IPv6 correspondence, port bounds. |
| zeek_conn | SF duration/counter presence, valid transport, finite/nonnegative counters; zero-duration warning. |
| zeek_dhcp | String message-type list, finite/nonnegative lease; DHCP lifecycle remains specialized. |
| zeek_dns | Numeric/name relationships, answers/TTLs correspondence, float TTL elements, optional partial metadata. |
| zeek_files | Finite/nonnegative counters and typed lists; avoid requiring full file observation or cross-record equality. |
| zeek_http | CONNECT body semantics, reconciled methods, nonnegative body counters; HTTP/file agreement specialized. |
| zeek_ntp | Finite time/interval fields and nonnegative extension count; no blanket synchronized-server assumption. |
| zeek_ocsp | Typed values; reversed interval diagnostic; cryptographic verification remains specialized. |
| zeek_packet_filter | Existing boolean/string source-health contract; no inferred sibling evidence. |
| zeek_pe | Typed list elements; file/process/cryptographic identity stays specialized. |
| zeek_reporter | Existing source-health scalar contract; warnings can describe legitimate unusual evidence. |
| zeek_smb_files | Rename source name; SMB action/session/storage semantics remain specialized. |
| zeek_smb_mapping | Existing tree/share schema; topology and backing storage semantics remain specialized. |
| zeek_smtp | Typed recipient/forwarding lists; conversation/envelope/lifecycle checks remain specialized. |
| zeek_ssl | Typed certificate/protocol lists; TLS chain/observation checks remain specialized. |
| zeek_weird | Existing source diagnostic contract; unusual traffic itself is not a correctness violation. |
| zeek_x509 | Typed SAN lists and finite validity fields; reversed interval diagnostic, certificate checks specialized. |

## Baseline evidence

- Isolated environments: `/private/tmp/eforge-rv-baseline-env` and
  `/private/tmp/eforge-rv-candidate-env`, each installed from its own frozen lockfile. Dependency diff
  removes only json-logic-qubit and its six dependency. Package version stays 2.1.0.
- Nine frozen generation comparisons cover typed activity in default/threaded, SOF-ELK®/serial,
  Splunk/threaded, filtered Zeek, system families, SMB phases, periodic content, foreground process
  ownership, and process companions. All 236 artifact comparisons match. `generation.log` is
  excluded; manifest creation times are normalized and every manifest file hash is independently
  verified by `scripts/compare_cleanup_output.py`. Ground truth and observation sidecars are included.
- The extra resolver fixture was rejected by the existing capture harness because it is not in that
  harness's frozen input inventory. This was a harness precondition failure, not output divergence.
- All 18 scenario fixtures compile in baseline and candidate in sequential fresh processes, including
  Scenario 1.0, Scenario 2.0, industry and organization packs. Full compiled payloads match after
  excluding only changed package-owned format/threshold/co-occurrence/behavior documents and their
  effective_config/compiled digests. Scenario entities, supported configuration, provenance and pack
  locks otherwise match exactly.
- Representative authoritative bundle: 1,045 records from 17 sources. Schema and correctness both
  score 100% after correcting HTTP method policy. No generator correction was needed for this bundle.
- Three relevant slow fresh-process determinism tests passed (`--no-cov`). Routine checkpoint smoke
  verifies suspended/resumed output against uninterrupted output, including emitted evidence.

## Verification status

Earlier full runs exposed stale behavior fingerprints while source files were still being edited,
plus skill-size/packaging expectations. These were corrected. Final passing results are recorded
below; the earlier failed runs are retained here as execution history.

## Complete rule inventory

The 42 `legacy-N` IDs retain a traceable mapping to the old co-occurrence rule order. New semantic
checks use descriptive IDs. Error rules gate correctness; warning rules are realism/context
diagnostics. Scalar type/constraint checks additionally apply to every declared field.

| Rule | Category | Contract |
|---|---|---|
| `bash_history.legacy-1` | objective correctness | Command is non-empty |
| `bash_history.legacy-2` | objective correctness | Has username |
| `ecar.legacy-1` | objective correctness | PROCESS records have pid |
| `ecar.legacy-2` | context-dependent / realism diagnostic | PROCESS/CREATE records have canonical primary tid |
| `ecar.legacy-3` | context-dependent / realism diagnostic | PROCESS/TERMINATE records have canonical primary tid |
| `ecar.legacy-4` | objective correctness | All records have objectID |
| `ecar.legacy-5` | objective correctness | PROCESS/CREATE has image_path |
| `ecar.legacy-6` | context-dependent / realism diagnostic | PROCESS/CREATE has ppid |
| `ecar.legacy-7` | context-dependent / realism diagnostic | PROCESS/CREATE has command_line |
| `ecar.legacy-8` | context-dependent / realism diagnostic | THREAD/REMOTE_CREATE has target info |
| `ecar.legacy-9` | context-dependent / realism diagnostic | PROCESS/OPEN has source image |
| `ecar.legacy-10` | objective correctness | FLOW events have network fields |
| `ecar.legacy-11` | objective correctness | SERVICE/CREATE has service name |
| `ecar.legacy-12` | context-dependent / realism diagnostic | USER_SESSION LOGIN has principal |
| `ecar.object-action` | objective correctness | Unsupported object/action combination |
| `snort_alert.legacy-1` | objective correctness | Alert has valid priority |
| `snort_alert.legacy-2` | objective correctness | Alert has source and destination |
| `syslog.legacy-1` | objective correctness | Syslog has non-empty message |
| `syslog.legacy-2` | objective correctness | Syslog has hostname |
| `web_access.legacy-1` | objective correctness | Request has valid status code |
| `web_access.legacy-2` | objective correctness | Request has HTTP method |
| `windows_event_security.legacy-1` | context-dependent / realism diagnostic | Network logon (type 3) requires valid IP |
| `windows_event_security.legacy-2` | context-dependent / realism diagnostic | Interactive logon (type 2) uses local workstation |
| `windows_event_security.legacy-3` | context-dependent / realism diagnostic | Process creation has process name |
| `windows_event_security.legacy-4` | context-dependent / realism diagnostic | Logoff must have a logon type |
| `windows_event_security.legacy-5` | context-dependent / realism diagnostic | Logon has valid SID |
| `windows_event_security.legacy-6` | context-dependent / realism diagnostic | Failed logon has status code |
| `windows_event_security.legacy-7` | context-dependent / realism diagnostic | Special privileges has privilege list |
| `windows_event_security.legacy-8` | context-dependent / realism diagnostic | Process termination has process name |
| `windows_event_security.legacy-9` | context-dependent / realism diagnostic | Kerberos TGT has krbtgt service |
| `windows_event_security.legacy-10` | context-dependent / realism diagnostic | Kerberos service ticket has service name |
| `windows_event_security.legacy-11` | context-dependent / realism diagnostic | NTLM validation has workstation |
| `windows_event_security.legacy-12` | context-dependent / realism diagnostic | Kerberos preauth failure has status |
| `windows_event_security.legacy-13` | context-dependent / realism diagnostic | WFP connection has direction |
| `windows_event_security.legacy-14` | context-dependent / realism diagnostic | Explicit creds has target server |
| `sysmon.source-family` | objective correctness | IP address must agree with IPv6 flag |
| `sysmon.destination-family` | objective correctness | IP address must agree with IPv6 flag |
| `zeek_conn.legacy-1` | objective correctness | Completed connection (SF) has duration |
| `zeek_conn.legacy-2` | objective correctness | Completed connection (SF) has byte counts |
| `zeek_conn.legacy-3` | objective correctness | Connection has valid protocol |
| `zeek_conn.legacy-4` | context-dependent / realism diagnostic | Completed TCP (SF) cannot have zero duration |
| `zeek_dns.legacy-1` | context-dependent / realism diagnostic | DNS query has non-empty query field |
| `zeek_dns.legacy-2` | context-dependent / realism diagnostic | DNS response has rcode |
| `dns.qtype-name` | objective correctness | qtype and its name must agree |
| `dns.rcode-name` | objective correctness | rcode and its name must agree |
| `dns.answer-ttls` | objective correctness | Answers and TTLs must correspond |
| `zeek_http.legacy-1` | objective correctness | HTTP CONNECT must not have response body |
| `zeek_http.legacy-2` | objective correctness | HTTP response has method |
| `zeek_ocsp.interval` | context-dependent / realism diagnostic | Validity interval is reversed |
| `smb.rename-source` | objective correctness | Rename requires previous name |
| `zeek_x509.interval` | context-dependent / realism diagnostic | Validity interval is reversed |

## Additional frozen-tree evidence

- The one-hour mixed-platform `checkpoint-all-formats.yaml` baseline and candidate captures match
  across all 26 hashed artifacts. Its 1,407 parsed records pass both record/schema gates at 100%.
  This caught and corrected a parser conversion regression: Security `Protocol` is numeric, Sysmon
  `Protocol` is textual. The regression now has a focused test.
- Across scenario comparisons, native files cover 22 formats. The three source-health/anomaly formats
  (`zeek_packet_filter`, `zeek_reporter`, `zeek_weird`) did not appear in those bounded scenarios.
  Their unchanged templates render identical native bytes in both environments; committed native
  parser fixtures and schema witnesses cover them. This is renderer/parser coverage, not a claim
  that those scenarios emitted all 25 formats. Expanding generation of those diagnostics is a
  separate source-routing/observation investigation; no generator patch was made speculatively.
- Positive schema witnesses cover all 25 formats and all 43 Windows/Sysmon variants. Each required
  field is removed in turn, and every bundled record rule has explicit positive/negative witnesses.
  New tests include malformed definitions, malformed native inputs, optional DNS observations,
  Sysmon protocol representation, source sentinels, engine-error outcomes, exact single-violation
  acceptance, cached field plans, and clean command JSON failure envelopes.
- Correctness scoring now executes once per record in the normal scoring pass, retaining only
  bounded diagnostic samples. On repeated parsed DNS records with tracemalloc enabled: 1,000 records
  took 0.188 s, 10,000 took 1.867 s, and 20,000 took 3.757 s (about 5,300 records/s). Incremental traced
  peak allocation was 14.9/12.0/12.0 KiB respectively, excluding the already-parsed input collection.
  This measures the shared schema/correctness pass, not total multi-pillar evaluation memory.
- Final focused parser/evaluator/contract run: 322 passed. Relevant slow fresh-process determinism:
  3 passed in 25.64 s, without coverage. Ruff check/format and the revision-90 generation-behavior
  declaration check pass. Full macOS routine and remote Linux/Windows CI results are recorded below when complete.

## Final parser boundary repair

A final truncation probe found that an unterminated `<Events>` wrapper could yield zero parsed
records. Windows parsing now records unmatched/malformed wrappers as parse failures, while a
complete empty wrapper remains an empty input. Four regression cases cover this distinction;
271 parser/contract/evaluator tests pass after the repair. This changes no generated bytes.

External CI has not run: automatic approval review rejected `git push` because external publication
was not explicitly authorized. No push occurred. The committed branch and draft-PR description are
prepared locally; user approval to push/open the draft is required to run Linux/Windows CI.

## Local completion results

- Full macOS routine run: **8,844 passed, 67 skipped, 2,023 deselected**, without coverage
  (338.69 seconds). The wrapper repair additionally passes its 271-test focused gate.
- A final HTTP boundary check extends the migrated CONNECT guard from only 200 to every 2xx
  response. This is required by RFC 9110 section 9.3.6, not a new scenario restriction:
  https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6 . Seven explicit status-boundary tests
  distinguish successful tunnels from failed CONNECT error responses. This affects evaluation only.
- Final focused rule/parser/checkpoint/behavior gate: **261 passed** in 23.93 seconds. A fresh
  candidate generation after the final rule adjustment matches all 29 baseline artifacts again.
- Local work is complete. Remote Linux/Windows CI remains blocked solely on explicit approval to
  publish the local feature branch and open a draft PR.

## Full iteration-test follow-up (supersedes the completion statement above)

At the user's request, ran the current `scenarios/iteration-test/scenario.yaml` unchanged against
baseline `787fd733` and candidate `3c4323fb`, using their isolated locked environments. Both CLI
commands ran from the same project root, with `--seed 42 --target default`, normal threaded
rendering, and the default checkpoint cadence. The Scenario 2.0 input uses six hours of collection,
two hours of warmup, the Meridian Healthcare Solutions organization pack 1.1.0, technology industry
pack 1.0.0, and the `enterprise_standard` observation profile. Input SHA-256:
`f397d25ebb47d21ae2232bd3d1022bcedc96eb8d75a58b65fa7db5462c24e9a4`.
Validation passed; no scenario, configuration, pack, or generator changes were made for this test.

### Generation comparison: PASS

- Both generate commands exited 0. Outputs are retained in
  `/private/tmp/eforge-rv-iteration-baseline` and `/private/tmp/eforge-rv-iteration-candidate`.
- Both contain 143 files excluding `generation.log`; no files are missing or extra. All 141 files
  other than the resolved scenario and generation manifest are raw-byte identical, including native
  evidence, ground truth, observation/collection/storage sidecars, and payload/email artifacts.
- Independently verified all 142 file hashes in each generation manifest and each resolved-file
  hash. Both seeds, targets, selected pack identities/digests, and runtime metadata match.
- `RESOLVED_SCENARIO.yaml` differs only in package-owned format definitions, migrated co-occurrence
  rules, exact schema/correctness thresholds, and the three resulting configuration/document digests.
  Authored scenario, resolved entities, assets, provenance, and other effective configuration match.
- `GENERATION_MANIFEST.json` differs only in `created_at`, `compiled_sha256`,
  `resolved_file_sha256`, and `files.RESOLVED_SCENARIO.yaml`.
- Native data occupies 76,175,193 bytes. Both evaluators account for 123,105 records in 22 source
  categories, including 25 `email_artifacts` records. This is 21 native log formats plus the artifact
  category; this run does not contain Zeek NTP, packet_filter, reporter, or weird records.
- Comparison script and full enumerated metadata differences are retained at
  `/private/tmp/eforge-rv-iteration-compare.py` and
  `/private/tmp/eforge-rv-iteration-comparison.json`.

### Evaluation: candidate integration defects found

- Baseline evaluation completes its pillars, overall 96.3267, acceptance FAIL because temporal
  integrity is 83.3333 against its unchanged 85 minimum. Its legacy record validator additionally
  reports one eCAR FILE/RENAME false rejection (123,104/123,105 passing).
- Candidate parseability and plausibility pillars fail with `ConfigurationError: Format definition
  not found: email_artifacts`. Their new generic format loading mistakenly includes this specialized
  artifact source. These pillars are unmeasured; no 100% schema/correctness claim is warranted.
- The existing engine catches those pillar exceptions, continues producing a partial report, and
  exits 0. Acceptance correctly fails for the unmeasured required gates, but the execution failure
  is not surfaced as exit 22. This remains a gap in the requested explicit engine-error contract.
- Both baseline and candidate write validator warnings before the JSON document on stdout; the
  candidate also writes pillar tracebacks there. Raw stdout is therefore not valid JSON. The prior
  narrow JSON checks did not cover this richer input. Original stdout/stderr are retained separately;
  `*-report.json` files extract the report object for diagnosis without rerunning evaluation.
- Candidate causality and timing match baseline exactly, including the same eight temporal-integrity
  findings (40/48 expected-visible events correctly timed). Both load the observation manifest and
  apply identical filtered/dropped/delayed/out-of-window accounting.
- Do not interpret the candidate's partial overall score (93.5685) as a realism regression: two
  scoring pillars did not execute. The evidence bytes are identical.

Reports: `/private/tmp/eforge-rv-iteration-{baseline,candidate}-report.json`; original captured output:
`/private/tmp/eforge-rv-iteration-{baseline,candidate}-eval.json` and corresponding `.err` files.
Next implementation work must restore specialized email-artifact handling without silently accepting
missing native schemas, surface pillar execution failures explicitly, and keep JSON stdout clean.
The full iteration scenario should become a regression gate for these interactions.


## Evaluator routing repair

Implemented explicit Pydantic-validated source routes for all 26 parser sources: 25 native schemas
and the named email-manifest artifact validator. Shared command preflight and evaluation verify
registry completeness; duplicate parser registration, duplicate/missing/stale routes, unavailable
schemas, and unknown artifact validators fail explicitly. Inventory tests also reconcile all 25
native emitter registrations and parse all 29 embedded Jinja template strings.

Email artifacts retain their existing open extension metadata and optional fields. Known scalar and
recipient-list types are checked; malformed top-level shapes, sections, message entries, and dates
remain counted failures. Invalid values retain raw evidence but do not reach specialized indexes
(for example, a list-valued Message-ID cannot crash a dictionary lookup). Complete empty sections
remain empty inputs. Existing email/SMTP/file consistency checks remain active.

Pillar execution failures now abort evaluation through the existing CLI exit-22 boundary, without
an incomplete quality report. Completed evaluations with failed acceptance retain exit 0. Logging
is configured on stderr for each CLI invocation, preserving clean JSON stdout across repeated
in-process invocations. Normal execution failures have concise diagnostics; verbose mode retains
explicit traceback access. CLI help, canonical evaluate skill, and shared validation references are
updated; installed skills were regenerated through `install-skills` (sandbox-authorized write).

Coverage now includes 66 native render/parse/validate cases spanning all native formats and every
supported Windows/Sysmon variant, with explicit Bash and Snort source-native rendering paths. A
committed compact email/SMTP/connection fixture verifies normal scoring and cross-source subject
agreement; corrupt manifest cases verify completed failed acceptance rather than pillar crashes.
The slow iteration test generates twice in fresh processes, verifies manifest hashes, compares all
manifest-owned bytes including the resolved scenario, and requires all four pillars to complete
with exact schema/correctness scores.

Generation behavior revision 91 declares `impact: none` for the expanded preflight/error surface;
package version remains 2.1.0. Two repaired fresh-process captures match all 141 baseline evidence
files and the pre-repair candidate, with manifest hashes independently verified. The first final
revision-91 slow-test capture also matches those 141 frozen-baseline files; metadata changes are
restricted to the packaged validation/behavior contracts and derived provenance hashes.

The repaired full iteration evaluation parses all 123,105 records and completes every pillar:
schema and record correctness 100%; plausibility 96.88451591546246; causality 93.9846681096681;
timing 93.04839206783377. Overall is 96.32697441984939, acceptance FAIL solely for the unchanged
83.3333 temporal-integrity score against 85. No new evidence violation was found after repairing
routing. Original output remains unchanged; reports are in `/private/tmp/eforge-routing-final-report.json`
and corresponding `.err`, with comparison evidence in `/private/tmp/eforge-routing-byte-comparison.json`.

Initial full routine run: 8,940 passed, one skill-word-limit failure, 67 skipped, 2,024 deselected.
The skill text was shortened and its focused gate passed. Final focused routing/parser cases:
143 passed; skill/routing gate: 96 passed. Checkpoint resume and behavior gates: 24 passed.
Final full routine and slow results follow below when complete. Linux/Windows CI remains unrun;
no branch publication is authorized by this repair request.


### Final repair gates

- Full routine suite: **8,946 passed, 67 skipped, 2,024 deselected**, `--no-cov`, 352.20 seconds.
- Final routing/parser/engine/skill focused gate: **159 passed**, 4.25 seconds.
- Slow iteration plus determinism gate: **4 passed, 7 deselected**, `--no-cov`, 474.27 seconds.
  This includes two complete fresh-process iteration generations and a full successful evaluation
  execution; schema/correctness gates are 100%, while the known temporal gate still fails acceptance.
- Checkpoint suspension/resume and behavior manifest gate: **24 passed**, 24.80 seconds.
- Ruff check and format check pass (883 files); `git diff --check` is clean. Behavior revision 91
  digest: `01d8e495c09bb88c163a1142a30bf272eaf4fba201c29ccb26b3173c61eccbed`.
- Final revision-91 captures have identical file sets and all 142 manifest-owned files are identical
  between fresh processes, including `RESOLVED_SCENARIO.yaml`. Against frozen baseline, all 141
  non-metadata evidence/sidecar/artifact files match. The only changed files are the resolved scenario
  and generation manifest; resolved changes are exclusively the enumerated package-owned validation
  documents and derived digests. Comparison details and hashes are retained in
  `/private/tmp/eforge-routing-final-comparison.json`.
- Logs: `/private/tmp/eforge-routing-routine-final.log`, `/private/tmp/eforge-routing-final-focused.log`,
  `/private/tmp/eforge-routing-slow.log`, `/private/tmp/eforge-routing-checkpoint.log`.
- Immutable baseline checkout remains clean. No generator correction, scenario/pack/overlay edit,
  package-version bump, push, or PR publication occurred. Linux/Windows CI remains outstanding.

## Pre-PR gap closure (2026-09-15)

### Requirement matrix

| Requirement | Status | Evidence / boundary |
|---|---|---|
| 1. Returned correctness/diagnostic/artifact execution errors | Passed | Scoring calls `require_evaluated` before aggregation; CLI fault injection checks exit 22, empty stdout, rule/source/variant/fields. Library compatibility remains `valid=False` plus errors/findings. |
| 2. Native malformed-record matrix | Passed | All 66 format/Windows variant witnesses; 2,044 required JSON/XML mutations; six malformed text timestamps; 51 rules through native parsing (101 pass/fail cases, one explicitly inapplicable native case); 310 JSON fields with null/empty/dash/object/bounds/nonfinite/list cases. |
| 2. Malformed values through all pillars | Passed | One combined CLI batch covers all 25 native formats, every required-field mutation and every JSON field with an invalid object. Exact source counts remain; completed FAIL exits 0. |
| 3. Historical checkpoint | Passed | Baseline suspension, untouched copy, exact refusal/no mutation, read-only status/verify, compatible hydration/resume, one migration, dependency diagnostics and 24 byte-identical evidence files against both uninterrupted controls. |
| 4. Scenario/config/pack compatibility | Passed | 55 comparison entries across two projects and Scenario 1.0/2.0; all command exits match. Supported effective values, entities, provenance, pack locks/build/import/hydration match. Detailed differences retained. |
| 4. Target generation bytes | Passed | Full iteration SOF-ELK serial and Splunk threaded captures: 141 evidence files each match baseline, with manifest hashes independently verified. |
| 4. Target evaluation | **Failed / merge blocker** | SOF-ELK Snare lacks the full XML contract and has ambiguous flattened field labels. No schema waiver or generation change made. Splunk JSON parser repaired; exact record gates now pass, but indicator accuracy is 71.9215%. |
| 4. Five-run full-evaluation performance | Passed | Isolated full parsing/all-pillar runs on the same 123,105-record baseline evidence; final median candidate 12.1033s versus 12.3028s baseline, with slightly lower peak RSS. |
| 4. Routine/slow/Ruff/behavior gates | Results below | First routine run found missing navigation in the expanded checkpoint reference; fixed and installer rerun. |
| 4. Linux/Windows CI | Externally pending | No publication authorized. Local macOS tests do not substitute for CI. |
| 5. Independent review / merge readiness | Externally pending | No independent review or PR publication. The target findings above remain explicit blockers. |

### Repairs and demonstrated defects

- Shared scoring now converts **returned** `evaluation_error` findings into `EvaluationError`
  before aggregate totals, including diagnostics and artifact validators. Ordinary malformed evidence
  is not an execution fault. The diagnostic boundary includes the rule, source, variant and fields.
- Bash epochs outside platform time range, or beyond Python's integer-string conversion limit,
  previously raised before producing a record. Both now remain counted parse failures.
- The combined native mutation batch exposed an OCSP diagnostic comparing malformed operands, then
  a distribution index using a dictionary-valued field as a key. Diagnostics now check operand
  schema validity; parseability records schema failures in a run-local set. Later pillars consume
  the usable-record view, while source totals and exact acceptance retain every malformed record.
  Well-typed cross-field contradictions still reach specialized evaluators. No catch-and-continue
  or acceptance relaxation was added.
- Baseline checkpoint hydration initially rejected frozen JSON Logic format documents. A narrowly
  recognized immutable-snapshot decoder now promotes the two known legacy format documents and
  threshold policy in memory. Full-document hashes must match, and native rendering templates must
  remain identical. Stored snapshots are untouched; arbitrary old disk/internal syntax is still
  rejected. Promoting only rule lists was insufficient: Windows renderer identity also depends on
  canonical field metadata, which the final decoder preserves coherently.
- Full Splunk target evaluation exposed text-only web/proxy parsers. The new Apache JSON adapter
  maps the existing target fields, preserves source-native values, rejects conflicting aliases and
  malformed shapes/types/timestamps, and retains CONNECT authority versus ordinary request-path
  semantics without inventing URL schemes. Compact native fixtures cover positive and corrupted
  records through parsing, scoring and CLI acceptance. No emitter was changed.

### Historical checkpoint evidence

`tests/integration/test_validation_checkpoint_upgrade.py` is the reproducible slow gate. Set
`EFORGE_VALIDATION_BASELINE_PYTHON=/private/tmp/eforge-rv-baseline-env/bin/python` and run it with
`-m slow --no-cov`. Routine decoder tests use committed immutable baseline YAML fixtures, so they
need no external checkout. The mixed Windows/Linux fixture has one hour warmup, three hours of
collection, seed 42, hourly checkpoints, and the existing synchronization harness.

The verified run preserved the suspended checkpoint byte-for-byte. Exact policy exited 1 and
left every checkpoint/bundle file hash unchanged; status and full scratch verification also left
it unchanged. Compatible resume exited 0, recorded `accepted_policy=compatible`, migration count 1,
and removal of `json-logic-qubit`. It retained `output_equivalence=not-guaranteed` for runtime drift.
All 24 evidence/ground-truth/observation files matched both controls. Resolved scenario and generation
manifest differences are validation snapshots, derived fingerprints, generation/resume timestamps,
and migration lineage. Byte equality is evidence for this run, not a compatibility guarantee.

The first scratch verifier attempt hit macOS's `/var` symlink ancestry guard. The harness now uses
its resolved private temporary directory for scratch storage; the safety guard was not bypassed.
An existing classifier initializes any nonempty behavior history as `localized`, including a history
containing only `impact: none` entries. That conservative diagnostic remains unchanged; it does not
prevent compatible hydration or strengthen the output-equivalence guarantee.

### CLI/configuration comparison

Scratch harness `/private/tmp/eforge-gap-compat.py` runs baseline and candidate in isolated processes,
with multiple project scopes sequentially inside each process. Both have 55 result entries and no
nonzero command exits. Coverage includes input/resolved validation, resolve JSON, configuration JSON,
CWD/explicit/no-ancestor resolution, two DNS overlays, Scenario 1.0/2.0, organization/industry closure,
pack validation/build/inspect/import/hydration, exact locks, and legacy text/JSON eval. A repeated
project-A check after project B matches A's initial configuration.

Compiled-document differences are limited to the already enumerated 20 format documents, packaged
co-occurrence/threshold documents, and effective/compiled digests. Scenario, supported overlays,
field provenance and locks do not differ. Resolve JSON differs only in `compiled_sha256`.
Validation text additionally reports changing available memory/disk. Eval retains existing keys;
expected differences are exact thresholds, structured findings, current validation counts/details,
execution timing and evaluated timestamp. Pack JSON and immutable release locks match exactly.
Full outputs: `/private/tmp/eforge-gap-compat-{baseline,candidate}/results.json`; comparison:
`/private/tmp/eforge-gap-compat-comparison.json`.

### Newly exposed target boundaries

Both targets contain 123,105 records from 22 sources; baseline/candidate bytes match in all 141
non-metadata files per target. SOF-ELK serial and Splunk threaded captures are retained under
`/private/tmp/eforge-gap-{sof-elk,splunk}-{baseline,candidate}`. Hash comparison:
`/private/tmp/eforge-gap-target-comparisons.json`.

SOF-ELK evaluation completes but schema compliance is 75.4397%: all 18,718 Windows Security and
11,517 Sysmon records lack XML-only `Level`, `ExecutionProcessID`, and `ExecutionThreadID` metadata.
Security labels also map `SourceAddress`/`DestAddress` to `SourceIp`/`DestinationIp` and flatten
subject/target identities into repeated labels that the current parser cannot scope reliably.
This is a projection-contract and information-preservation issue, not a missing Jinja template.
The full inventory is retained in `/private/tmp/eforge-gap-snare-audit.log`. A compact Snare fixture
keeps the failure visible. Defining a native projection contract and repairing lost identity scope
requires separate work; silently making XML fields optional would conceal it.

Splunk initially rejected all 2,236 proxy and 822 web records. After its parser repair, schema and
correctness are 100%; overall score is 95.3330. Its indicator accuracy of 71.9215% is now exposed by
complete parsing (1,063/1,478 checks), including proxy and Windows username mismatches. It needs a
separate trace-matching/identity investigation; the evaluator must not invent missing identities or
weaken the gate. Temporal integrity remains 83.3333% versus 85, as before. These findings, and the
packet-filter/reporter/weird generation investigation, remain separate from validation-rule fixes.

### Final evidence and repository gates

- Fix commits: `9c89e83d` (returned execution errors and malformed evidence), `cd6463f7`
  (historical snapshot recovery), `68cd5dd8` (Splunk web/proxy parsing). Generator code and package
  version are unchanged. Behavior revision 92 declares validation snapshot decoding with no
  generation impact; behavior manifest checks pass.
- **Routine:** 11,439 passed, 68 skipped, 2,025 deselected, `--no-cov`, 368.81s.
  The additional deliberate native skip is the unrepresentable empty Bash filename-derived username.
- **Slow:** 5 passed, 7 deselected, `--no-cov`, 482.28s: complete iteration fresh-process pair,
  authoritative observation-overlay evaluation, public seed determinism, hash-seed storage identity,
  and historical baseline checkpoint upgrade. The final default capture matches all **141** baseline
  evidence files; both fresh candidate captures match all **142** manifest-owned files including
  resolved input. Manifest-owned hashes are independently verified.
- **Final focused:** 152 passed, 2,456 deselected, 8.11s: error routing, snapshot decoder, target JSON,
  behavior provenance, combined 25-format malformed-record evaluation, and oversized Bash epochs.
- Existing routine cutoff/partial-observation guards remain active, including
  `test_firewall_teardown_after_export_window_is_marked_unobserved` and
  `test_pre_window_or_observation_gap_is_not_scored`. The dedicated slow observation-profile test
  verifies authoritative bundle configuration and intentional missingness through causality scoring.
- **Performance:** five isolated full evaluations per revision, alternating interpreters, identical
  123,105-record heterogeneous baseline bundle, all four pillars complete, all exits 0. Median wall
  time baseline **12.3028s**, candidate **12.1033s** (1.62% faster). Median peak process RSS baseline
  **777,846,784 bytes**, candidate **774,471,680 bytes** (0.43% lower). Includes imports, parsing and
  all pillars. No >20% regression to investigate; these measurements are not CI timing assertions.
- **Ruff:** check and format check pass (892 Python files). `git diff --check` is clean. Canonical
  references were regenerated through `install-skills`; installer/reference contracts pass.
- Immutable baseline checkout remains clean. No push, PR, version bump, generator modification,
  `attempt` policy, or relaxed threshold was used. Linux/Windows CI and independent review remain
  pending; **merge readiness is not established**, including the target-specific findings above.

Machine-readable results and comparison hashes are committed in
[validation-gap evidence](2026-09-15-validation-gap-evidence.json). Full logs are retained at
`/private/tmp/eforge-gap-routine-final.log`, `/private/tmp/eforge-gap-slow.log`,
`/private/tmp/eforge-gap-final-focused.log`, and `/private/tmp/eforge-gap-performance-final/`.
Historical preserved checkpoint and controls are in
`/private/tmp/eforge-gap-slow-final/test_baseline_checkpoint_upgra0/`.

Reproducible verification tools (run from the repository, with new output directories):

```bash
# Repeat for the candidate interpreter into a separate directory.
/private/tmp/eforge-rv-baseline-env/bin/python scripts/capture_validation_compatibility.py \
  --output /private/tmp/validation-compat-baseline-new

/private/tmp/eforge-rv-candidate-env/bin/python scripts/benchmark_validation.py \
  --baseline-python /private/tmp/eforge-rv-baseline-env/bin/python \
  --candidate-python /private/tmp/eforge-rv-candidate-env/bin/python \
  --bundle /private/tmp/eforge-rv-iteration-baseline \
  --output /private/tmp/validation-performance-new

EFORGE_VALIDATION_BASELINE_PYTHON=/private/tmp/eforge-rv-baseline-env/bin/python \
  uv run --no-sync pytest tests/integration/test_validation_checkpoint_upgrade.py -m slow --no-cov
```

The committed CLI capture tool was exercised against both isolated environments after its extraction
from the scratch harness: 55 results per revision, all exits 0, equal supported configuration and
pack operations. CWD/explicit effective configuration matches; no-ancestor mode excludes the parent
overlay; project A retains its values after project B. The `.efpack` archives are byte-identical:
`43433bfe3c0769748320318ab41261fd626e1471fa464c5420b0dfe3acf0757d`.

Baseline target evaluations independently confirm these parser/projection gaps predate this branch:
SOF-ELK baseline schema/correctness are both 75.4389%; Splunk baseline schema is 97.5151%.
Both baseline runs complete with failed acceptance. Candidate native Splunk parsing repairs its
3,058 rejected HTTP records; the small remaining baseline/candidate schema difference is the
previously documented eCAR rename validation defect. Original baseline target reports are retained
as `/private/tmp/eforge-gap-{sof-elk,splunk}-baseline-report.json` and included in the evidence summary.

## SOF-ELK parser investigation and Splunk anonymous-user repair

This section supersedes the earlier Splunk indicator investigation and narrows the SOF-ELK
assessment: missing XML system metadata does **not** establish incorrect Snare rendering.

### Upstream SOF-ELK findings

Inspected the actual preprocessing and extraction configuration at our harness pin
`517af9445574cc084cd5f4b80539fc244dab82b0` and current upstream main
`a85fe99b9dd296faeb39edb7b9eff0bbb87fdd4b`:

- [1010 preprocessing](https://github.com/philhagen/sof-elk/blob/517af9445574cc084cd5f4b80539fc244dab82b0/configfiles/1010-preprocess-snare.conf)
  removes MSWinEventLog and converts tabs into CSV separators. Our envelope uses this contract.
- [6010 extraction at the pin](https://github.com/philhagen/sof-elk/blob/517af9445574cc084cd5f4b80539fc244dab82b0/configfiles/6010-snare.conf)
  reads Snare criticality, counter, channel, provider, computer, log type and expanded message.
  It does not require XML Level/ExecutionProcessID/ExecutionThreadID. Criticality and Snare counter
  are their own fields, not interchangeable XML metadata. Our XML-schema requirement is wrong for
  this representation; adding invented XML values would also be wrong.
- SourceIp/DestinationIp map to ECS source.ip/destination.ip. These labels are intentional.
  SourcePort/DestinationPort have explicit patterns, but the retained 5156 fixture's DestPort does
  not match DestinationPort. Successful ingestion is therefore weaker than complete extraction.
- Repeated Security ID, Account Name, Account Domain and Logon ID labels feed generic fields.
  There is no event-specific subject/target reconstruction in these patterns. Our parser additionally
  overwrites repeated labels. Preserve the raw ordered occurrences; do not assign scope by guessing.
- Sysmon UtcTime overrides the syslog timestamp; the local-system timestamp is retained separately.
  Hex process/logon IDs are converted, hashes are split, and backslashes are normalized to slashes.
  These are explicit projection semantics to account for in comparison tests.
- [Current main](https://github.com/philhagen/sof-elk/blob/a85fe99b9dd296faeb39edb7b9eff0bbb87fdd4b/configfiles/6010-snare.conf)
  now distinguishes New Process ID/Creator Process ID and New Process Name/Creator Process Name.
  Our renderer's generic Process ID/Process Name matches the older pin, so parser-version coverage
  matters. Both inspected versions retain notes about unhandled Security messages.
- Our external Snare harness currently checks event ID/provider/channel/computer and ingestion tags;
  it does not assert full account/process/network extraction. This explains why that gate could pass
  while internal XML-based evaluation fails. This investigation was source inspection, not a fresh
  Logstash execution; the sandbox could not access the Docker socket.

Recommended implementation: explicit Snare representation metadata and a typed native-envelope
contract, event-specific unambiguous alias normalization, ordered repeated-label retention, and
field-level external-parser assertions against a declared upstream revision. Apply shared rules to
facts the representation actually carries; report unavailable scope explicitly. Retain full XML
requirements for XML. Separately demonstrate any rendering incompatibility before authorizing a
renderer change. No Snare parser/schema/renderer changes were made in this follow-up.

### Splunk fix and evidence

Apache JSON `user: "-"` now means absent authenticated identity, matching the text parsers.
Normalization happens after alias conflict detection, preserving errors for contradictory
`user`/`username` values in either order. Real usernames, domain-qualified users, and machine accounts
are retained; actual wrong usernames still fail indicator checks. Regression coverage includes
parsing, schema scoring, indicator checks, and CLI accounting/acceptance for conflicting aliases.

Full retained Splunk iteration evaluation completed with exit 0 and one JSON report:
`/private/tmp/eforge-gap-splunk-normalized-report.json` (stderr in the adjacent `.err` file).
All 123,105 records remain counted. Schema/correctness remain 100%; indicator accuracy improves
from 1,063/1,478 (71.9215%) to 1,063/1,080 (98.4259%), matching the default target. The 398 removed
checks were comparisons against the no-user sentinel. The sole failing acceptance gate is unchanged
83.3333% temporal integrity versus 85%. No evidence regeneration or generator modification occurred.

### Deferred temporal work

At the user's direction, TODO now tracks temporal integrity as a separate **P1, deferred** item.
The eight findings are event indices 0 (-152s), 11 (-172s), 24 (-188s), 28 (+198s), 29 (+313s default,
+314s Splunk), 33 (ordering), 42 and 44 (missing traces). Timing tolerance is 120s. These require
separating matcher expectations from canonical/source-observation timing before prescribing fixes.
Thresholds and generated evidence remain unchanged. The obsolete Splunk investigation was removed;
the diagnostic Zeek generation-coverage follow-up remains separately tracked.

Verification for this follow-up: **89 passed** (Apache JSON and native evaluator parsers), 4.46s,
`--no-cov`; Ruff check/format (892 files), behavior-manifest check, and diff whitespace check pass.
The earlier full routine/slow results above precede this narrow normalization fix; those suites were
not rerun. No branch publication or PR was performed.

## Snare data preservation and representation-aware validation

This implementation supersedes the Snare investigation and pending recommendation above. Work
continues locally on `codex/record-validation`; the pre-Snare comparison commit is `2c899b06`.
Original baseline `787fd733` and its isolated environment remain untouched. Package version remains
2.1.0. No branch publication or PR is authorized or performed.

### Contracts and field dispositions

The companion `2026-09-15-snare-field-inventory.json` inventories all **43 variants / 826 declared
field slots**, including optional fields. Each slot names its canonical field, previous disposition,
current labels, upstream extraction destinations and committed fixture witness. Optional fixture
values are synthetic contract witnesses, not facts added to generated events. The 43 minimal native
fixtures remain covered alongside the expanded optional-field fixtures.

- Typed, exhaustive, package-owned YAML projections replace the global Security label mapping.
  Generic account labels consistently select one event-appropriate identity; scoped subject and
  target values remain independently available. New/creator process aliases use their actual owners.
- `DestPort` now supplies the supported `DestinationPort` alias. Hex ProcessId values retain their
  canonical spelling and provide a decimal view where required by upstream patterns.
- Level, execution IDs, precise TimeCreated, Windows EventRecordID, zero and empty string values are
  retained when supplied. Private bookkeeping and absent values are not emitted. Envelope position,
  timestamp convention, and existing whitespace/tab/newline/double-pipe sanitization remain stable.
- Subject/target/linked logon IDs use protected `Canonical[...]` labels: the upstream `LogonId:`
  pattern is unanchored and otherwise captures scoped names. The selected `Logon ID` display alias
  remains available for generic Security extraction. These are distinct downstream field names.
- Current upstream requires an execution-PID fallback for events without an actor/new-process PID.
  It comes only from supplied ExecutionProcessID, and internal normalization preserves that owner.
  A trailing projection marker prevents whitespace trimming from hiding the final real field from
  upstream patterns requiring two spaces after a value.
- Supplied Sysmon UtcTime is no longer overwritten with TimeCreated. XML truth comparison exposed
  **9,011 affected Sysmon rows** in the iteration scenario. Missing UtcTime retains the existing
  fallback; no canonical event time is generated or moved by this renderer repair.

The parser distinguishes XML and Snare explicitly. Snare validates its own typed envelope and
projection; criticality/counter do not masquerade as Windows Level/EventRecordID. Ordered repeated
labels survive parsing. Historical unscoped identities are not guessed; missing unavailable facts
produce structured not-applicable findings with counts and bounded examples. Current projections
must supply their required facts. Conflicting aliases, malformed numeric fields, invalid timestamps,
and missing required fields remain counted failures through CLI acceptance. Engine-error versus
ordinary FAIL exit semantics are unchanged.

### External compatibility

Actual Docker/Filebeat/Logstash pipelines are exercised at both frozen revisions:

- `517af9445574cc084cd5f4b80539fc244dab82b0` (existing harness pin).
- `a85fe99b9dd296faeb39edb7b9eff0bbb87fdd4b` (frozen current upstream).

The harness's existing small-file path-identity adapter removes upstream compression auto-detection
for uncompressed staged fixtures; Filebeat otherwise refuses that combination. Upstream Logstash
filters are unmodified. The existing optional-enrichment `_grokparsefail_6010-01` policy remains;
no new tag exemption was added. Current upstream `_grokparsefail_6010-02` was repaired by the truthful
execution-PID fallback, not waived.

Fixtures include distinct subject/target users, child/creator processes, hexadecimal IDs, all optional
fields, IPv6, zero ports, Unicode paths, and command-line punctuation. Assertions cover record counts,
existing tag policy, values and types, identity/process/network ownership, Sysmon event time and
optional metadata. Raw preservation does not imply indexed fields: both revisions omit zero ports
under POSINT patterns and do not extract many canonical system/scoped fields. Those values remain
in the raw record. Native whitespace sanitization is not byte-for-byte preservation of pre-render
strings. No upstream parser modification is required for these dispositions.

### Verification and reproducibility

Final execution results and generation evidence are recorded below for the frozen-source runs.
The external suite is opt-in; a skipped run is not a passing external gate:

```sh
uv run --no-sync pytest tests/external_parser/test_snare_projection_matrix.py \
  -m external_parser --include-external-parsers --no-cov
uv run --no-sync pytest tests/unit/test_snare_projection.py --no-cov
uv run --no-sync pytest tests/integration/test_iteration_validation.py -m slow -k sof-elk --no-cov
uv run --no-sync pytest tests/integration/test_checkpoint_smoke.py --no-cov
uv run --no-sync pytest --no-cov
uv run --no-sync python scripts/check_generation_behavior.py --base-ref 2c899b06
uv run --no-sync ruff check .
uv run --no-sync ruff format --check .
```

The Snare projection loader is registered with the existing trusted derived-cache contract; otherwise
checkpoint generation correctly rejected the unknown cached loader. The macOS mixed-format
checkpoint test also exposed a tool-owned `/var` versus `/private/var` temporary-path alias: checkpoint
verification now resolves that scratch root before Snort hydration, preserving ancestry enforcement.
Generation behavior revision **93** declares localized Windows source-native projection changes.

Canonical evaluation references and documentation describe historical ambiguity, unavailable checks,
raw versus indexed fields, and source-specific metadata. Installed Codex skills are regenerated only
through `eforge install-skills --agent codex`. Temporal-integrity repair remains separately deferred
P1; diagnostic Zeek generation coverage remains a separate P2 investigation. Linux/Windows CI and
independent review remain publication-dependent merge gates.

### Final local evidence

- **Routine:** 11,608 passed, 70 skipped, 2,026 deselected, 437.95s, `--no-cov`.
  Log: `/private/tmp/eforge-snare-routine-delivery.log`. The later fixture-only refinements are also
  covered by 226 focused native/installer/behavior checks (4.40s).
- **Iteration slow:** 1 passed (SOF-ELK target), 386.44s; generates twice in fresh processes, verifies
  every manifest hash, compares all covered bytes, and completes all four evaluation pillars.
  Log: `/private/tmp/eforge-snare-complete.log`; outputs are under
  `/private/tmp/eforge-snare-complete/test_iteration_fresh_process_b0/{first,second}`.
- **Checkpoint:** default and mixed Windows/Linux SOF-ELK suspend/verify/resume match uninterrupted
  controls; 25 checkpoint/behavior tests passed in 60.18s. The original-baseline compatibility slow
  test also passed (1 test, 51.37s). Snare's localized behavior change is declared, not misrepresented
  as guaranteed equivalence with old rendering.
- **Candidate evaluation:** `/private/tmp/eforge-snare-delivery-report.json` is one complete JSON
  object, exit 0; stderr is separate. All 123,105 records are counted. Spec Conformance and Format
  Constraints are 100%. Temporal integrity remains 83.3333% versus 85%, the sole failed gate.
- **Byte comparison:** `2026-09-15-snare-generation-evidence.json` records hashes and per-variant label
  differences. Both runs contain 142 covered files. Twenty Snare files and RESOLVED_SCENARIO.yaml
  differ from the retained pre-change target bundle; the other 121 are byte-identical. Resolved
  differences are the added packaged projection YAML and associated configuration digests.
- **XML truth comparison:** `2026-09-15-snare-xml-truth-evidence.json` matches all 18,718 Security and
  11,517 Sysmon records by host/EventID/EventRecordID. UtcTime now agrees for every Sysmon row.
  Remaining differences are timestamp spelling, XML template defaults absent from canonical event
  input, preserved native whitespace sanitation, and RestrictedSidCount string-to-integer typing.
  No generated facts were invented to imitate XML template placeholders.
- **External optional-field results:** both frozen revisions pass 45-record pipelines, including all
  optional field witnesses (97.23s). The stronger assertions exposed upstream RuleName array typing,
  qualified-name requirements, and raw-only ParentImage/CurrentDirectory. Both revisions replace
  backslashes before the latter fields' backslash-dependent patterns; actual rows confirm absent
  destinations with intact raw fields and unchanged unrelated extraction. These are documented
  unsupported extraction paths, not claimed successful indexing. No unsafe alternative labels or
  upstream filter edits are introduced.
- Ruff check, Ruff format (895 files), behavior revision/digest against `2c899b06`, and diff whitespace
  checks pass. Canonical references were regenerated with the installer; the reference/link tests
  pass. External skipped runs are excluded from pass evidence.

| Requirement | Status | Evidence |
|---|---|---|
| Every variant/field disposition | Passed | 43 variants, 826 slots, full/minimal committed fixtures and inventory |
| Typed projections and native/legacy normalization | Passed | Native tests, CLI corruption accounting, unavailable findings |
| Both actual external parsers | Passed | Opt-in 45-record pipelines at both frozen revisions |
| Optional-field interference / extraction | Passed with explicit raw-only limitations | Assertions and upstream pattern dispositions above |
| Full iteration byte equality and hashes | Passed | Generation evidence JSON; 121 unaffected files identical |
| Fresh-process and checkpoint determinism | Passed | Slow iteration and mixed-target checkpoint controls |
| Full evaluation | Completed FAIL | Schema/correctness 100%; unchanged temporal P1 failure |
| Routine / Ruff / behavior / skills | Passed | Logs and commands above |
| Linux/Windows CI and independent review | Externally pending | No publication authorized |
| Temporal repair and diagnostic Zeek generation coverage | Deferred | Existing separate P1/P2 roadmap items |

The final external gate adds actual tab/newline/double-pipe command-line input to the Unicode
witness: **2 passed, 96.64s**, 45 records per frozen revision. Log:
`/private/tmp/eforge-snare-external-accepted.log`; extracted JSON and staged inputs are retained under
`/private/tmp/eforge-snare-external-accepted/test_all_snare_variants_extrac{0,1}/runtime/`.
This supersedes the earlier external runs. The only remaining upstream extraction limitations are
explicit raw-only dispositions, not missing event facts or waived ingestion failures. TODO records
the upstream pattern follow-up separately; the Snare preservation/evaluation task is locally complete.
Rendering/projection and evaluator integration share one implementation commit because the shared
contract is required by both; expanded external verification and documentation are committed separately.

Local implementation commits: `1e91cf1b` (projection/validation), `2526cda3` (checkpoint scratch path),
`7b2ea369` (external and generation gates). Final native/installer/documentation checks: **205 passed,
3.97s**. Installed skills were regenerated after the final canonical-reference update.
