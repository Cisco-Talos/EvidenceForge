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
