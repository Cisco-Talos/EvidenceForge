# Unified record validation

## Contract and baseline

- Branch: `codex/record-validation`, based on freshly fetched `origin/dev` at `787fd733`.
- Immutable comparison checkout: `/tmp/eforge-record-validation-baseline` (detached).
- Preserve scenario/pack schemas, overlay precedence, project-root behavior and CLI exit codes.
- Correctness checks apply to every record and gate acceptance at 100%; realism remains diagnostic.
- Validation-only changes must preserve raw generated evidence; any generator correction requires
  separate evidence and a separate commit. Package version remains unchanged.

## Execution

Local implementation and validation are complete. External CI awaits explicit publication approval.
No generator correction was made; source-native contract defects were repaired in validation.

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
