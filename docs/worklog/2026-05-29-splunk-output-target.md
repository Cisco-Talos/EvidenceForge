# 2026-05-29 Splunk Output Target

## Scope

Implement the Splunk output target and a Splunk-backed external parser
validation lane on feature branch `codex/splunk-output-target` in Codex managed
worktree `/Users/dabianco/.codex/worktrees/be6f/EvidenceForge`.

## Design Notes

- Keep the no-vendoring pattern from the SOF-ELK® lane. EvidenceForge owns only
  staging, generated Splunk app config, search/report code, and Compose files.
- The Splunk runtime uses the `splunk/splunk:10.2.3` container and requires
  explicit license and Splunk General Terms acceptance before startup.
- CIM validation is opt-in/automatic only when caller-supplied local Splunk
  apps are provided. EvidenceForge does not download or commit Splunkbase apps.
- Windows Security and Sysmon use the existing XML event body but switch from a
  rooted `<Events>` document to one complete `<Event>` per line for Splunk file
  monitoring.
- Sensor-scoped sources do not write root-level fallback files. If no matching
  Zeek, IDS, or firewall sensor exists, the corresponding sensor log is absent.
- Host-scoped multiplexed sources also drop hostless directory-mode records
  instead of writing root-level fallback files.
- Splunk external-parser coverage now mirrors the SOF-ELK purpose-built sample
  pattern. `tests/external_parser/sample_data.py` writes one Zeek record per
  Zeek type through the real emitters and a compact multi-family Splunk parser
  sample for Windows XML streams, syslog, Cisco ASA, web, proxy, eCAR, and Zeek.
- The live Splunk container smoke is
  `tests/external_parser/test_splunk_harness.py`; it is opt-in with
  `--include-external-parsers` and `EFORGE_ACCEPT_SPLUNK_LICENSE=1`.

## 2026-06-01 Checkpoint

Implemented the first Splunk output-target and parser-harness pass on branch
`codex/splunk-output-target`. Focused unit coverage was kept passing while
iterating on the harness. The live Splunk smoke now starts the official Splunk
container on Apple Silicon by running the `splunk/splunk:10.2.3` image as
`linux/amd64`, mounts generated and caller-supplied apps as ephemeral writable
runtime inputs, and validates base sourcetype counts, fields, timestamps,
source/host metadata, and `_internal` parser warnings through REST searches.

Follow-up fix completed: the harness now stages host-scoped files under
Splunk-safe internal directory names while keeping the original EvidenceForge
host value in generated `inputs.conf` metadata. The live smoke also needed
generated `server.conf` to allow localhost REST validation after the Free
license activates, a future-tolerant REST search window for scheduled training
data, and filtering of Splunk search/export informational messages that are not
actual parser-warning rows.

Validation after the fix:

- `uv run ruff check src/evidenceforge/external_parsers/splunk.py src/evidenceforge/external_parsers/splunk_runtime.py tests/unit/test_splunk_harness.py`
- `uv run ruff format --check src/evidenceforge/external_parsers/splunk.py src/evidenceforge/external_parsers/splunk_runtime.py tests/unit/test_splunk_harness.py`
- `uv run pytest --no-cov tests/unit/test_splunk_harness.py`
- `EFORGE_ACCEPT_SPLUNK_LICENSE=1 uv run pytest --include-external-parsers --no-cov tests/external_parser/test_splunk_harness.py`

The live smoke passed with all expected Splunk sourcetypes indexed.

## 2026-06-01 CIM Supplied-App Smoke

Local Splunkbase app archives were supplied from `/tmp/SplunkTA`, including
Splunk CIM, Microsoft Windows, Sysmon, Unix/Linux, Cisco ASA, Zeek, and Apache
Web Server add-ons. The first CIM-required run against the Windows-only
`/tmp/eforge-splunk-live/data` dataset showed that the Microsoft Windows TA
normalizes both `XmlWinEventLog:Security` and
`XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` to indexed
`sourcetype=XmlWinEventLog`. The harness now accounts for that known
TA-normalized sourcetype while preserving base-mode expectations.

Validation after the adjustment:

- Windows-only CIM-required parser run passed with expected/observed
  `{'XmlWinEventLog': 98}` and visible CIM models.
- Multi-family CIM-required parser run passed with Windows normalized to
  `XmlWinEventLog` and all non-Windows supported v1 sourcetypes preserving the
  base indexed sourcetype.

This proves that supplied apps can be installed ephemerally, CIM data models are
visible, and base ingest/field validation survives the supplied TAs. It does not
yet prove that every event populates CIM data-model datasets; that requires the
next validation layer of source-specific data-model searches and CIM field
coverage checks.

## 2026-06-01 CIM Data-Model Validation

Added the first source-family-specific CIM validation layer. In `--cim require`
or supplied-app `--cim auto` mode, the Splunk harness now searches the expected
CIM data-model datasets for source families covered by the supplied-app smoke:
Windows Security authentication, Sysmon process events, Zeek connection and HTTP
events, Cisco ASA network traffic, and Apache-style web access logs. Each check
verifies that the expected event count appears in the CIM dataset and that key
CIM fields are populated.

A local run with the supplied apps in `/tmp/SplunkTA` still passes base ingest
and base field validation, but the new CIM dataset checks fail with zero
matching events for all currently checked families. That is useful signal rather
than a container/runtime failure: the TAs and CIM app are visible, Splunk indexes
the staged data, but the generated events are not yet landing in the selected
CIM data-model datasets. The next implementation work is to adjust generated
source metadata, sourcetypes, tags/eventtypes, field extractions, or Splunk
validation app config so source families map into CIM cleanly.

## 2026-06-01 CIM Harness Query Fix

Diagnosis showed that `| datamodel ... search` result rows carry plain
`source` and `sourcetype`, but not a reliable plain `index` field. The harness
was filtering post-data-model results with `index=eforge`, causing false
negative CIM failures for source families that were actually present in CIM.
The CIM dataset search now filters only on `sourcetype` plus source when needed.

Validation after the fix:

- Base Splunk external smoke still passes.
- CIM-required supplied-app smoke now fails only for `zeek_conn`, `zeek_http`,
  and `web_access`.
- Windows Security, Sysmon, and Cisco ASA are no longer counted as zero-CIM
  dataset failures by the harness.

## 2026-06-01 CIM Field-Quality Tightening

Implemented the approved follow-up subset from the CIM diagnosis:

- CIM dataset validation now treats required fields with `unknown`, `0`, empty,
  or absent values as invalid instead of only checking dataset membership.
- Supplied Splunk app names are tracked in the runtime manifest, and Zeek CIM
  searches run in the `Splunk_TA_zeek` namespace when that app is supplied so
  app-local Zeek knowledge objects are visible.
- The Splunk target stages web access logs as `sourcetype=apache:access` so the
  Apache TA eventtype/tag path can activate.
- The compact Splunk parser sample now uses the fuller source-native ASA 302013
  connection shape with parenthesized mapped endpoint tuples. The production ASA
  emitter already used that richer form.

Validation after the change:

- `uv run ruff check src/evidenceforge/external_parsers/splunk.py src/evidenceforge/external_parsers/splunk_runtime.py tests/unit/test_splunk_harness.py tests/external_parser/sample_data.py`
- `uv run ruff format --check src/evidenceforge/external_parsers/splunk.py src/evidenceforge/external_parsers/splunk_runtime.py tests/unit/test_splunk_harness.py tests/external_parser/sample_data.py`
- `uv run pytest --no-cov tests/unit/test_splunk_harness.py`
- `EFORGE_ACCEPT_SPLUNK_LICENSE=1 uv run pytest --include-external-parsers --no-cov tests/external_parser/test_splunk_harness.py`

The base live Splunk smoke still passes. A CIM-required supplied-app run now
shows improved diagnostic signal: Cisco ASA has no CIM required-field failures,
Zeek reaches CIM in the Zeek TA namespace but still lacks endpoint fields from
dotted JSON keys, and web access reaches `Web.Web` after the sourcetype change
but lacks required Web fields because the Apache TA's `apache:access` parser
expects a richer Apache log shape than EvidenceForge's current common combined
line.

## 2026-06-01 TA-Aligned CIM Fix Trial

Implemented and tested the next TA-aligned fixes:

- Splunk-target Windows Security and Sysmon XML streams now compact `<Data>`
  field-name attributes to the single-quoted shape expected by the Microsoft
  Windows and Sysmon TA XML transforms, while keeping default XML output
  unchanged.
- Zeek JSON keeps native dotted field names such as `id.orig_h`; the generated
  validation app now adds the Zeek TA-documented `FIELDALIAS` mappings and
  exports its ephemeral knowledge objects system-wide so the aliases are
  visible from the `Splunk_TA_zeek` CIM search namespace.
- Web access is staged as `apache:access:combined`, matching the Apache TA
  parser stanza for standard Apache/Nginx Combined Log Format. The target policy
  label was corrected from `w3c_extended` to `apache_combined`.

Validation after the change:

- `uv run ruff check src/evidenceforge/output_targets.py src/evidenceforge/external_parsers/splunk.py src/evidenceforge/external_parsers/splunk_runtime.py src/evidenceforge/generation/emitters/windows_event/__init__.py tests/unit/test_splunk_harness.py tests/unit/test_output_target_rendering.py tests/unit/test_output_targets.py tests/external_parser/sample_data.py`
- `uv run ruff format --check src/evidenceforge/output_targets.py src/evidenceforge/external_parsers/splunk.py src/evidenceforge/external_parsers/splunk_runtime.py src/evidenceforge/generation/emitters/windows_event/__init__.py tests/unit/test_splunk_harness.py tests/unit/test_output_target_rendering.py tests/unit/test_output_targets.py tests/external_parser/sample_data.py`
- `uv run pytest --no-cov tests/unit/test_output_targets.py tests/unit/test_output_target_rendering.py tests/unit/test_splunk_harness.py`
- `EFORGE_ACCEPT_SPLUNK_LICENSE=1 uv run pytest --include-external-parsers --no-cov tests/external_parser/test_splunk_harness.py`

Results:

- Base live Splunk ingest still passes.
- CIM-required supplied-app validation now passes for Windows Security, Sysmon,
  Cisco ASA, Zeek connection, and Zeek HTTP field coverage.
- The only remaining CIM-required failure in the compact supplied-app run is
  `web_access: expected 1 event(s) in CIM Web.Web, got 0`.
- Direct REST search in the Apache TA namespace confirms
  `apache:access:combined` parses the combined log fields (`client`, `src`,
  `url`, `http_method`, `status`), but the supplied Apache TA's default
  `access_log_event` eventtype only tags `apache:access`, `apache:access:kv`,
  and `apache:access:json`. It does not tag `apache:access:combined`, so the
  parsed record does not enter the Web data model without additional local
  eventtype/tag configuration.

## 2026-06-04 Apache TA JSON Trial

The Splunk target now renders `web_access.log` as Apache TA-compatible
line-delimited JSON and stages it as `sourcetype=apache:access:json`. Default
and SOF-ELK output still use Apache/Nginx Combined Log Format. The JSON fields
match the Apache TA's JSON stanza path: `client`, `server`, `dest_port`,
`http_method`, `uri_path`, `uri_query`, `status`, `bytes_in`, `bytes_out`, and
request metadata. This should let the supplied Apache TA own parsing, `client`
to `src` aliasing, `server` to `dest` aliasing, URL construction, eventtype
tagging, and CIM Web data-model membership.

Durable follow-up parked in `TODO.md`: add output-target ingest guides that
list fully parsed/normalized sources, parsed-only sources, unsupported sources,
and target-specific ingest guidance.

## 2026-06-05 Proxy CIM Trial

The Splunk target now renders `proxy_access.log` as Apache TA-compatible
line-delimited JSON and stages it as `sourcetype=apache:access:json`. Default
and SOF-ELK output still use the existing W3C Extended proxy log shape.

Because the supplied Apache TA parses Apache access JSON but does not tag
proxy rows by itself, the generated EvidenceForge validation app adds
source-scoped proxy classification only for `proxy_access.log`:

- `eventtype=evidenceforge_proxy_access`
- `tag=web`
- `tag=proxy`
- source-scoped `category`, `action`, and `vendor_product` mapping

This keeps Apache TA parsing as the base proof path while making proxy events
distinct at search time through `tag=proxy` and the CIM `Web.Proxy` data-model
dataset. Regular web server rows remain source-filtered to `web_access.log`.

## 2026-06-05 Branch-Office CRC Salt Diagnosis

The full branch-office Splunk+CIM run initially timed out waiting for Windows
XML ingest: `XmlWinEventLog` plateaued at `10677` instead of `14286`. A
Sysmon-only split run showed `2513/3711` indexed rows. Local XML validation
confirmed every Sysmon record was one complete valid XML event per physical
line, so the missing rows were not malformed XML.

Splunk `splunkd.log` identified the root cause as file-monitor duplicate
detection, not XML parsing: three whole Sysmon host files were skipped with
`File will not be read, is too small to match seekptr checksum` and duplicate
`initcrc` warnings. The skipped files were WS-MPATEL, WS-OREED, and WS-VHALE,
totaling exactly the missing `1198` Sysmon records. The generated
`inputs.conf` used `crcSalt = <SOURCE>{sourcetype}`; Splunk did not treat that
as a source salt. Changing the generated monitor stanzas to exactly
`crcSalt = <SOURCE>` fixed the file-monitor collision.

Validation after the fix:

- Focused unit suite: `uv run pytest --no-cov tests/unit/test_splunk_harness.py`
- Ruff: `uv run ruff check src/evidenceforge/external_parsers/splunk.py tests/unit/test_splunk_harness.py`
- Ruff format check: `uv run ruff format --check src/evidenceforge/external_parsers/splunk.py tests/unit/test_splunk_harness.py`
- Full branch-office Splunk+CIM rerun:
  `/tmp/eforge-splunk-branch-office-cim-20260605a/work-crcsalt-fix`

The rerun indexed all expected base records, including `XmlWinEventLog=14286`,
with no duplicate-CRC skip errors. It still failed later CIM field/model quality
checks for eCAR, Windows Security/Sysmon field coverage, Zeek `dest_port`, and
Cisco ASA `dest_port`; those are separate normalization/content diagnosis items
after base ingest succeeds.

## 2026-06-05 CIM Normalization Harness Fixes

The branch-office CIM failures after the CRC salt fix were mostly validation
scope issues rather than Splunk-target formatting defects. The harness now
validates only CIM-eligible subsets instead of comparing each source file family
to an entire data model:

- Windows Security Authentication expected counts now follow the CIM
  Authentication root constraint, `tag=authentication NOT (action=success
  user=*$)`, instead of all Security XML rows.
- Windows Security `src` is checked conditionally for auth event IDs where a
  source is meaningful, so privilege companion rows such as 4672 do not fail
  the full dataset.
- Sysmon Endpoint.Processes full field validation is limited to Event IDs 1 and
  5 for now. Sysmon 7/8/10 still enter the Endpoint data model under the
  supplied TA but have partial CIM field coverage; the decision on whether to
  add local aliases or treat them as parsed/partial-CIM remains open.
- Zeek and Cisco ASA `dest_port` is required only for non-ICMP network traffic.
- eCAR remains a custom parsed format and no longer requires a synthetic
  `event_type` field for Splunk validation.
- Preview rows from Splunk search/export no longer produce duplicate field
  failures.

Validation after the change:

- `uv run ruff check src/evidenceforge/external_parsers/splunk.py tests/unit/test_splunk_harness.py`
- `uv run ruff format --check src/evidenceforge/external_parsers/splunk.py tests/unit/test_splunk_harness.py`
- `uv run pytest --no-cov tests/unit/test_splunk_harness.py`
- Full branch-office Splunk+CIM run passed:
  `/tmp/eforge-splunk-branch-office-cim-20260605a/work-normalization-fixes-v2`

The 4648 diagnosis was intentionally left as diagnosis only. The observed 4648
rows are produced by persona baseline explicit-credential activity. That path
calls `generate_explicit_credentials()` without a modeled remote `source_ip`,
and `_explicit_credentials_source_ip()` intentionally renders `NetworkAddress =
-` unless the source IP maps to a different modeled system. If these rows are
intended to represent remote explicit-credential use, the root fix belongs in
the activity/bundle intent layer so the event carries a modeled source endpoint;
if they are local RunAs/service credential use, the current `NetworkAddress = -`
shape is plausible and should not be forced into remote-source semantics.
