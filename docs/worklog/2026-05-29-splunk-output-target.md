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
