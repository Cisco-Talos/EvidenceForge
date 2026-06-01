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

Known remaining issue: the latest live smoke still times out waiting for every
expected sourcetype. Splunk indexes the staged Zeek files and Cisco ASA file,
but does not pick up files staged under dotted host-directory names such as
`win01.example.test/windows_event_security.xml`. The next diagnostic/fix should
stage monitored files under Splunk-safe internal directory names while keeping
the original EvidenceForge host value in generated `inputs.conf` metadata.
That would change only the harness staging path, not the generated dataset path
or host identity seen by Splunk.
