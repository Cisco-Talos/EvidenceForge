# Output Target Ingest Guides

EvidenceForge output targets choose how generated evidence is rendered on disk.
The canonical event model is the same, but the target may change file layout,
line breaking, envelopes, or record shape so a parser can ingest the data.

Use these guides when deciding which target to generate and what the downstream
tooling proves.

| Target | Best use | Guide |
| --- | --- | --- |
| `default` | Source-readable generated data, internal evaluation, manual review, and custom ingestion experiments. | [default.md](default.md) |
| `sof-elk` | Developer-facing parser validation through SOF-ELK® Filebeat and Logstash. | [sof-elk.md](sof-elk.md) |
| `splunk` | Developer-facing Splunk ingest validation and optional CIM/data-model validation. | [splunk.md](splunk.md) |

## Choose A Target

| Goal | Recommended target | Why |
| --- | --- | --- |
| Run `eforge eval` or inspect generated source-native logs by hand. | `default` | Keeps neutral, readable output and avoids parser-specific envelopes. |
| Prove SOF-ELK can parse supported generated families. | `sof-elk` | Emits SOF-ELK-compatible Snare/RFC3164 layouts for Windows and syslog-family logs. |
| Prove Splunk can ingest supported generated families. | `splunk` | Emits Splunk-friendly Windows XML event streams and target-specific web/proxy JSON records. |
| Prove Splunk CIM visibility for supported families. | `splunk` plus supplied Splunk CIM/TAs | The Splunk harness can install caller-supplied apps ephemerally and run data-model searches. |

Do not use a `default` dataset for the SOF-ELK or Splunk parser lanes. The
external parser script checks `OUTPUT_TARGET.txt` and exits before staging when
the target marker does not match the requested backend.

## Validation Tiers

The guides use these status terms.

| Tier | Meaning |
| --- | --- |
| Generated | EvidenceForge emits the file when the scenario config enables the source. No external parser claim is made. |
| Ingest validated | The external parser harness proved records were indexed or parsed at the expected count, with basic metadata and line breaking intact. |
| Field validated | The harness proved required parser-visible fields were present for that family. |
| CIM normalized | Splunk only. Events were found in the expected CIM data model or object with required CIM fields. |
| Parsed-only | Splunk only. Events are ingested and basic fields are available, but no CIM data-model claim is made. |
| Unsupported | The harness detects the file family but intentionally does not validate it for that target. |

Parser validation proves format and parser compatibility for the stated fields.
It does not prove that every generated record is realistic, complete for every
analytics use case, or normalized by every possible third-party app version.

## Source Presence

Generated files follow the scenario topology. EvidenceForge does not emit source
families when no corresponding source exists:

- No Zeek sensors means no Zeek logs.
- No IDS sensors means no Snort/Suricata alert logs.
- No firewall sensors means no Cisco ASA logs.
- No `web_server` hosts means no web access logs.
- No `forward_proxy` hosts means no proxy access logs.
- Host logs are scoped to concrete host directories.

This matters when building parser smoke scenarios: a minimal scenario may be
valid but still omit entire source families.

## Related Developer Docs

- [External parser validation](../external-parser-validation/README.md)
- [Parser coverage matrix](../external-parser-validation/coverage-matrix.md)
- [Evidence formats reference](../reference/EVIDENCE_FORMATS.md)
