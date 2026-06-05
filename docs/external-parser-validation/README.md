# External Parser Validation

External Parser Validation checks generated EvidenceForge logs with third-party
parsers. The goal is format and parseability validation, not blind realism
review and not the deterministic `eforge eval` scoring model.

The current implementation supports two developer-facing parser backends:

- SOF-ELK® through Filebeat and Logstash, without Elasticsearch.
- Splunk Enterprise in Docker, using generated file-monitoring app config and
  REST search/export validation.

## Quickstart

Generate the dataset with the SOF-ELK output target, then run the full
developer-facing pipeline against the generated `data/` directory:

```bash
uv run eforge generate scenarios/apt-healthcare-breach/scenario.yaml --target sof-elk
uv run python scripts/external_parser.py scenarios/apt-healthcare-breach/data
```

For Splunk validation, generate with the Splunk output target and explicitly
accept Splunk's license and General Terms for the ephemeral container run:

```bash
uv run eforge generate scenarios/apt-healthcare-breach/scenario.yaml --target splunk
uv run python scripts/external_parser.py scenarios/apt-healthcare-breach/data \
  --backend splunk \
  --accept-splunk-license
```

The script requires `OUTPUT_TARGET.txt` to exist beside the scenario artifacts
or inside `data/`, and the marker must contain `sof-elk` or `splunk`. Missing,
invalid, or `default` markers exit gracefully before discovery/staging with a
message that explains how to regenerate the dataset. This keeps target-specific
parser lanes from quietly validating only the target-invariant subset of a
default-target dataset.

For a durable report location, pass a work directory:

```bash
uv run python scripts/external_parser.py \
  scenarios/apt-healthcare-breach/data \
  --work-dir /private/tmp/eforge-parser-validation \
  --timeout 180
```

Each SOF-ELK run clears parser-owned `sof-elk/*` runtime directories. Each
Splunk run clears parser-owned `splunk/stage`, `splunk/parsed`,
`splunk/search-results`, `splunk/pipeline-logs`, and
`splunk/runtime-config-src` directories. Use a unique work directory when you
need to keep artifacts from multiple runs side by side.

The runner auto-detects supported logs. Do not pass validator names for normal
use. Unsupported logs are reported as warnings so new formats are visible
without blocking supported parser checks.

Docker Compose v2 or Podman Compose is required for SOF-ELK. Splunk validation
currently requires Docker Compose because it uses the official `splunk/splunk`
container.

Splunk CIM validation is controlled with `--cim auto|require|off`. The default
`auto` mode runs base ingest/parse validation and skips CIM checks unless one or
more local apps are supplied with repeatable `--splunk-app <path>`. `require`
fails early without supplied apps. EvidenceForge never vendors or downloads
Splunkbase apps; supplied app directories or archives are copied/unpacked only
into the ephemeral run work directory.

Run the contributor smoke lane when changing emitted formats covered by this
pipeline:

```bash
uv run pytest --include-external-parsers -m external_parser --no-cov
```

The Splunk external-parser test uses a purpose-built multi-family parser sample,
not `tests/fixtures/scenarios/minimal.yaml`. It writes explicit host/sensor
directories and includes one compact record for every Splunk-supported
EvidenceForge family. To run only that live Splunk smoke after reviewing the
Splunk terms:

```bash
EFORGE_ACCEPT_SPLUNK_LICENSE=1 uv run pytest \
  --include-external-parsers \
  --no-cov \
  tests/external_parser/test_splunk_harness.py
```

## Current Coverage

Supported through SOF-ELK today:

- Zeek: every Zeek log type EvidenceForge can emit
- Cisco ASA firewall logs generated with `--target sof-elk`
- Web access logs
- Linux syslog generated with `--target sof-elk`
- Windows Security and Sysmon Snare/RFC3164 logs generated with `--target sof-elk`

Supported through Splunk today:

- Windows Security and Sysmon XML event streams generated with `--target splunk`
- Linux RFC5424 syslog and native Cisco ASA syslog generated with `--target splunk`
- Zeek per-sensor NDJSON, web access, proxy access, and eCAR JSON
- Optional CIM/data-model visibility checks when caller-supplied Splunk apps are present

Not yet supported:

- Native Windows/Sysmon XML files from the `default` target
- Default-target Linux syslog and Cisco ASA layouts
- Any dataset missing `OUTPUT_TARGET.txt` or marked with `default`
- Proxy logs in the SOF-ELK backend
- Snort fast alert and bash history in the Splunk backend v1
- eCAR in the SOF-ELK backend, which has no stable third-party standard parser target
- Elasticsearch output behavior

See [coverage-matrix.md](coverage-matrix.md) for the current parser/filter
mapping.

## How To Read Results

On failure, the most useful files are under the run work directory:

| Path | Purpose |
| --- | --- |
| `sof-elk/parsed/sof_elk_parser_failures.json` | Structured failure report with counts, fatal tags, and sample failed events |
| `sof-elk/parsed/*.jsonl` | Raw parsed events, including original parser tags |
| `sof-elk/stage/logstash/...` | The exact files as staged for SOF-ELK |
| `sof-elk/pipeline-logs/filebeat.log` | Filebeat container log |
| `sof-elk/pipeline-logs/logstash.log` | Logstash container log |
| `sof-elk/compose.yaml` | Generated Compose topology |
| `sof-elk/runtime-config-src/` | EvidenceForge-owned wrapper configs consumed by the prep service |
| `splunk/parsed/splunk_parser_failures.json` | Structured Splunk failure report with counts, parser issues, CIM status, and samples |
| `splunk/search-results/*.jsonl` | Raw Splunk REST search/export rows used for validation |
| `splunk/stage/data/...` | The exact files as staged for Splunk file monitoring |
| `splunk/pipeline-logs/splunkd.log` | Recent Splunk daemon log |
| `splunk/pipeline-logs/btool-*.txt` | Effective Splunk config snapshots |
| `splunk/compose.yaml` | Generated Splunk Compose topology |
| `splunk/runtime-config-src/` | EvidenceForge-owned Splunk app config and ephemeral supplied app copies |

Fatal failures are things that mean a record did not parse or required
normalized fields are missing. Optional enrichment misses are ignored only when
they are explicitly registered in code and documented in
[ignored-parser-tags.md](ignored-parser-tags.md).

## References

- [sof-elk-harness.md](sof-elk-harness.md): container lifecycle, downloads,
  mounts, staging, and artifacts
- [splunk-harness.md](splunk-harness.md): Splunk container lifecycle, generated
  app config, CIM mode, and artifacts
- [ignored-parser-tags.md](ignored-parser-tags.md): ignored parser tags and
  rationale
- [coverage-matrix.md](coverage-matrix.md): supported and unsupported log
  families
- [AGENTS.md](AGENTS.md): short orientation for future agents

## Acknowledgements

SOF-ELK® is a registered trademark of Lewes Technology Consulting, LLC. Used with permission.

Elastic, Filebeat, and Logstash are trademarks or registered trademarks of Elasticsearch B.V.

Splunk is a trademark or registered trademark of Splunk LLC. Splunk container
license and Splunkbase app terms are the caller's responsibility.
