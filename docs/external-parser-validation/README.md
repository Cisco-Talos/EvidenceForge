# External Parser Validation

External Parser Validation checks generated EvidenceForge logs with third-party
parsers. The goal is format and parseability validation, not blind realism
review and not the deterministic `eforge eval` scoring model.

The current implementation uses SOF-ELK's Filebeat and Logstash parsing path
through Docker Compose or Podman Compose. Generated files are staged in the
directory layout SOF-ELK expects, a short-lived prep service downloads the
pinned SOF-ELK checkout into Compose-managed volumes, and parsed events are
written to temporary JSONL artifacts instead of Elasticsearch.

## Quickstart

Run the full developer-facing pipeline against an existing generated `data/`
directory:

```bash
uv run python scripts/external_parser.py scenarios/apt-healthcare-breach/data
```

For a durable report location, pass a work directory:

```bash
uv run python scripts/external_parser.py \
  scenarios/apt-healthcare-breach/data \
  --work-dir /private/tmp/eforge-parser-validation \
  --timeout 180
```

Each run clears the parser-owned `sof-elk/stage`, `sof-elk/parsed`,
`sof-elk/pipeline-logs`, `sof-elk/filebeat-data`, `sof-elk/logstash-data`, and
`sof-elk/runtime-config-src` directories before staging new input. Use a unique
work directory when you need to keep artifacts from multiple runs side by side.

The runner auto-detects supported logs. Do not pass validator names for normal
use. Unsupported logs are reported as warnings so new formats are visible
without blocking supported parser checks.

Docker Compose v2 or Podman Compose is required. The default runtime is Docker
Compose when available, then Podman Compose. Use `--runtime podman` to force
Podman Compose.

Run the contributor smoke lane when changing emitted formats covered by this
pipeline:

```bash
uv run pytest --include-external-parsers -m external_parser --no-cov
```

## Current Coverage

Supported through SOF-ELK today:

- Zeek: every Zeek log type EvidenceForge can emit
- Cisco ASA firewall logs
- Web access logs
- Linux syslog
- Windows Security and Sysmon Snare/RFC3164 sidecars

Not yet supported:

- Native Windows/Sysmon XML files (the parallel Snare sidecars are validated)
- IDS, proxy, eCAR
- Bash history
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

Fatal failures are things that mean a record did not parse or required
normalized fields are missing. Optional enrichment misses are ignored only when
they are explicitly registered in code and documented in
[ignored-parser-tags.md](ignored-parser-tags.md).

## References

- [sof-elk-harness.md](sof-elk-harness.md): container lifecycle, downloads,
  mounts, staging, and artifacts
- [ignored-parser-tags.md](ignored-parser-tags.md): ignored parser tags and
  rationale
- [coverage-matrix.md](coverage-matrix.md): supported and unsupported log
  families
- [AGENTS.md](AGENTS.md): short orientation for future agents
