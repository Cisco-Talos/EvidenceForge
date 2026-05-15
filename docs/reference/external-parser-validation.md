# External Parser Validation

EvidenceForge has an optional external-parser lane for checking generated logs
against third-party parsers. The first harness covers SOF-ELK Zeek ingestion.

The goal is not to prove that our JSON is valid JSON. The goal is to stage
generated files the way SOF-ELK expects to collect them, run SOF-ELK's own
Filebeat and Logstash parsing path, and capture enough evidence to fix
EvidenceForge output later when a parser rejects records.

## Current Scope

Supported in the V1 harness:

- All EvidenceForge Zeek log files:
  `conn`, `dns`, `http`, `files`, `ssl`, `x509`, `weird`, `dhcp`, `ntp`,
  `ocsp`, `packet_filter`, `pe`, and `reporter`
- SOF-ELK Filebeat input paths copied unchanged from `lib/filebeat_inputs/zeek.yml`
- Supplemental Filebeat inputs for EvidenceForge Zeek logs SOF-ELK does not
  currently watch: `ntp`, `ocsp`, `packet_filter`, `pe`, and `reporter`
- SOF-ELK Logstash filter files copied unchanged from a pinned checkout
- JSONL output instead of Elasticsearch

Not yet covered:

- Windows XML logs
- ASA, IDS, syslog, proxy, web, eCAR
- Elasticsearch output behavior

SOF-ELK has dedicated filters for the Zeek types it supports today, such as
`conn`, `dns`, `http`, `files`, `ssl`, `x509`, and `weird`. For EvidenceForge
Zeek files that SOF-ELK does not yet parse with a dedicated filter, the harness
still stages and ingests the file, validates JSON ingestion/counts, captures the
raw parsed event, and records in reports that the type did not use a dedicated
SOF-ELK filter.

## How It Works

The harness lives in `src/evidenceforge/external_parsers/sof_elk_zeek.py`.
The dataset runner lives in `scripts/external_parser.py` and auto-detects which
validators apply to the generated files under a `data/` directory.

At runtime it:

1. Scans the generated `data/` directory to determine which validators apply.
2. Warns about generated log families that do not yet have an external parser
   validator.
3. Runs every matching validator. Today that means SOF-ELK for Zeek files. The
   validator phase shows stage progress plus host/sensor, log family, and
   subtype progress while parsed records are checked after the third-party
   parser has produced output.
4. Clones SOF-ELK at the pinned commit into an external cache, not into this
   repository.
5. Stages generated Zeek files under a temporary SOF-ELK-style tree:
   `/logstash/zeek/<sensor>/<zeek-log-name>.log`.
6. Builds a temporary Logstash pipeline:
   - a small Beats input wrapper
   - unchanged SOF-ELK filter files
   - a JSONL file output wrapper
   It also builds Filebeat input config from SOF-ELK's unchanged `zeek.yml`
   plus supplemental EvidenceForge-only Zeek inputs for files SOF-ELK does not
   currently watch.
7. Runs pinned Logstash and Filebeat containers on an isolated container
   network.
8. Mounts staged input at `/logstash`.
9. Mounts the SOF-ELK checkout at `/usr/local/sof-elk`.
10. Writes parsed output to temp JSONL files.
11. Fails on count mismatches, parser failure tags, missing required fields, or
   missing DNS answers/TTLs when the raw input had them.

Two containers per run are expected:

- `eforge-logstash-<runid>`
- `eforge-filebeat-<runid>`

Both are removed in a `finally` block. They are labeled with
`evidenceforge.external_parser=sof-elk-zeek` so interrupted leftovers are easy
to find:

```bash
docker ps -a --filter label=evidenceforge.external_parser=sof-elk-zeek
```

## Staging Rules

SOF-ELK watches recursive paths such as `/logstash/zeek/**/conn.*` and
`/logstash/zeek/**/dns.*`, so the harness keeps the SOF-ELK collection shape.

Generated files are staged as follows. Per-sensor files keep their sensor
directory; flat generated files are adapted into a synthetic `default` sensor.

| EvidenceForge file | Staged SOF-ELK file |
| --- | --- |
| `<sensor>/conn.json` | `/logstash/zeek/<sensor>/conn.log` |
| `<sensor>/dns.json` | `/logstash/zeek/<sensor>/dns.log` |
| `zeek_conn.json` | `/logstash/zeek/default/conn.log` |
| `zeek_dns.json` | `/logstash/zeek/default/dns.log` |
| `zeek_http.json` | `/logstash/zeek/default/http.log` |
| `zeek_files.json` | `/logstash/zeek/default/files.log` |
| `zeek_ssl.json` | `/logstash/zeek/default/ssl.log` |
| `zeek_x509.json` | `/logstash/zeek/default/x509.log` |
| `zeek_weird.json` | `/logstash/zeek/default/weird.log` |
| `zeek_dhcp.json` | `/logstash/zeek/default/dhcp.log` |
| `zeek_ntp.json` | `/logstash/zeek/default/ntp.log` |
| `zeek_ocsp.json` | `/logstash/zeek/default/ocsp.log` |
| `zeek_packet_filter.json` | `/logstash/zeek/default/packet_filter.log` |
| `zeek_pe.json` | `/logstash/zeek/default/pe.log` |
| `zeek_reporter.json` | `/logstash/zeek/default/reporter.log` |

The same basename mapping applies inside real sensor directories, for example
`zeek-core/http.json` stages to `/logstash/zeek/zeek-core/http.log`.

## Commands

Run the normal external parser smoke tests:

```bash
uv run pytest --include-external-parsers -m external_parser --no-cov
```

Generate the medium dataset's Zeek logs and run the harness:

```bash
uv run eforge generate tests/fixtures/scenarios/medium-dataset.yaml \
  --output /private/tmp/eforge-sof-elk-medium \
  --formats zeek \
  --force \
  --verbose

uv run python scripts/external_parser.py \
  /private/tmp/eforge-sof-elk-medium/data \
  --work-dir /private/tmp/eforge-sof-elk-medium/harness \
  --timeout 180
```

For assessment/improvement loops, use the generated scenario output directory
from the coverage-test scenario workflow and pass its `data/` directory to the
same `scripts/external_parser.py ...` command. The runner will choose matching
validators automatically and print warnings for generated logs that do not yet
have a validator.
`scenarios/COVERAGE-TEST-PROMPT.md` is the prompt used to create that scenario,
not itself a runnable scenario YAML file.

## Cache And Images

The SOF-ELK checkout is downloaded by the host-side harness, then mounted into
the containers. It is not downloaded inside the containers and is not vendored
into this repository.

Defaults:

- SOF-ELK repo: `https://github.com/philhagen/sof-elk.git`
- SOF-ELK commit: defined by `SOF_ELK_COMMIT` in
  `src/evidenceforge/external_parsers/sof_elk_zeek.py`
- Filebeat image: defined by `FILEBEAT_IMAGE`
- Logstash image: defined by `LOGSTASH_IMAGE`

Set `EFORGE_EXTERNAL_CACHE_DIR` to control where the SOF-ELK checkout is cached.
If unset, the harness uses `$XDG_CACHE_HOME/evidenceforge/external-parsers` or
`~/.cache/evidenceforge/external-parsers`.

## Outputs And Failure Reports

Given a runner work directory, each validator writes under its own subdirectory
such as `sof-elk-zeek/`. Useful SOF-ELK Zeek artifacts are:

| Path | Purpose |
| --- | --- |
| `sof-elk-zeek/stage/logstash/zeek/...` | Files as SOF-ELK sees them |
| `sof-elk-zeek/runtime-config/pipeline/` | Temporary Logstash pipeline wrapper plus copied SOF-ELK filters |
| `sof-elk-zeek/runtime-config/filebeat.yml` | Filebeat config that loads generated input files |
| `sof-elk-zeek/runtime-config/filebeat-inputs/zeek.yml` | SOF-ELK Zeek Filebeat input copied unchanged |
| `sof-elk-zeek/runtime-config/filebeat-inputs/evidenceforge-zeek.yml` | Supplemental inputs for EvidenceForge Zeek files SOF-ELK does not watch |
| `sof-elk-zeek/parsed/zeek_*.jsonl` | Parsed events by Zeek label type |
| `sof-elk-zeek/parsed/sof_elk_parser_failures.json` | Structured failure report when validation fails |
| `sof-elk-zeek/pipeline-logs/filebeat.log` | Filebeat container logs |
| `sof-elk-zeek/pipeline-logs/logstash.log` | Logstash container logs |

The failure report includes:

- expected and observed counts
- staged source paths
- parsed output paths
- failure messages
- failure tag counts by log type
- DNS failure counts by question type
- whether each staged log type had a dedicated SOF-ELK filter
- sample failed events with `event.original`

This report is the main artifact to keep when triaging generated-data parser
failures.

## Current Medium Dataset Result

The medium dataset can now be generated and ingested through the harness. In the
current implementation, the pipeline discovers and emits JSONL for every staged
EvidenceForge Zeek file present in the dataset, but validation fails because
SOF-ELK tags some DNS records with `_grokparsefail_6200-01`.

Observed in one run:

- `zeek_conn`: 10,790 input lines, 10,790 parsed events, no parser failure tags
- `zeek_dns`: 4,227 input lines, 4,227 parsed events, 341 parser failure tags
- `zeek_http`: 593 input lines, 593 parsed events, no parser failure tags
- `zeek_files`: 582 input lines, 582 parsed events, no parser failure tags
- `zeek_ssl`: 1,128 input lines, 1,128 parsed events, no parser failure tags
- `zeek_x509`: 357 input lines, 357 parsed events, no parser failure tags
- `zeek_dhcp`: 28 input lines, 28 JSON-ingested events, no parser failure tags
- `zeek_ntp`: 152 input lines, 152 JSON-ingested events, no parser failure tags
- `zeek_ocsp`: 39 input lines, 39 JSON-ingested events, no parser failure tags
- DNS failures by question type: `PTR` 194, `NS` 59, `MX` 55, `SOA` 33

This is exactly the kind of generated-data finding the external-parser lane is
intended to expose. Do not patch SOF-ELK filters to make this pass. Later work
should decide whether EvidenceForge is emitting valid Zeek DNS records that
SOF-ELK models too narrowly, or whether the emitter should change to match real
Zeek output more closely. The `dhcp`, `ntp`, and `ocsp` counts above are
JSON-ingestion checks because the pinned SOF-ELK config does not include
dedicated filters for those EvidenceForge Zeek types.
