# External Parser Validation

EvidenceForge has an optional external-parser lane for checking generated logs
against third-party parsers. The first harness covers SOF-ELK Zeek `conn` and
`dns` ingestion.

The goal is not to prove that our JSON is valid JSON. The goal is to stage
generated files the way SOF-ELK expects to collect them, run SOF-ELK's own
Filebeat and Logstash parsing path, and capture enough evidence to fix
EvidenceForge output later when a parser rejects records.

## Current Scope

Supported in the V1 harness:

- Zeek connection logs
- Zeek DNS logs
- SOF-ELK Filebeat input paths from `lib/filebeat_inputs/zeek.yml`
- SOF-ELK Logstash filter files copied unchanged from a pinned checkout
- JSONL output instead of Elasticsearch

Not yet covered:

- Zeek `http`, `ssl`, `files`, `x509`, `ntp`, and other Zeek logs
- Windows XML logs
- ASA, IDS, syslog, proxy, web, eCAR
- Elasticsearch output behavior

## How It Works

The harness lives in `tests/helpers/sof_elk_zeek.py`.

At runtime it:

1. Clones SOF-ELK at the pinned commit into an external cache, not into this
   repository.
2. Stages generated Zeek files under a temporary SOF-ELK-style tree:
   `/logstash/zeek/<sensor>/conn.log` and `/logstash/zeek/<sensor>/dns.log`.
3. Builds a temporary Logstash pipeline:
   - a small Beats input wrapper
   - unchanged SOF-ELK filter files
   - a JSONL file output wrapper
4. Runs pinned Logstash and Filebeat containers on an isolated container
   network.
5. Mounts staged input at `/logstash`.
6. Mounts the SOF-ELK checkout at `/usr/local/sof-elk`.
7. Writes parsed output to temp JSONL files.
8. Fails on count mismatches, parser failure tags, missing required fields, or
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

Generated files are staged as follows:

| EvidenceForge file | Staged SOF-ELK file |
| --- | --- |
| `<sensor>/conn.json` | `/logstash/zeek/<sensor>/conn.log` |
| `<sensor>/dns.json` | `/logstash/zeek/<sensor>/dns.log` |
| `zeek_conn.json` | `/logstash/zeek/default/conn.log` |
| `zeek_dns.json` | `/logstash/zeek/default/dns.log` |

The flat `zeek_conn.json` and `zeek_dns.json` forms come from generated outputs
without explicit network sensors. They are adapted into a `default` sensor only
for parser validation.

## Commands

Run the normal external parser smoke tests:

```bash
uv run pytest --include-external-parsers -m external_parser --no-cov
```

Generate the medium dataset's Zeek logs and run the harness manually:

```bash
uv run eforge generate tests/fixtures/scenarios/medium-dataset.yaml \
  --output /private/tmp/eforge-sof-elk-medium \
  --formats zeek \
  --force \
  --verbose

uv run python -c 'from pathlib import Path; from tests.helpers.sof_elk_zeek import run_sof_elk_zeek_parser; run_sof_elk_zeek_parser(Path("/private/tmp/eforge-sof-elk-medium/data"), Path("/private/tmp/eforge-sof-elk-medium/harness"), timeout_seconds=180)'
```

For assessment/improvement loops, use the generated scenario output directory
from the coverage-test scenario workflow and pass its `data/` directory to
`run_sof_elk_zeek_parser(...)`. `scenarios/COVERAGE-TEST-PROMPT.md` is the
prompt used to create that scenario, not itself a runnable scenario YAML file.

## Cache And Images

The SOF-ELK checkout is downloaded by the host-side harness, then mounted into
the containers. It is not downloaded inside the containers and is not vendored
into this repository.

Defaults:

- SOF-ELK repo: `https://github.com/philhagen/sof-elk.git`
- SOF-ELK commit: defined by `SOF_ELK_COMMIT` in
  `tests/helpers/sof_elk_zeek.py`
- Filebeat image: defined by `FILEBEAT_IMAGE`
- Logstash image: defined by `LOGSTASH_IMAGE`

Set `EFORGE_EXTERNAL_CACHE_DIR` to control where the SOF-ELK checkout is cached.
If unset, the harness uses `$XDG_CACHE_HOME/evidenceforge/external-parsers` or
`~/.cache/evidenceforge/external-parsers`.

## Outputs And Failure Reports

Given a harness work directory, useful artifacts are:

| Path | Purpose |
| --- | --- |
| `stage/logstash/zeek/...` | Files as SOF-ELK sees them |
| `runtime-config/pipeline/` | Temporary Logstash pipeline wrapper plus copied SOF-ELK filters |
| `runtime-config/filebeat.yml` | Filebeat config that points at SOF-ELK's Zeek input file |
| `parsed/zeek_conn.jsonl` | Parsed connection events |
| `parsed/zeek_dns.jsonl` | Parsed DNS events |
| `parsed/sof_elk_parser_failures.json` | Structured failure report when validation fails |
| `pipeline-logs/filebeat.log` | Filebeat container logs |
| `pipeline-logs/logstash.log` | Logstash container logs |

The failure report includes:

- expected and observed counts
- staged source paths
- parsed output paths
- failure messages
- failure tag counts by log type
- DNS failure counts by question type
- sample failed events with `event.original`

This report is the main artifact to keep when triaging generated-data parser
failures.

## Current Medium Dataset Result

The medium dataset can now be generated and ingested through the harness. In the
current implementation, the pipeline discovers and parses every staged `conn`
and `dns` line, but validation fails because SOF-ELK tags some DNS records with
`_grokparsefail_6200-01`.

Observed in one run:

- `zeek_conn`: 10,790 input lines, 10,790 parsed events, no parser failure tags
- `zeek_dns`: 4,227 input lines, 4,227 parsed events, 341 parser failure tags
- DNS failures by question type: `PTR` 194, `NS` 59, `MX` 55, `SOA` 33

This is exactly the kind of generated-data finding the external-parser lane is
intended to expose. Do not patch SOF-ELK filters to make this pass. Later work
should decide whether EvidenceForge is emitting valid Zeek DNS records that
SOF-ELK models too narrowly, or whether the emitter should change to match real
Zeek output more closely.
