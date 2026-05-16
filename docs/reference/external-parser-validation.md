# External Parser Validation

EvidenceForge has an optional external-parser lane for checking generated logs
against third-party parsers. The first harness covers SOF-ELK ingestion.

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
- Cisco ASA firewall logs staged through SOF-ELK's syslog archive path with
  `1100-preprocess-syslog.conf` and `6018-cisco_asa.conf`
- Web access logs staged through SOF-ELK's HTTPD archive path with
  `6100-httpd.conf`, `8060-postprocess-useragent.conf`, and
  `8110-postprocess-httpd.conf`
- Linux syslog staged through SOF-ELK's syslog archive path with
  `1100-preprocess-syslog.conf` plus the SOF-ELK DHCP, BIND, SSHD, PAM,
  iptables, and syslog postprocess filters

Not yet covered:

- Windows XML logs
- IDS, proxy, eCAR
- Elasticsearch output behavior

SOF-ELK has dedicated filters for the Zeek types it supports today, such as
`conn`, `dns`, `http`, `files`, `ssl`, `x509`, and `weird`. For EvidenceForge
Zeek files that SOF-ELK does not yet parse with a dedicated filter, the harness
still stages and ingests the file, validates JSON ingestion/counts, captures the
raw parsed event, and records in reports that the type did not use a dedicated
SOF-ELK filter.

The coverage contract is "every Zeek type EvidenceForge can emit," not just the
Zeek files produced by the current medium sample. Unit tests assert that the
harness mapping matches both the `zeek_*.yaml` format definitions and the Zeek
emitter registry. The external-parser smoke test renders one representative
file for each current EvidenceForge Zeek type through the EvidenceForge emitters
and sends all of them through the containerized SOF-ELK path.

## How It Works

The Zeek harness lives in `src/evidenceforge/external_parsers/sof_elk_zeek.py`.
Non-Zeek SOF-ELK source harnesses live in
`src/evidenceforge/external_parsers/sof_elk_sources.py`.
The combined runtime harness lives in
`src/evidenceforge/external_parsers/sof_elk.py`.
The dataset runner lives in `scripts/external_parser.py` and auto-detects which
validators apply to the generated files under a `data/` directory.

At runtime it:

1. Scans the generated `data/` directory to determine which validators apply.
2. Warns about generated log families that do not yet have an external parser
   validator.
3. Runs one combined SOF-ELK validation pass for every matching SOF-ELK-backed
   validator. Today that means Zeek, Cisco ASA, web access, and Linux syslog
   files share a single Filebeat/Logstash container pair. The validator phase
   shows stage progress plus host/sensor, log family, and subtype progress
   while parsed records are checked after the third-party parser has produced
   output.
4. Clones SOF-ELK at the pinned commit into an external cache, not into this
   repository.
5. Stages generated files under temporary SOF-ELK-style trees such as
   `/logstash/zeek/<sensor>/<zeek-log-name>.log` and
   `/logstash/syslog/<year>/<sensor>/cisco_asa.log` or
   `/logstash/httpd/<sensor>/web_access.log`, and
   `/logstash/syslog/<year>/<host>/syslog.log`.
6. Builds one temporary Logstash pipeline:
   - SOF-ELK's Beats input
   - unchanged SOF-ELK filter files
   - a JSONL file output wrapper
   It also builds one Filebeat config from SOF-ELK's unchanged source input
   files, such as `zeek.yml`, `syslog.yml`, and `httpdlog.yml`, plus
   supplemental EvidenceForge-only Zeek inputs for files SOF-ELK does not
   currently watch.
7. Runs pinned Logstash and Filebeat containers on an isolated container
   network.
8. Mounts staged input at `/logstash`.
9. Mounts the SOF-ELK checkout at `/usr/local/sof-elk`.
10. Writes parsed output to temp JSONL files.
11. Fails on count mismatches, fatal parser tags, missing required fields, or
   missing DNS answers/TTLs when the raw input had them.

Two containers per run are expected:

- `eforge-logstash-<runid>`
- `eforge-filebeat-<runid>`

Both are removed in a `finally` block. They are labeled with
`evidenceforge.external_parser=sof-elk`, so interrupted leftovers are easy to
find:

```bash
docker ps -a --filter label=evidenceforge.external_parser=sof-elk
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

Cisco ASA files stage through SOF-ELK's recursive syslog file input:

| EvidenceForge file | Staged SOF-ELK file |
| --- | --- |
| `<sensor>/<year>/cisco_asa.log` | `/logstash/syslog/<year>/<sensor>/cisco_asa.log` |
| `<sensor>/cisco_asa.log` | `/logstash/syslog/<inferred-year>/<sensor>/cisco_asa.log` |

Web access files stage through SOF-ELK's recursive HTTPD file input:

| EvidenceForge file | Staged SOF-ELK file |
| --- | --- |
| `<sensor>/web_access.log` | `/logstash/httpd/<sensor>/web_access.log` |
| `web_access.log` | `/logstash/httpd/default/web_access.log` |

Linux syslog files stage through SOF-ELK's recursive syslog file input:

| EvidenceForge file | Staged SOF-ELK file |
| --- | --- |
| `<host>/<year>/syslog.log` | `/logstash/syslog/<year>/<host>/syslog.log` |
| `<host>/syslog.log` | `/logstash/syslog/<inferred-year>/<host>/syslog.log` |

## Commands

Run the normal external parser smoke tests:

```bash
uv run pytest --include-external-parsers -m external_parser --no-cov
```

That smoke lane includes an emitter-rendered all-Zeek-type fixture to verify
the parser pipeline can discover, stage, ingest, and validate every current
EvidenceForge Zeek output type. Full dataset runs still evaluate whatever files
the scenario actually generated.

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

Given a runner work directory, the combined SOF-ELK run writes under one
`sof-elk/` subdirectory. Useful artifacts are:

| Path | Purpose |
| --- | --- |
| `sof-elk/stage/logstash/...` | All staged files as SOF-ELK sees them |
| `sof-elk/runtime-config/pipeline/` | Temporary Logstash pipeline wrapper plus copied SOF-ELK filters |
| `sof-elk/runtime-config/filebeat.yml` | Filebeat config that loads generated input files |
| `sof-elk/runtime-config/filebeat-inputs/` | SOF-ELK Filebeat inputs copied unchanged plus supplemental Zeek inputs |
| `sof-elk/parsed/*.jsonl` | Parsed events by SOF-ELK label type, such as `zeek_conn`, `syslog`, and `httpdlog` |
| `sof-elk/parsed/sof_elk_parser_failures.json` | One structured failure report for every supported log family in the run |
| `sof-elk/pipeline-logs/filebeat.log` | Filebeat container logs |
| `sof-elk/pipeline-logs/logstash.log` | Logstash container logs |

The failure report includes:

- expected and observed counts
- staged source paths
- parsed output paths
- fatal failure tag counts by log type
- DNS failure counts by question type
- whether each staged log type had a dedicated SOF-ELK filter
- sample failed events with `event.original`

This report is the main artifact to keep when triaging generated-data parser
failures.

## Parser Tag Policy

External parser tags are fatal only when they indicate that the record was not
parsed or required normalized fields are missing. Known optional enrichment
misses are ignored in normal validation output; the parsed JSONL still preserves
the raw parser-emitted tags for deep debugging.

The first ignored optional enrichment tag is SOF-ELK `_grokparsefail_6200-01`
on `zeek_dns`. SOF-ELK emits this when it cannot derive `dns.answers.ip` from
`dns.answers.data`; non-address DNS answer types such as `NS`, `PTR`, `MX`, and
`SOA` remain valid parsed DNS records.

Other explicitly ignored optional tags include `_grokparsefail_8110-01` on
`web_access`, which is optional HTTPD page/not-page classification after the
access record has already parsed. `_grokparsefailure_1100-03` is not ignored for
syslog-family sources because generated RFC3164 logs must be staged under a
year-bearing SOF-ELK archive path; otherwise Logstash can silently assign the
wrong year. In the combined SOF-ELK pipeline, `_grokparsefail_6018-01` is
ignored for
`syslog` because SOF-ELK's Cisco ASA filter opportunistically tries ordinary
Linux syslog rows that no earlier source-specific syslog filter marked
`parse_done`; that miss does not mean the Linux syslog framing failed.

## Current Medium Dataset Result

The medium dataset can now be generated and ingested through the harness. In the
current implementation, the pipeline discovers and emits JSONL for every staged
EvidenceForge Zeek file present in the dataset and validation passes when all
required normalized fields are present.

Observed in one run:

- `zeek_conn`: 10,790 input lines, 10,790 parsed events, no parser failure tags
- `zeek_dns`: 4,227 input lines, 4,227 parsed events; SOF-ELK emitted 341
  `_grokparsefail_6200-01` optional enrichment tags on non-address answers
- `zeek_http`: 593 input lines, 593 parsed events, no parser failure tags
- `zeek_files`: 582 input lines, 582 parsed events, no parser failure tags
- `zeek_ssl`: 1,128 input lines, 1,128 parsed events, no parser failure tags
- `zeek_x509`: 357 input lines, 357 parsed events, no parser failure tags
- `zeek_dhcp`: 28 input lines, 28 JSON-ingested events, no parser failure tags
- `zeek_ntp`: 152 input lines, 152 JSON-ingested events, no parser failure tags
- `zeek_ocsp`: 39 input lines, 39 JSON-ingested events, no parser failure tags

The ignored Zeek DNS enrichment tags were observed on `PTR` 194, `NS` 59,
`MX` 55, and `SOA` 33. The `dhcp`, `ntp`, and `ocsp` counts above are
JSON-ingestion checks because the pinned SOF-ELK config does not include
dedicated filters for those EvidenceForge Zeek types.

That medium run did not happen to generate `weird`, `packet_filter`, `pe`, or
`reporter` rows. Those types are still covered by the all-Zeek-type external
parser smoke test and by the staging/discovery unit tests.

## Current Non-Zeek Smoke Results

Small container smoke tests confirm:

- Cisco ASA: SOF-ELK parsed representative `302013` built and `302014`
  teardown records staged under `/logstash/syslog/<year>/<sensor>/cisco_asa.log`.
- Web access: SOF-ELK parsed representative Apache/Nginx combined access rows
  staged under `/logstash/httpd/<host>/web_access.log`.
- Linux syslog: generated RFC3164 rows stage under
  `/logstash/syslog/<year>/<host>/syslog.log`, allowing SOF-ELK to recover the
  correct year while parsing the source-specific sshd/PAM message body.
