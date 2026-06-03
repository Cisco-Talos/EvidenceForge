# Spillage Full Matrix Test

This scenario is a compact EvidenceForge harness for a data-driven spillage
matrix. It is intentionally a test fixture, not a realistic hunt story.

## Purpose

The storyline uses `family:` for every current built-in secret family and routes
them across every semantic spillage surface.

| Family | Surface | Actor Host | Expected Primary Evidence |
|---|---|---|---|
| `aws_iam` | `shell_history` | `WS-JLEE-01` | `bash_history` |
| `github_pat` | `shell_history` | `WS-JLEE-01` | `bash_history` |
| `db_uri` | `process_command_line` | `APP-MTX-01` | eCAR process telemetry |
| `bearer_token` | `process_command_line` | `WS-NKAPOOR-01` | eCAR plus Windows process creation telemetry |
| `slack_token` | `syslog_message` | `APP-MTX-01` | Linux `syslog.log` |
| `password_generic` | `syslog_message` | `APP-MTX-01` | Linux `syslog.log` |
| `gcp_api_key` | `http_request_url` | `WS-NKAPOOR-01` | HTTP web access plus Zeek `conn`/`http` |
| `github_fine_pat` | `http_request_url` | `WS-NKAPOOR-01` | HTTPS web access plus Zeek `conn`/TLS |
| `stripe_key` | `http_referrer` | `APP-MTX-01` | HTTP web access Referer plus Zeek `conn`/`http` |
| `jwt` | `http_referrer` | `APP-MTX-01` | HTTPS web access Referer plus Zeek `conn`/TLS |

The scenario also includes an omitted-scheme `http_request_url` spill using
`bearer_token` to verify auto-selection prefers HTTPS when compatible HTTPS web
servers exist.

## Web Scheme Matrix

The environment intentionally includes each web-server capability shape:

| Host | Services | Expected Scheme Capability |
|---|---|---|
| `WEB-01-HTTPONLY` | `http`, `nginx` | HTTP only |
| `WEB-02-HTTPSONLY` | `https`, `nginx` | HTTPS only |
| `WEB-03-LEGACY` | `nginx` | legacy generic, both HTTP and HTTPS |
| `WEB-04-BOTH` | `http`, `https`, `apache2` | both HTTP and HTTPS |

Explicit HTTP spillage should choose the first compatible HTTP target,
`WEB-01-HTTPONLY`. Explicit HTTPS spillage and omitted-scheme auto-selection
should choose a compatible HTTPS target, with no cleartext secret in Zeek
`http.json` for HTTPS flows.

The explicit forward proxy and `control-proxy-beacon` are present only for a
negative control: `http_*` spillage should remain direct and absent from
`proxy_access.log`.

## Quick Checks

Recommended commands:

```bash
uv run eforge validate scenarios/spillage-full-matrix-test/scenario.yaml
uv run eforge generate scenarios/spillage-full-matrix-test/scenario.yaml --output /private/tmp/eforge-spillage-full-matrix --force
uv run eforge eval /private/tmp/eforge-spillage-full-matrix --scenario scenarios/spillage-full-matrix-test/scenario.yaml
```

After generation, inspect `GROUND_TRUTH.json` first. There should be 11 emitted
spillage records: one for each built-in data-driven family, plus one extra
omitted-scheme HTTP surface test. HTTP-scheme records should have `scheme:
http`, port 80 connection evidence, web access evidence, and cleartext Zeek HTTP
where the path is visible. HTTPS-scheme records should have `scheme: https`, port
443 connection/TLS evidence, web access evidence, and no cleartext secret in
Zeek HTTP.
