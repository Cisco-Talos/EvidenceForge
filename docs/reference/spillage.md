# Spillage event type

The `spillage` event type emits a **synthetic** credential/secret into a semantic
exposure *surface* of the generated logs, and records it in the canonical
machine-readable ground-truth document. It exists so defenders can score a log scrubber / DLP /
pre-ingest masker against labeled positives, train analysts to recognize
credential disclosure, and validate retroactive log-cleanup.

## Scenario syntax

```yaml
storyline:
  - id: spill-aws-bash
    time: "+20m"
    actor: nina.kapoor
    system: APP-SRV-01          # Linux host (v1 surfaces are Linux-modeled)
    activity: "AWS access key leaked via bash history"
    events:
      - type: spillage
        surface: shell_history  # semantic surface, never an emitter name
        family: aws_iam         # synthesize a safe canonical fake, OR:
        # value: "Bearer EvidenceForgeFake_INTERNAL_SSO_TOKEN_v1"  # a literal

  - id: spill-api-key-referrer
    time: "+24m"
    actor: nina.kapoor
    system: WS-NKAPOOR-01
    activity: "API key leaked in HTTPS Referer header"
    events:
      - type: spillage
        surface: http_referrer
        family: gcp_api_key
        scheme: https          # optional; only valid on http_request_url/http_referrer
```

Provide **exactly one** of `family` (synthesize a fresh value from a data-driven
family) or `value` (a literal that must pass the safety guardrails). For a family,
a **new value is synthesized per event** from the family's `value_template`, then
a varied **carrier line** is selected for the surface and the value is rendered
into it with surface-appropriate encoding — routed through the canonical modeled
generation path, not a raw emitter shortcut. No two spills are byte-identical, so
the corpus is not a single memorizable string.

### Surfaces

| Surface | Modeled path | Output (source) | Encoding applied |
|---|---|---|---|
| `shell_history` | bash command | `bash_history` (`…/bash_history/<user>.bash_history`) | shell-quoting (`shlex.quote`) |
| `process_command_line` | process execution (under the actor's session) | `ecar` (EDR process telemetry, **required**; on Windows the credential also lands in 4688, but eval keys on `ecar`) | shell-quoting (`shlex.quote`) |
| `syslog_message` | syslog event | `syslog` (`…/syslog.log`) | control-character escaping (single-line) |
| `http_request_url` | HTTP/S request to a web server | `web_access` (the server's combined access log; credential in the request URL/query string → `path` field) | percent-encoding (`urllib.parse.quote`) |
| `http_referrer` | HTTP/S request to a web server | `web_access` (credential in the `Referer` header; the request path is benign) | percent-encoding (`urllib.parse.quote`) |

`shell_history`/`syslog_message` are Linux-modeled; `process_command_line` and the
`http_*` surfaces are cross-OS. For `process_command_line` the carrier is OS-aware:
a Windows host renders a `cmd`/PowerShell/`.exe` command line (from a family's
`process_command_line_windows` carriers, or a generic Windows fallback), never a
Linux `/usr/bin` command — so the Windows 4688/eCAR record stays plausible. The
`http_*` surfaces model an outbound request **from the actor's host directly to a
web server** — a host with `roles: [web_server]` must exist in the environment (a
hard validation error otherwise), since the credential is recorded by that
server's `web_access` log. The request is sent direct (proxy-bypassed) so the
access-log `client_ip` is always the actor's host and the credential cannot be
rewritten or scrubbed by an intervening explicit proxy. If multiple `web_server`
hosts exist, a server other than the actor's own host is preferred, then the
lexicographically-first (by hostname) is chosen deterministically. The destination server's FQDN is recorded
in the ground-truth record's `target_system` (the same name as its `web_access` output
directory). `SURFACE_FORMATS` in `generation/spillage.py` is the single extension
point (renderer + validation + eval all consume it).

### HTTP/HTTPS scheme selection

`http_request_url` and `http_referrer` may include `scheme: http` or
`scheme: https`. The field is rejected on non-HTTP surfaces. When `scheme` is
omitted, the generator still chooses a compatible web server and derives an
effective scheme: HTTPS is preferred when the selected target supports it, but an
HTTP-only target uses HTTP.

Web-server scheme support comes from `services` on systems with
`roles: [web_server]`:

- `http` is an explicit HTTP marker.
- `https`, `ssl`, or `tls` are explicit HTTPS markers.
- `http` plus any HTTPS marker means both schemes are supported.
- If no explicit scheme marker is present, legacy generic web markings support
  both schemes: empty `services`, `roles: [web_server]`, or stack indicators
  such as `nginx`, `apache2`, `httpd`, or `iis`.

An explicit `scheme` can only target web servers that support that scheme, and
validation fails when no compatible server exists. Effective HTTP uses port 80
and service `http`; effective HTTPS uses port 443 and service `https`. Both stay
direct and proxy-bypassed. HTTP can expose the rendered value in `web_access` and
Zeek `http` evidence when visible. HTTPS exposes the value in `web_access` while
network evidence stays at Zeek connection/TLS level, so the secret is not present
in cleartext Zeek HTTP logs.

### Correlation scope (v1)

How much correlated system activity each surface produces, so a dataset never
labels unrealistic standalone evidence as fully correlated:

- **`http_request_url` / `http_referrer`** — fully correlated: the credential
  rides on a real modeled HTTP/S connection (web access log + network evidence).
- **`process_command_line`** — a real, **in-window** process-execution record
  (eCAR) with a durable, unique process identity, emitted as a *standalone*
  process attributed to the actor (not interleaved into a busy interactive
  shell's foreground timeline, so it can't be shifted/dropped during eCAR
  post-flush normalization). Because it is a *live* process record, its carriers
  are deliberately **local commands only** (`aws configure set`, `git config`,
  `os.environ[...]=`, `cmd /c set`, …) — never a network tool like `curl`/`psql`
  — so the process record is self-consistent and never implies an outbound
  connection that isn't modeled. Network-tool credential leaks are covered by the
  other surfaces below.
- **`shell_history`** — the bash-history-**file** exposure: the credential left in
  a user's `~/.bash_history`. A history file legitimately records commands run at
  any time (including network tools like `curl`/`scp`), so its carriers may be
  network commands — this is a *historical artifact*, not a claim of correlated
  in-window network/process telemetry, and v1 emits none for the carrier. Use
  `process_command_line` for the live EDR-correlated form.
- **`syslog_message`** — a standalone application syslog line; v1 does not emit
  correlated service/process evidence for it.

### Families

A curated set (`aws_iam`, `github_pat`, `github_fine_pat`, `gcp_api_key`,
`slack_token`, `stripe_key`, `jwt`, `db_uri`, `bearer_token`, `password_generic`).
Each family is **data** in `config/activity/secret_families.yaml` — a `regex`
(for literal validation), a `value_template` (per-event synthesis), and per-surface
`carriers` (varied carrier-line templates). All are user-customizable via the
overlay at `.eforge/config/activity/secret_families.yaml`, including adding new
families. Template tokens (`{alnum:N}`, `{host}`, `{marker}`, …) are expanded by
the code engine and always embed a poison marker so the value stays provably fake.
When authoring an overlay `value_template`, keep the poison marker **inside the
same credential-shaped token** as any long random run (not merely elsewhere in the
value): the per-token safety sweep requires every high-entropy token to carry its
own marker. `eforge validate-config` *samples* each template/`examples` family
once and safety-checks it; a borderline template whose safety depends on the
random draw is better made unconditionally safe than relied on to pass by luck.

## Safety guardrails

Spillage intentionally produces *provably synthetic* data — the opposite of the
realism guidance for other event types — so defenders can pre-allowlist it. Every
emitted value is safety-checked before it can land: a literal `value:` at `eforge
validate` **and** again at generation time; a family-synthesized value at
generation time **and** at `eforge validate-config` (which synthesizes and checks
every family template). The four guardrails are:

1. **Marker/allowlist** — contains a poison marker (`EvidenceForgeFake`,
   `EXAMPLE`, `DO_NOT_USE`, `EFORGE_TEST`, …) **or** is a vendor-published fake.
   This includes a **per-credential-token sweep**: every *credential-shaped*
   substring must itself carry a marker (or overlap a vendor fake), so a real key
   with a marker merely appended elsewhere is rejected. The sweep covers both the
   structured family regexes *and* a generic high-entropy detector (long,
   random-looking tokens mixing letters and digits — e.g. OpenAI/SendGrid/Azure
   keys, 40-hex tokens), so a real secret of an unmodeled shape is caught too.
2. **Host allowlist** — any host embedded in the value (URL, `user@host`, or bare
   domain) is an RFC 2606 / RFC 6761 reserved domain or an RFC 5737 / 3849 / 1918
   address. In a URL/userinfo host position this also resolves obfuscated IPv4
   (dotless-decimal, hex, octal) and IDN/punycode hosts so a real public IP or
   domain cannot hide behind an alternate encoding.
3. **Family regex** — a literal declared for a `family` must match its regex.
4. **Single-line / control-free** — the value carries no CR/LF or other line
   separator (so a credential cannot be split across log lines) and no other
   control character such as ESC/NUL/BEL (so it cannot inject a terminal escape
   sequence when rendered raw into a command line). Only tab is allowed. Spillage
   is not a log-injection primitive.

This is a strong best-effort synthetic-data contract, not a formal proof. Known
residuals: a *bare* integer (not in a URL/host position) is not treated as a
host (it is not one); a *short* or low-entropy secret below the high-entropy
threshold can still pass with only a detached marker; entropy detection is a
heuristic; and a hand-crafted `jwt` **literal** whose final segment is an
artificially short, all-lowercase string can be mis-read as a bare host and
rejected (a real or family-synthesized JWT signature is long and mixed-case, so
this false-positive does not occur in practice). The poison-marker requirement
still applies to every accepted value.

A value failing these (or an unknown family, or a surface whose output format/OS
cannot actually emit it) is a hard validation **error** and never reaches
generation — so ground truth never labels a credential that was not written.
At generation time the same guarantee holds dynamically: if a surface cannot
actually emit (a `shell_history` spill dwell-shifted past the window, or an
`http_*` request whose actor→web-server path no sensor observes, so the
connection is filtered out), the event is recorded as `skipped` and **excluded
from the canonical document** rather than mislabeled as landed evidence — `GROUND_TRUTH.md` notes it as "Skipped
(not emitted)".

## Ground truth

Each spillage event is recorded in two complementary places: **full
machine-readable labels** live in the canonical `GROUND_TRUTH.json` document, and
a **redacted human-readable summary** (preview + SHA-256, never the full secret)
lives in `GROUND_TRUTH.md`.

`GROUND_TRUTH.json` is the schema-versioned machine-readable companion to
`GROUND_TRUTH.md`. It stores scenario/report metadata plus an `events` array
containing one record per tracked storyline or red-herring event. Spillage uses
the same common event envelope as every other event, with spillage-specific
scoring fields nested under `attributes`. Each emitted spillage event looks like:

```json
{"schema_version":1,
 "scenario_name":"spill-demo",
 "events":[
   {"record_id":"spill-aws-bash#0","kind":"spillage",
    "storyline_id":"spill-aws-bash","time":"2024-03-18T14:20:07Z",
    "actor":"nina.kapoor","system":"APP-SRV-01","activity":"credential spill",
    "ground_truth_section":"storyline","emitted":true,
    "attributes":{
      "surface":"shell_history","family":"aws_iam",
      "value":"AKIAIOSFODNN7EXAMPLE","value_sha256":"…",
      "rendered_value":"AKIAIOSFODNN7EXAMPLE","rendered_sha256":"…",
      "expected_sources":["bash_history"]
    }}
 ]}
```

Field notes for scoring a scrubber by hand:

- `attributes.rendered_value` is the **exact on-disk byte form** (surface-encoded —
  shell-quoted for `shell_history`, control-escaped for `syslog_message`). Match
  **this** against the logs; `attributes.value` is the canonical secret (equal for simple
  values, but they differ when the credential contains shell metacharacters).
- `time` is the **actual emitted timestamp** of the log line, so records join to
  log lines by timestamp.
- For the `http_*` surfaces, `value` and `rendered_value` differ when the
  credential contains URL metacharacters (`attributes.rendered_value` is
  percent-encoded — match that), and the record carries an
  `attributes.target_system` field with the destination web server's **FQDN**
  (identical to its `web_access` output directory) plus `attributes.scheme`
  (`http` or `https`); the `client_ip` on that line is the actor's host.
- `emitted=false` plus `skipped_reason` means the storyline intended a spill but
  the final generated logs did not contain it (for example, dwell-shifted outside
  the scenario window). Such records remain honest machine-readable ground truth,
  but they do not carry `attributes.rendered_value` because nothing landed on disk.
- Locate a record's file from `attributes.expected_sources` + `system` + `actor` (e.g.
  `<system_fqdn>/bash_history/<actor>.bash_history`, `<system_fqdn>/syslog.log`),
  for `http_*` surfaces directly from `<attributes.target_system>/web_access.log`,
  or simply `grep -rl "<attributes.rendered_value>"` the output tree.
- `record_id` (`<storyline_id>#<n>`) uniquely addresses each positive, even when
  the same credential is spilled more than once.

Byte offsets/line numbers are intentionally omitted: emitters stream output, so a
value's position is not known at ground-truth-writing time.

`eforge eval` reads this canonical document to recognize spillage events: its causality
pillar confirms each labeled value actually landed in the logs (so a spillage
dataset passes acceptance) — it does **not** re-run synthesis. Scrubber
precision/recall scoring is out of scope for this PR; when added it will fold into
`eforge eval` rather than a new top-level command.
