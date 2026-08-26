---
description: "Exact time-window, baseline shaping, observation profile, and output schemas"
---

# Scenario Time, Baseline, and Output

Read this reference when the run window, baseline traffic, observation profile, or output changes.

## Time and top-level controls

`time_window` supports required `start`, exactly one of `end` or `duration`, and optional `warmup`
(default `8h`, minimum one hour when supplied). Start/end are ISO 8601 datetimes. Duration fields
use `d`, `h`, `m`, `s`, or `ms` components such as `2h30m`.

`generation_seed` is an unsigned 64-bit integer and defaults to 42. `observation_profile` is a
simple configured profile name and defaults to `complete`. `logon_grace_period` is a duration and
defaults to `30m`.

## Baseline activity

`baseline_activity` requires `description`, `intensity: low|medium|high`, and
`variation: low|medium|high`. It also supports `suspicious_noise:
low|medium|high|ludicrous` (default high), optional `traffic_rates`, `traffic_affinities` (default
`[]`), and `traffic_suppression` (default `[]`).

`traffic_rates` keys are configured traffic families. Each value is a positive integer, positive
`[lo, hi]` integer range, or `low|medium|high`. Prefer ordinary intensity controls unless the
exercise needs an exact family override.

An affinity supports `name`, `kind: web|connection`, `direction:
outbound|inbound|internal`, optional `destination` or `target`, `audience`, positive `weight`,
`participation` from 0–1, `per_client_sessions` as a nonnegative `[lo, hi]` range, optional
`cadence: diffuse|business_hours|periodic`, `request_profile`, `connection_profile`, and `seed`.
Inbound affinities require `target`; outbound/internal require `destination`. Web affinities use
`request_profile`; connection affinities use `connection_profile`.

An endpoint supports one or more of `identity`, `system`, `host`, or `ip`, plus `port` (1–65535,
default 443), `proto: tcp|udp|icmp`, and optional `service`. Audience fields are `users`,
`personas`, `groups`, `systems`, and `external_client_classes`, each defaulting to `[]`.

A connection `connection_profile` supports optional nonnegative `[lo, hi]` `durations`,
`orig_bytes`, and `resp_bytes`, plus weighted `conn_states` (default `{SF: 1.0}`).

A web `request_profile` contains `routes` (default `[]`). Each route requires origin-form `path`
and nonempty `methods`, plus positive `weight` (default 1). Each method profile supports weighted
`statuses` (default `{200: 1.0}`), optional `request_body_bytes`, `request_content_type`,
`request_wire_filename`, `request_multipart`, `response_body_bytes`, `response_multipart`, and
`content_type` (default `text/html`). Body byte fields are nonnegative `[lo, hi]` ranges and are
mutually exclusive with the corresponding multipart entity. Read the HTTP reference for the exact
multipart part schema.

A suppression supports optional `direction`, optional `kind`, lists `identities`, `domains`, and
`tags`, an `audience`, and required `factor` from 0–1. Zero removes matching default traffic;
intermediate factors down-rank it.

```yaml
baseline_activity:
  description: "Normal office activity"
  intensity: medium
  variation: medium
  suspicious_noise: high
  traffic_affinities:
    - name: partner-status
      kind: web
      direction: outbound
      destination: {identity: partner_portal, port: 443, service: ssl}
      audience: {personas: [developer]}
      participation: 0.5
      per_client_sessions: [1, 2]
```

Read the HTTP reference before defining route/method request profiles or multipart bodies.

## Output

`output` supports exactly required `logs`, required `destination`, and `compression` (default
`false`). Each log entry requires `format`; discover installed format names with
`eforge info formats --json` because formats can differ by installation.
The authored destination is a compatibility/provenance hint; the generate command owns the final
bundle location. Rendering targets such as `default`, `sof-elk`, and `splunk` are CLI choices, not
scenario fields.
