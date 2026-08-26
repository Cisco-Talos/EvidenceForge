---
description: "Exact network, remote-session, DNS, scan, beacon, and IDS event schemas"
---

# Scenario Network and Bulk Events

Read this reference when authoring any event type below. Every event accepts optional `technique`
and `description`; `type` selects the exact schema, and unknown fields are rejected.

**Contents:** connection and remote sessions · DHCP and scans · beacons · DNS and DGA ·
credential campaigns · IDS attachments

Network-owning events also accept `ids_alerts`, a list of `{sid, policy}` attachments. `sid` is an
integer from 1 through 2,147,483,647 and must be unique on the event. Omit `policy` to use the
configured signature policy, or use `policy: every`. A structured override may contain a
`detection_filter` and/or `event_filter`; each uses `track: by_src|by_dst`, positive `count`, and
positive `seconds`, while an event filter also requires `type: limit|threshold|both`.

Periodic events share `start_time`, exactly one of `interval` or `rate`, exactly one of `end_time`,
`duration`, or positive `count`, and `jitter` from 0 through 1. Duration strings use positive
`d`, `h`, `m`, `s`, or `ms` components such as `5m30s`.

## `connection`

Fields: `type`, required `dst_ip`, `dst_port`, `hostname`, `service`, `source_ip`, `method`, `uri`,
`status_code`, `user_agent`, `referrer`, `request_body_len`, `request_multipart`,
`response_body_len`, `response_multipart`, `orig_bytes`, `resp_bytes`, `conn_state`, `ids_alerts`,
`technique`, and `description`. `dst_port` defaults to `443`. A `hostname` is a bare FQDN without
scheme, port, or path. HTTP fields apply when `service: http`; read the HTTP reference for body,
file, multipart, and proxy semantics.

```yaml
- type: connection
  dst_ip: "203.0.113.60"
  dst_port: 443
  hostname: partner.example.com
  service: ssl
```

## `ssh_session`

Fields: `type`, optional `source_ip`, `ids_alerts`, `technique`, and `description`. The SSH action
bundle owns TCP/22, authentication, shell/session evidence, command ownership, and teardown; do
not add an independent `logon` or port-22 `connection` for the same session.

## `rdp_session`

Fields: `type`, optional `source_ip`, `ids_alerts`, `technique`, and `description`. The RDP action
bundle owns the source client, TCP/3389, target Type 10 session, and teardown; do not add an
independent Type 10 `logon` or port-3389 `connection` for the same session.

The target must be Windows and RDP-capable. Windows servers and domain controllers receive that
capability by type. A Windows workstation must declare at least one accepted service: `rdp`,
`remote-desktop`, `remote_desktop`, or `termservice`.

```yaml
systems:
  - hostname: WS-RDP-01
    ip: "10.0.1.20"
    os: "Windows 11"
    type: workstation
    services: [termservice]
```

## `dhcp_lease`

Fields: `type`, optional `mac_address`, `requested_ip`, `ids_alerts`, `technique`, and
`description`. Omitted identity fields are derived deterministically. The DHCP bundle owns the
transaction, lease identity, Zeek connection/DHCP evidence, and eligible client companions.

## `port_scan`

Fields: `type`, `source_ip`, `target_ips`, `target_segment`, `target_count`, `ports`, `protocol`,
`scan_rate`, `ids_alerts`, `technique`, and `description`. `source_ip` defaults to the storyline
system, `target_count` defaults to `50` and is bounded to 1–5,000, `ports` defaults to
`[22, 80, 443, 445, 3389]`, `protocol` is `tcp`, `udp`, or `icmp`, and positive `scan_rate`
defaults to `100.0`. Use explicit `target_ips` or a resolvable `target_segment` when the scan scope
matters.

## `beacon`

Fields: `type`, required `dst_ip`, `dst_port`, `hostname`, `service`, `source_ip`, `protocol`,
`action`, `method`, `uri`, `status_code`, `user_agent`, `referrer`, `request_body_len`,
`request_multipart`, `response_body_len`, `response_multipart`, `profile`, `http_sequence`,
`orig_bytes`, `resp_bytes`, `conn_state`, `dns_resolution`, `start_time`, `interval`, `rate`,
`end_time`, `duration`, `count`, `jitter`, `ids_alerts`, `technique`, and `description`.

Beacons require `interval`, forbid `rate`, default to port 443/TCP, `action: allow`, jitter `0.15`,
and `dns_resolution: cached`; use `each_tick` only when every tick should resolve. Optional
`http_sequence` entries can set `method`, `uri`, `status_code`, `user_agent`, `referrer`, exact or
`[lo, hi]` byte fields, and multipart bodies. Every entry must override at least one field.

## `dns_query`

Fields: `type`, required `query`, `qtype`, `rcode`, `ttl`, `answer`, `source_ip`, `ids_alerts`,
`technique`, and `description`. `qtype` is `A`, `AAAA`, `TXT`, `CNAME`, `MX`, `NULL`, `SRV`, or
`PTR`; `rcode` is `NOERROR`, `NXDOMAIN`, `SERVFAIL`, or `REFUSED`. A `NOERROR` response requires
`answer`. DKIM TXT answers must contain a parseable RSA public key.

## `web_scan`

Fields: `type`, required `dst_ip`, `dst_port`, `hostname`, `source_ip`, `preset`, `paths`,
`user_agent`, `status_codes`, `start_time`, `interval`, `rate`, `end_time`, `duration`, `count`,
`jitter`, `ids_alerts`, `technique`, and `description`. It requires positive `rate`, forbids
`interval`, and requires `preset`, `paths`, or both. `dst_port` defaults to 80 and jitter to 0.4.
Discover configured preset names with `eforge info web_scan_presets`; use `--json` directly only
when structured handling is needed. The names are runtime inventory, while this event structure is
not.

## `credential_spray`

Fields: `type`, `source_ip`, `pattern`, required nonempty `target_accounts`, `logon_type`, `success`,
`start_time`, `interval`, `rate`, `end_time`, `duration`, `count`, `jitter`, `technique`, and
`description`. It requires `interval`, forbids `rate`, defaults to `pattern: spray`, logon type 3,
and jitter 0.5. `pattern` is `spray`, `brute_force`, or `stuffing`. Optional `success` requires
`account` from `target_accounts` and integer `after >= 1`. Logon type 9 is invalid.

## `dga_queries`

Fields: `type`, `source_ip`, `length_range`, `charset`, `tld`, `seed`, `rcode_distribution`,
`answer_ip`, `start_time`, `interval`, `rate`, `end_time`, `duration`, `count`, `jitter`,
`ids_alerts`, `technique`, and `description`. It requires `interval` and forbids `rate`.
`length_range` defaults to `[8, 15]`, must be ordered, and cannot exceed the 63-byte DNS label
limit. `rcode_distribution` uses supported DNS rcodes and sums to approximately 1; any positive
`NOERROR` probability requires `answer_ip`.

## `dns_tunnel`

Fields: `type`, required `base_domain`, `encoding`, `qtype`, `label_length`, `payload`,
`payload_size`, `source_ip`, `start_time`, `interval`, `rate`, `end_time`, `duration`, `count`,
`jitter`, `ids_alerts`, `technique`, and `description`. It requires `interval`, forbids `rate`, and
uses `base32`, `base64`, or `hex` encoding. `qtype` is `TXT`, `NULL`, or `CNAME`; `label_length` is
1–63. Literal `payload` and generated `payload_size` are each capped at 1 MiB; `payload_size`
defaults to 256.
