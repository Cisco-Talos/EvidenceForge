---
description: "Exact scenario network segments, sensors, firewall, NAT, and public reachability"
---

# Scenario Network Topology

Read this reference whenever `environment.network`, visibility, sensors, firewall policy, NAT, or
public reachability changes. Network topology is optional, but selected Zeek, IDS, and firewall
evidence requires a compatible observable path.

## Network shape

`network` supports exactly required `segments`, optional `sensors` (default `[]`), and optional
`public_cidrs` (default `[]`). At least one segment is required when `network` is present.

Each segment supports required `name`, `cidr`, and `exposure: internal|external|both`, plus
`description` (default empty), `systems` (default `[]`), and optional `external_ratio`. A ratio is
valid only with `exposure: both` and must be 0–1. System membership may be declared or inferred by
CIDR.

```yaml
environment:
  network:
    segments:
      - name: workstations
        cidr: "10.0.1.0/24"
        description: "User LAN"
        systems: [WS-DEV-01]
        exposure: internal
    public_cidrs: ["203.0.113.0/28"]
    sensors: []
```

`public_cidrs` contains organization-owned public address blocks. When omitted, external scan
targets may be derived from static NAT VIPs. External inbound activity reaches a private host only
through modeled static NAT; a public-addressed modeled host can be reached directly.

## Sensors

Each sensor supports these exact fields:

- Required: `type: network|ids|firewall`, `name`, and `monitoring_segments`.
- Identity/placement: `hostname` (default `name` when blank),
  `direction: inbound|outbound|bidirectional` (default bidirectional), and
  `placement: span|tap` (default span).
- Collection: `capture_profile` (default configured profile when blank) and `log_formats`
  (default `[zeek]`). Discover format and profile names from runtime inventory only when the
  project can change them.
- Firewall presentation: `interfaces`, `interface_security_levels` (0–100), ordered `policy`,
  `default_action: deny|permit`, `deny_ratio` (0–50, default 5),
  `drop_mode: drop|reject`, `threat_detection_rate` (nonnegative, default 10), and `nat_rules`.
- Optional `description`.

A SPAN sensor sees eligible intra-segment traffic; a TAP sees traffic crossing its monitored
boundary. `monitoring_segments` must use exact declared segment names.

## Firewall policy and NAT

Firewall `policy` entries support required `src` and `dst`, `ports` (default `[]`, meaning any),
and `action: permit|deny` (default permit). Rules are evaluated in order and the first match wins;
`default_action` handles unmatched traffic. Sources/destinations may be segment names, `external`,
`any`, IPs, or CIDRs.

NAT entries support exactly `type: dynamic_pat|static`, `src` (one string or list), required
`mapped_ip`, `real_ip` (default empty), and `interface_pair` (default `[]`). Static NAT needs the
real internal IP; dynamic PAT maps matching sources to a shared public address.

```yaml
sensors:
  - type: firewall
    name: edge-fw
    hostname: fw01
    monitoring_segments: [workstations]
    direction: bidirectional
    placement: tap
    log_formats: [cisco_asa]
    interfaces: {workstations: inside}
    interface_security_levels: {inside: 100, outside: 0}
    policy:
      - {src: workstations, dst: external, ports: [80, 443], action: permit}
    default_action: deny
    nat_rules:
      - type: dynamic_pat
        src: workstations
        mapped_ip: "203.0.113.5"
```

Do not add placeholder sensors merely to silence a warning. Choose topology that corresponds to
the exercise's intended collection boundary and retain intentional blind spots.
