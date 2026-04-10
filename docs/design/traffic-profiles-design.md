# Design: Role/Persona-Aware Network Traffic Model

## Problem

Current baseline network generation is mostly role-agnostic. Connections are generated semi-randomly with minimal consideration of what a given host should be doing on the network. Expert reviewers caught symptoms like domain controllers scanning external IPs on Redis ports. The root cause is that the generation model doesn't constrain traffic by host role or user persona.

## Solution

A data-driven traffic profile system using two complementary layers defined in a single YAML file (`config/activity/traffic_profiles.yaml`):

- **role_traffic**: System-level connections that happen 24/7 based on the host's assigned role. A domain controller generates AD replication, DNS zone transfers, and CRL checks. A file server generates Kerberos to DC and Windows Update. These run regardless of who is logged in.

- **persona_traffic**: User-initiated connections layered on top during active sessions. A developer adds git/npm/SSH traffic. An executive adds email/calendar/web traffic. These are only generated during work hours when the user has an active session.

## Scope (Hybrid Approach)

The traffic profile system replaces simple port-to-service connection generation:
- Background HTTPS traffic (all systems uniform → role-specific)
- Database client traffic (uniform → role/persona-specific)
- ICMP monitoring pings (ad-hoc → role-specific)
- Process-correlated network connections (`_PROCESS_NETWORK_MAP` → persona_traffic)

It does NOT replace compound/specialized generators that need internal structure:
- 26 lateral movement patterns (bursty timing, multi-port, already role-gated)
- Periodic system traffic (DNS/NTP/SMB/Kerberos/LDAP phase-based timing)
- SSH/RDP sessions (compound events with process + syslog + auth)
- IDS alerts, web access logs, suspicious noise patterns

## Data Model

See `src/evidenceforge/config/activity/traffic_profiles.yaml` for the full schema and profiles.

## Generation Flow

### Per hour, per host — outbound system traffic:
1. Look up the host's canonical roles (compiled from `system.roles`, `system.type`, `services`, hostname)
2. Load matching `role_traffic.outbound` profile, filter by OS
3. Generate N connections (scaled by time-of-day), weighted-sampled from profile
4. Resolve `role` to a concrete destination IP (excluding self)

### Per hour, per host — inbound traffic:
1. Load matching `role_traffic.inbound` profile for the host's canonical roles
2. Generate M inbound connection attempts, weighted-sampled from profile
3. Resolve `role` to a concrete source IP (e.g., `_external` → random internet IP)
4. Connection flows through the existing visibility engine and firewall policy:
   - Permitted: produces Zeek conn/ssl/http on destination-side sensors + ASA Built
   - Denied: produces ASA Deny record + source-side sensor visibility only

### Per hour, per active user session — user traffic:
1. Look up the user's `persona`
2. Load matching `persona_traffic.outbound` profile (or `_default`), filter by OS
3. Generate M connections (scaled by Hawkes model + work hours), weighted-sampled
4. Resolve destinations same as role_traffic

### Role resolution (`role` to concrete IP):
- Named roles (`domain_controller`, `file_server`, etc.) → pick a system with that role
- `_external` → dns_registry domain-first selection or random external IP
- `_any_server` → any server-type system
- `_any` → any system in the scenario
- `_dc` → alias for domain_controller
- All lookups exclude the local host to prevent self-connections
