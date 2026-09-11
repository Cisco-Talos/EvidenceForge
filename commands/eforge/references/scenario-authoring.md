---
description: "Compatibility index for the decomposed scenario-authoring references"
---

# Scenario Authoring Reference Index

Scenario authoring is split into conditional references so chat clients do not load one large
guide. `/eforge scenario` links every reference below directly and selects only those required by
the current task. Do not load this index plus every destination.

| Need | Direct reference |
|---|---|
| Authored versions, includes, safe create/update/repair | `/eforge:references:scenario-core` |
| Consume an existing industry or organization pack | `/eforge:references:scenario-pack-consumption` |
| Users, systems, topology, sensors, baseline, output | `/eforge:references:scenario-environment` |
| Users, systems, accounts, groups, and network identities | `/eforge:references:scenario-environment-identities` |
| Segments, sensors, firewall, NAT, and reachability | `/eforge:references:scenario-environment-network` |
| Exact deployment or observation overrides | `/eforge:references:scenario-environment-overrides` |
| Time, baseline shaping, observation profile, and output | `/eforge:references:scenario-baseline-output` |
| Storyline, red herrings, timing, typed-event ownership | `/eforge:references:scenario-storyline` |
| Endpoint, authentication, account, and raw event fields | `/eforge:references:scenario-events-endpoint` |
| Network, remote-session, DNS, scan, beacon, and IDS fields | `/eforge:references:scenario-events-network` |
| Email topology, messages, reads, and corpora | `/eforge:references:scenario-email` |
| HTTP, proxy, bodies, files, and multipart | `/eforge:references:scenario-http` |
| Windows/Linux storage, CIFS/`smbclient`, Samba, and typed SMB activity | `/eforge:references:scenario-smb` |
| Spillage, adversarial payloads, and encoded content | `/eforge:references:scenario-payloads` |
| Attack-free analyst briefing | `/eforge:references:scenario-briefing` |
| Windows Security and Sysmon evidence | `/eforge:references:evidence-windows` |
| Zeek, firewall, DHCP, DNS, TLS, and IDS | `/eforge:references:evidence-network-ids` |
| Web, proxy, HTTP-file, and email evidence | `/eforge:references:evidence-web-email` |
| eCAR, Linux syslog, and bash history | `/eforge:references:evidence-endpoint-linux` |
| Bundle layout, formats, and targets | `/eforge:references:generation-bundle-targets` |

Packs are optional. Default new authored documents to Scenario 2.0, including monolithic no-pack
work, and preserve existing Scenario 1.0 documents unless migration is requested. Generated
resolved scenarios and bundle sidecars are not editable authoring sources.
