# DNS, network, web, and identity overlays

Read the requested family and inspect its packaged file and project overlay before editing.
The live schema remains authoritative.

## DNS and traffic

### `dns_registry.yaml`

Owns reusable domain/IP identity and tag selection:

```yaml
valid_tags:
  healthcare: Healthcare services
domains:
  - domain: portal.example.test
    ips: [198.51.100.20]
    tags: [web, healthcare]
```

Query `eforge info dns_tags` for current tags. Entries merge by `domain`; lists append unless that
entry uses `_replace: true`. Preserve `long_tail`, `ipv6_map`, and `ipv6_prefixes` shapes. Public CDN
ownership belongs to `public_identity_profiles.yaml`. Use `environment.network_identities` for one
scenario's domains; prefer reserved, behavior-shaped identities over real malicious IOCs.

### `traffic_profiles.yaml`

`role_traffic` and `persona_traffic` deep-merge. Select exact domains or existing `dns_tags`.
Match the default persona shape: mapping with inbound/outbound branches or supported list.

`traffic_rates.yaml` owns intensity counts/ranges. `network_params.yaml` owns OUI, external-client
exclusions, Linux SMB owners, DNS-tunnel timing/answers, scanner mixes and proxy status messages.
Deep-merged `http_transport_floor_slack` freezes short-HTTP close median/sigma/minimum/maximum ms
and admission maximum; absent frozen policy retains legacy parameters. Public DNS/NTP belongs to
the public identity registry; scenario-defined internal infrastructure belongs in the scenario.
`transport_histories`/`ssl_histories` replace selected profile lists: positive integer weights, native history strings, plus transport state.
Once-only conn classes occur once/direction regardless of packet counts. Passive TLS uses client uppercase/server lowercase; encrypted/post-detection content stays unknown.

`public_dns_profiles.yaml` owns NS/SOA/MX/AAAA answers and `generic_aaaa_probability`, not
the canonical domain/IP registry. Profile lists merge by `name`.

## Beacon and storage profiles

### `beacon_profiles.yaml`

`profiles` deep-merges by name: user-agent pool, weighted HTTP sequence, method, URI template,
byte ranges, optional DNS. Preserve safe placeholders and scenario-supplied reserved destinations;
profiles never authorize callbacks or select destinations alone.

`network_params.yaml.rdp_payload_bounds` declares positive, ordered initiator/responder payload
minima/maxima for initial, reconnect and compatibility RDP transports. Logical byte quotas cover
that support through the existing operation allowance, not a small first random draw; physical
counters, cumulative operation checks and lifecycle limits remain enforced. Absent frozen policy
retains historical 50k–500k/100k–2M draws with repaired logical provisioning. Reject malformed
present values; partial overlays preserve unspecified bounds.

### `storage_catalog.yaml`

`population_counts` and named `profiles` deep-merge portable directory/subject vocabulary and
weighted extension/MIME pairs, not servers/shares/users/access policy. Components must be relative,
traversal-free and MIME-consistent. Put vocabulary reusable across projects/industries in a pack.

Engine-owned `file_size_policy.profiles` maps names to positive, ordered
`minimum_bytes`/`maximum_bytes` supports for automatic metadata sizes. Route through
`preset_extension_profiles`, `extension_profiles`, `preset_profiles`, then `default_profile`;
extension keys are lowercase suffixes. Explicit seed sizes win; later SMB evolution is separate.
Absent frozen policy retains original sizing. Keep this root outside portable pack vocabulary.

Optional engine-owned `policy_repository` models Windows domain-policy metadata outside pack
vocabulary. Given an explicit environment domain, recognized Windows DC SYSVOL/NETLOGON shares
use bounded domain/GPO GUID paths and linked templates. `sysvol_root`/`netlogon_root` affect only
synthesized roots; explicit roots/seeds win. Templates require literal relative `path`, MIME,
positive ordered sizes and finite `presence_probability`; each GPO requires `GPT.INI`.
Bounds model supports, not empirical calibration. Missing/disabled policy preserves legacy paths
and RNG; malformed present policy rejects; partial overlays deep-merge. Custom shares, file sets,
domain-unknown environments and Samba members retain existing behavior. Initial paths/size/MIME
add no filesystem aliases or live AD/DFSR replication/mutation. Cap catalogs at finite realizable
space and record requested/effective counts in the storage manifest.

## Proxy, web, and HTTP

`proxy_uri_templates.yaml` roots: `default_http_policy`, `domains`, `tags`, `generic`, `search_terms`.
Domain/tag templates own
URI, method, content type, domain class and referrer behavior; they do not make domains browsable.

### `site_maps.yaml`

Roots: `search_terms`, `domains`, `tags` (not `tag_templates`), `generic`. Deep-merged domain entries
own pages, navigation, CDN hosts and subresources; tag/generic tiers are fallbacks. Do not fabricate
`/about`, `/login`, `/api/v1` or assets as repairs. Ask for intended routes; absence may be intentional.

### `web_session_profiles.yaml` and `web_scan_presets.yaml`

Deep-merge `web_session_profiles.yaml` visitor classes/User-Agents. Replace each named
`web_scan_presets.yaml` preset as a unit; copy it fully before editing. IDS entries need positive
valid SIDs/messages and share global signature identities.

### `proxy_user_agents.yaml` and `proxy_phase_profiles.yaml`

User-Agent roots (`domain_overrides`, `workstation`, `server`) deep-merge. Keep OS/package-manager
identities coherent. Proxy phase profiles own resolver mixture and phase timing, not source-level
observation delay; millisecond ranges must be non-negative, ordered, and bounded.

### `http_file_profiles.yaml`

Deep-merge `extension_mime_types` (lowercase `.ext` → valid MIME), `request_profiles` (request MIME
defaults/nonempty URI tokens), and `multipart` (browser/curl/generic boundaries, supported header
order, bounded part/depth/file/quoted-printable limits). Multipart limits affect serializer safety
and Zeek caps; copy the packaged subtree, change only the intended leaf, and validate.

## TLS and public infrastructure

- `tls_issuers.yaml`: issuers merge by `name`; domain overrides must reference an issuer.
- `tls_realism.yaml`: deep-merges SAN, serial-number, OCSP, chain, and destination profiles. OCSP
  responder hosts also need DNS identity. Preserve issuer/key/signature compatibility.
- `public_identity_profiles.yaml`: provider-owned public IP, forward/PTR, TLS, and client traits for
  scanners, external/failed logons, C2, human/crawler/API clients, ordinary responders, CDN, DNS,
  NTP, and mail.
- `network_params.yaml`: scanner protocol mixes and network timing; not public identity ownership or
  canonical scenario infrastructure.
  Optional `tls_detection_phase` models one physical first-TLS delay before sensor clocks:
  `minimum_ms < median_ms < maximum_ms`, positive finite `sigma`. Partial overlays retain defaults;
  physical close/HTTP bounds win; children reuse the transport phase. Absent frozen policy retains
  legacy no-phase behavior; malformed/null present policy fails. These are modeled supports,
  not measured network calibration.

## Generated identity pools

`eforge info identity_pools` reports these realism-sensitive fallbacks:

| File | Purpose and key |
|---|---|
| `public_identity_profiles.yaml` | Canonical providers and roles keyed by `id`, with fixed identities, public address ranges, DNS/PTR, TLS, and client traits. |
| `email_background.yaml` | Weighted `external_domains` (`domain`) and inbound/outbound local parts (`local_part`). |
| `suspicious_benign.yaml` | Benign-but-suspicious DNS and connection hosts, keyed by `hostname`. |
| `command_parameter_pools.yaml` | Deep-merged command URL/host substitution pools. |

Use reserved/documentation identities as safety policy requires; avoid contradictory public
client/hostile/service roles. Scenario identities win. Deprecated inputs/migration belong only
in the project migration guide.

## Repair decisions

- Adding a domain alone does not directly imply a proxy template, site map, traffic selector, TLS
  profile, or public DNS profile. Ask which behaviors the user wants.
- If the user explicitly names tags or an exact selector, adding those references is directly
  implied; apply and report.
- A validation `INFO` about missing optional web/proxy richness is advisory, not permission to invent
  content.
- Validate all changes with `eforge validate-config --json` in a fresh process.
