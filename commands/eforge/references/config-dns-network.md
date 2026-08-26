# DNS, network, web, and identity overlays

Read only the section matching the requested family. Always inspect the packaged file and existing
project overlay before editing; this reference gives ownership and guardrails, not a substitute for
the live schema.

## Contents

- [DNS and traffic](#dns-and-traffic)
- [Beacon and storage profiles](#beacon-and-storage-profiles)
- [Proxy, web, and HTTP](#proxy-web-and-http)
- [TLS and public infrastructure](#tls-and-public-infrastructure)
- [Generated identity pools](#generated-identity-pools)
- [Repair decisions](#repair-decisions)

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

Query `eforge info dns_tags` rather than copying a hardcoded tag list. Domain
entries merge by `domain`; lists append unless that keyed entry uses `_replace: true`. Other roots
include `long_tail`, `cdn_ranges`, `ipv6_map`, and `ipv6_prefixes`; preserve their packaged shapes.

Use `environment.network_identities` for a domain needed by one scenario. Do not add a real malicious
IOC when a reserved, behavior-shaped identity will satisfy the exercise.

### `traffic_profiles.yaml`

`role_traffic` and `persona_traffic` deep-merge. Connection entries can select exact domains or
`dns_tags`; every referenced tag must exist. A persona profile may be either the packaged mapping
shape with inbound/outbound branches or the supported list shape—match the surrounding default.

`traffic_rates.yaml` owns intensity-level count/range defaults. `network_params.yaml` owns OUI data,
public DNS/NTP fallback servers, external-client exclusions, Linux SMB connection owners, DNS-tunnel
timing/answers, scanner port mixes, and proxy status messages. Do not use it for scenario-defined
internal infrastructure.

### `public_dns_profiles.yaml`

Owns provider-style NS/SOA/MX/AAAA answer behavior and `generic_aaaa_probability`; it does not own
the canonical domain/IP registry. Profile lists merge by `name`.

## Beacon and storage profiles

### `beacon_profiles.yaml`

The `profiles` mapping deep-merges by profile name. A profile owns its user-agent pool and weighted
HTTP sequence, including method, URI template, byte ranges, and optional DNS behavior. Preserve the
documented safe template placeholders and use reserved destinations supplied by the scenario; a
profile never authorizes callbacks or selects a destination by itself.

### `storage_catalog.yaml`

`population_counts` and named `profiles` deep-merge. Profiles define portable directory/subject
vocabulary plus weighted extension/MIME pairs; they do not define concrete servers, shares, users,
or access policy. Keep component names relative and traversal-free, keep MIME consistent with the
extension, and use a pack instead when the vocabulary is reusable across projects or industries.

## Proxy, web, and HTTP

### `proxy_uri_templates.yaml`

Roots are `default_http_policy`, `domains`, `tags`, `generic`, and `search_terms`. Domain-specific
and tag templates control URI, method, content type, domain class, and referrer behavior. They do not
make a domain browsable by themselves.

### `site_maps.yaml`

Roots are `search_terms`, `domains`, `tags`, and `generic`—the tag root is `tags`, not
`tag_templates`. Curated domain entries define pages, navigation targets, CDN hosts, and
subresources; tag and generic tiers are fallbacks. Site maps deep-merge.

Do not fabricate `/about`, `/login`, `/api/v1`, or asset paths as an automatic repair. Ask for the
application's real or intended route shape. Absence can be intentional because generic fallback
exists.

### `web_session_profiles.yaml` and `web_scan_presets.yaml`

`web_session_profiles.yaml` deep-merges visitor classes and User-Agent pools. Each named preset in
`web_scan_presets.yaml` is replaced as a unit; copy the complete preset before changing it. Preset
IDS entries require valid positive SIDs and messages and share the global signature identity space.

### `proxy_user_agents.yaml` and `proxy_phase_profiles.yaml`

User-Agent roots (`domain_overrides`, `workstation`, `server`) deep-merge. Keep OS/package-manager
identities coherent. Proxy phase profiles own resolver mixture and phase timing, not source-level
observation delay; millisecond ranges must be non-negative, ordered, and bounded.

### `http_file_profiles.yaml`

Deep-merges three roots:

- `extension_mime_types`: lowercase `.ext` to valid MIME type.
- `request_profiles`: request MIME defaults and non-empty URI tokens.
- `multipart`: complete browser/curl/generic boundary morphology, supported header order, and bounded
  part/depth/file/quoted-printable limits.

Changing multipart limits affects serializer safety and Zeek projection caps; copy the packaged
subtree, change only the intended leaf, and validate.

## TLS and public infrastructure

- `tls_issuers.yaml`: issuers merge by `name`; domain overrides must reference an issuer.
- `tls_realism.yaml`: deep-merges SAN, serial-number, OCSP, chain, and destination profiles. OCSP
  responder hosts also need DNS identity. Preserve issuer/key/signature compatibility.
- `network_params.yaml`: fallback resolvers, NTP servers, scanner/network pools, and protocol timing;
  not canonical scenario infrastructure.

## Generated identity pools

`eforge info identity_pools` reports these realism-sensitive fallbacks:

| File | Purpose and key |
|---|---|
| `email_background.yaml` | Weighted `external_domains` (`domain`) and inbound/outbound local parts (`local_part`). |
| `mail_public_identities.yaml` | Reserved replacement domains and provider entries keyed by `name`. |
| `external_actor_profiles.yaml` | Weighted fallback public IPs for logon, failed-logon, and C2 roles, keyed by `ip`. |
| `suspicious_benign.yaml` | Benign-but-suspicious DNS and connection hosts, keyed by `hostname`. |
| `command_parameter_pools.yaml` | Deep-merged command URL/host substitution pools. |

Use reserved/documentation identities where required by safety policy. Do not reuse one public
identity for contradictory client, hostile, and service roles. Scenario-authored identities take
precedence over these fallbacks.

## Repair decisions

- Adding a domain alone does not directly imply a proxy template, site map, traffic selector, TLS
  profile, or public DNS profile. Ask which behaviors the user wants.
- If the user explicitly names tags or an exact selector, adding those references is directly
  implied; apply and report.
- A validation `INFO` about missing optional web/proxy richness is advisory, not permission to invent
  content.
- Validate all changes with `eforge validate-config --json` in a fresh process.
