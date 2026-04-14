# DNS & Network Configuration Reference

Schema documentation for the network-related config files. User customizations go in the project-local overlay at `.eforge/config/activity/` — partial files that merge with package defaults. See `config-dependency-graph.md` for details.

## Table of Contents

1. [dns_registry.yaml](#dns_registryyaml)
2. [traffic_profiles.yaml](#traffic_profilesyaml)
3. [proxy_uri_templates.yaml](#proxy_uri_templatesyaml)
4. [site_maps.yaml](#site_mapsyaml)
5. [network_params.yaml](#network_paramsyaml)
6. [tls_issuers.yaml](#tls_issuersyaml)

---

## dns_registry.yaml

Single source of truth for all domain-to-IP mappings. The loader builds `FORWARD_DNS`, `REVERSE_DNS`, and tag-based lookup tables from this data.

### Structure

```yaml
domains:
  # === Provider Name ===
  - domain: www.example.com        # FQDN (required)
    ips: ["93.184.216.34"]         # List of 1-3 IPs (required, non-empty)
    tags: [web]                     # List of tags (required, non-empty)
```

### Field Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `domain` | string | yes | Fully qualified domain name |
| `ips` | list[string] | yes | 1-3 realistic IP addresses. CDN/cloud domains typically have 2. |
| `tags` | list[string] | yes | One or more tags from the valid set (see below) |

### Valid Tags

| Tag | Purpose | Used By |
|-----|---------|---------|
| `web` | General browsing targets | Persona browsing sessions |
| `saas` | SaaS application traffic | Persona SaaS interactions |
| `cdn` | CDN/API endpoints (not directly browsed) | Background requests, subresources |
| `email` | Email server connections | Email-related traffic |
| `git` | Source control services | Developer traffic |
| `background` | OS-level background HTTPS (updates, telemetry) | All hosts |
| `windows` | Windows-specific background traffic | Windows hosts only |
| `linux` | Linux-specific background traffic | Linux hosts only |
| `internal` | Internal infrastructure | Rarely used in dns_registry |
| `storage` | Cloud storage (exfiltration targets) | Scenario-dependent |
| `dev` | Developer tool API endpoints | Developer traffic |
| `social` | Social media sites | Marketing, sales, general browsing |

### Conventions

- Group entries by provider using `# === Provider Name ===` comment headers
- Use realistic IPs from the provider's actual ASN ranges (or plausible-looking ranges)
- CDN/cloud domains should have 2 IPs to simulate load balancing
- A domain can have multiple tags: `tags: [web, saas]`
- API/CDN subdomains should use `cdn` or `dev`, not `web` (prevents them from appearing as direct browsing targets)

### Complete Entry Example

```yaml
  # === Notion ===
  - domain: www.notion.so
    ips: ["104.18.12.166", "104.18.13.166"]
    tags: [web, saas]
  - domain: api.notion.com
    ips: ["104.18.14.166", "104.18.15.166"]
    tags: [dev]
```

### Common Mistakes

- Using `tags: [web]` for API endpoints (produces unrealistic browsing to API domains)
- Only providing 1 IP for cloud/CDN domains (less realistic)
- Forgetting to add corresponding proxy_uri_templates and site_maps entries for `web`/`saas` domains

---

## traffic_profiles.yaml

Defines role-based and persona-based network connection patterns. Two sections: `role_traffic` (system-level, 24/7) and `persona_traffic` (user-initiated, during work hours).

### Structure

```yaml
role_traffic:
  role_name:
    outbound:
      - {role: target, port: 443, proto: tcp, service: ssl, weight: 30, emit_dns: true, dns_tags: [web]}
    inbound:
      - {role: source, port: 443, proto: tcp, service: ssl, weight: 20}

persona_traffic:
  persona_name:
    outbound:
      - {role: _external, port: 443, service: ssl, weight: 50, emit_dns: true, dns_tags: [saas, web]}
```

### Connection Entry Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `role` | string | yes | — | Target/source role. Special values: `_external`, `_any_server`, `_any`, `_dc` |
| `port` | int | yes | — | Destination port (outbound) or listening port (inbound). Use `0` for ICMP. |
| `proto` | string | no | `tcp` | Protocol: `tcp`, `udp`, or `icmp` |
| `service` | string | no | — | Zeek service label (e.g., `ssl`, `http`, `dns`, `kerberos`, `smb`) |
| `weight` | int | yes | — | Relative frequency weight. Higher = more connections. |
| `os` | string | no | — | Restrict to hosts with this OS: `windows` or `linux` |
| `emit_dns` | bool | no | `false` | Emit a preceding DNS lookup for this connection |
| `dns_tags` | list[string] | no | `[background, <os>]` | Tags for domain selection when `role: _external`. Falls back to `[background, <source_os>]` if omitted. |
| `description` | string | no | — | Human-readable note (ignored by engine) |

### Special Role Values

| Value | Meaning |
|-------|---------|
| `_external` | Random external IP, resolved via dns_registry domain-first selection |
| `_any_server` | Any system with type `server` or `domain_controller` |
| `_any` | Any system in the scenario |
| `_dc` | Alias for `domain_controller` |
| Named roles | Specific system role (e.g., `database`, `file_server`, `web_server`) |

### Conventions

- Use compact flow-style YAML for connection entries: `{role: ..., port: ..., weight: ...}`
- Weights are relative within a role/persona — they don't need to sum to 100
- Always pair `emit_dns: true` with `dns_tags:` to control which domains get resolved
- Include `description:` for non-obvious connections

### Common Mistakes

- Omitting `dns_tags:` when using `emit_dns: true` (falls back to generic background traffic)
- Using a dns_tag that no domain in dns_registry has (silent — no domains match)
- Forgetting to add `persona_traffic:` entries for new personas (persona gets no custom traffic patterns)

---

## proxy_uri_templates.yaml

Per-domain and per-tag URI path templates for realistic proxy log generation. Lookup order: exact domain match -> tag-based fallback -> generic fallback.

### Structure

```yaml
domains:
  domain.example.com:
    user_agent: "Mozilla/5.0 ..."     # Optional, overrides default
    os: windows                        # Optional, restricts to OS
    paths:                             # Required, list of URI path templates
      - "/api/v2/endpoint/{guid}"
      - "/static/resource.js"
    content_type: "application/json"   # Optional, default varies
    methods: ["GET"]                   # Optional, default ["GET"]
```

### Field Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `user_agent` | string | no | Custom User-Agent header (overrides browser default) |
| `os` | string | no | Restrict to `windows` or `linux` |
| `paths` | list[string] | yes | URI path templates with optional `{placeholder}` variables |
| `content_type` | string | no | MIME type for responses |
| `methods` | list[string] | no | HTTP methods (default: `["GET"]`) |

### Template Variables

| Variable | Expands To |
|----------|------------|
| `{guid}` | Random UUID (e.g., `a1b2c3d4-e5f6-7890-abcd-ef1234567890`) |
| `{tenant_id}` | Random UUID for Azure AD tenant |
| `{hex8}` | 8-character hex string |
| `{hex16}` | 16-character hex string |

### Auto-Fix Stub Template

When the skill auto-generates a proxy_uri_templates entry for a new domain, use this pattern:

```yaml
  www.example.com:
    # TODO: Add domain-specific URI paths for realistic proxy logs
    paths:
      - "/"
      - "/api/v1/{guid}"
      - "/static/{hex8}.js"
      - "/assets/{hex8}.css"
    content_type: "text/html"
    methods: ["GET"]
```

---

## site_maps.yaml

Site map definitions for realistic browsing session generation. Three tiers of resolution.

### Tier 1: Curated Domains (exact match)

```yaml
domains:
  www.example.com:
    cdn_domains: ["cdn.example.com", "static.example.com"]  # CDN hosts for subresources
    pages:
      - path: "/dashboard"                                     # Page URL path
        nav_targets: ["/dashboard/reports", "/settings"]       # Pages user might click to next
        subresources:                                          # Resources loaded with the page
          - {host: "cdn.example.com", path: "/js/app.{hex8}.js", type: "application/javascript"}
          - {host: "cdn.example.com", path: "/css/main.{hex8}.css", type: "text/css"}
          - {path: "/api/dashboard/data", type: "application/json", method: "POST"}
```

### Tier 2: Tag-Based Synthesis

Templates applied to any domain matching a tag. Defined in the `tag_templates:` section. Lower fidelity than curated entries.

### Tier 3: Generic Fallback

Minimal single-page structure for domains with no curated or tag-based match.

### Subresource Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `host` | string | no | CDN hostname (omit for same-origin) |
| `path` | string | yes | URI path with optional template variables |
| `type` | string | yes | MIME type |
| `method` | string | no | HTTP method (default: `GET`) |

### Auto-Fix Stub Site Map

```yaml
  www.example.com:
    # TODO: Add realistic page hierarchy for browsing session depth
    cdn_domains: []
    pages:
      - path: "/"
        nav_targets: ["/about", "/login"]
        subresources:
          - {path: "/static/app.js", type: "application/javascript"}
          - {path: "/static/style.css", type: "text/css"}
```

---

## network_params.yaml

MAC OUI (vendor) prefixes with frequency weights for realistic DHCP and MAC address generation. Standalone — no cross-file dependencies.

### Structure

```yaml
oui_prefixes:
  - prefix: "D4:BE:D9"    # First 3 octets of MAC address
    vendor: "Dell"          # Hardware vendor name
    weight: 25              # Relative frequency weight
```

---

## tls_issuers.yaml

TLS certificate issuer configurations for realistic Zeek x509/SSL log generation. Standalone — no cross-file dependencies.

### Structure

```yaml
issuers:
  - name: "CN=R3, O=Let's Encrypt, C=US"   # Full issuer DN
    weight: 30                                # Relative frequency
    validity_days_min: 89                     # Minimum cert validity (days)
    validity_days_max: 90                     # Maximum cert validity (days)
    not_before_max_days: 60                   # Max days before scenario start for cert issuance
    key_types:
      - {type: "ecdsa", length: 256, weight: 70}
      - {type: "rsa", length: 2048, weight: 30}
```
