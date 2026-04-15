# Customizing EvidenceForge Configuration

EvidenceForge ships with 50+ YAML configuration files that control every aspect of realistic log generation — DNS domains, applications, personas, traffic profiles, spawn rules, and more. You can customize these to match your scenario's environment without modifying the installed package.

## The Overlay System

EvidenceForge uses a **project-local overlay** at `.eforge/config/` in your working directory. Overlay files contain only your additions or changes — the engine merges them with package defaults at load time.

```
your-project/
├── .eforge/config/              ← Your customizations (survives package upgrades)
│   ├── activity/
│   │   └── dns_registry.yaml    ← Only your new domains
│   └── personas/
│       └── nurse.yaml           ← A custom persona
├── scenarios/
│   └── hospital-breach/
│       └── scenario.yaml
```

**How merging works:**
- New entries (new domain, new app, new persona) are appended to package defaults
- Entries matching an existing key (same domain name, same app ID) are merged field-by-field — list fields are extended (appended), scalar fields are replaced, unmentioned fields are preserved
- Add `_replace: true` to an overlay entry to switch list fields from extend to replace (e.g., to retag a domain instead of adding a tag)
- Package defaults you don't override pass through unchanged

Your overlay is never touched by package upgrades. Run `eforge info overlay.exists` to check if you have one.

## Recommended: Use `/eforge:config`

The easiest way to customize configuration is through the Claude Code skill:

```
/eforge:config add a new persona called nurse for a healthcare scenario
```

```
/eforge:config add notion.so to the DNS registry as a SaaS domain
```

```
/eforge:config add Slack as a desktop application for developers and analysts
```

```
/eforge:config validate my config files
```

The skill automatically:
- Creates the overlay directory if it doesn't exist
- Writes partial overlay files with only your changes
- Handles cross-file dependencies (adding a domain also sets up proxy templates, site maps, etc.)
- Verifies consistency and auto-fixes simple issues

**Tip:** Always use `/eforge:config` explicitly — the skill may not auto-trigger on short prompts like "add a persona."

## Inspecting Current Configuration

The `eforge info` command shows what's configured, including overlay customizations:

```bash
# See everything
eforge info

# Query specific fields
eforge info personas          # List all persona names (package + overlay)
eforge info dns_tags          # List all DNS tags in use
eforge info application_ids   # List all application IDs
eforge info overlay.exists    # Check if an overlay is active
eforge info overlay.files     # List files in the overlay
eforge info paths.activity    # Path to the activity config directory

# Discover all available fields
eforge info --fields

# Machine-readable output
eforge info --json
```

## Manual Editing

If you prefer to edit YAML files directly instead of using the skill:

### 1. Create the overlay directory

```bash
mkdir -p .eforge/config/activity .eforge/config/personas
```

### 2. Add a custom persona

Create `.eforge/config/personas/nurse.yaml`:

```yaml
name: nurse
description: "Clinical nurse who uses EHR and basic web browsing"
typical_activities:
  - "Access electronic health records"
  - "Review patient charts"
  - "Browse medical reference sites"
work_hours: "7am-7pm (lunch 12pm-1pm)"
application_usage:
  - "Chrome"
  - "EHR Client"
risk_profile: "low"
browsing_intensity: "light"
```

All fields are required. Valid `risk_profile`: low, medium, high. Valid `browsing_intensity`: light, normal, heavy.

### 3. Add a custom domain

Create `.eforge/config/activity/dns_registry.yaml`:

```yaml
domains:
  - domain: ehr.meridianhealth.local
    ips: ["10.50.1.100"]
    tags: [internal]
```

Valid tags: `web`, `saas`, `cdn`, `email`, `git`, `background`, `windows`, `linux`, `internal`, `storage`, `dev`, `social`.

### 4. Add a persona to existing applications

Create `.eforge/config/activity/application_catalog.yaml`:

```yaml
applications:
  - id: chrome
    personas: [nurse]
  - id: outlook
    personas: [nurse]
```

This is a **partial overlay** — it adds `nurse` to Chrome's and Outlook's persona lists without replacing any other fields. The engine merges these with the package defaults.

### 5. Verify

```bash
eforge info personas    # Should include "nurse"
eforge info dns_tags    # Should include your new tags

# Run full validation (27 cross-reference checks)
eforge validate-config
```

## Cross-File Dependencies

Configuration files are interconnected. When you add an entry to one file, other files may need updates:

| When you add... | Also update... |
|----------------|----------------|
| A new domain | `proxy_uri_templates.yaml` (URI paths), `site_maps.yaml` (browsing depth) |
| A new application | `spawn_rules.yaml` (process tree), `process_network_map.yaml` (if it generates traffic) |
| A new persona | `application_catalog.yaml` (add persona to relevant apps' `personas:` lists) |

The `/eforge:config` skill handles these dependencies automatically. If editing manually, run `/eforge:config validate my config files` to check for missing cross-references.

## Reference Documentation

For full field schemas and conventions, see the reference docs installed with the skills:

| Topic | Skill Reference |
|-------|----------------|
| DNS, traffic, proxy, site maps | `/eforge:references:config-dns-network` |
| Applications, spawn rules, processes | `/eforge:references:config-apps-processes` |
| Persona file structure | `/eforge:references:config-personas` |
| Host activity (bash, systemd, syslog) | `/eforge:references:config-host-activity` |
| Cross-file dependency map | `/eforge:references:config-dependency-graph` |
| Validation checks (27) | `/eforge:references:config-validation` |
