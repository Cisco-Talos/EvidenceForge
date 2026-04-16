# Applications & Processes Configuration Reference

> **This is a reference document for the /eforge:config skill.** If you are trying to add, modify, or remove config entries, invoke /eforge:config instead of using this reference directly. This file contains schema details that the config skill reads during execution.
>
> To discover config file paths, run `eforge info <field>` (e.g., `eforge info paths.activity`). Run `eforge info --fields` to see all available fields.

Schema documentation for application, process tree, and process-network mapping config files. User customizations go in the project-local overlay at `.eforge/config/activity/` — partial files that merge with package defaults. See `config-dependency-graph.md` for details.

## Table of Contents

1. [application_catalog.yaml](#application_catalogyaml)
2. [spawn_rules.yaml](#spawn_rulesyaml)
3. [process_network_map.yaml](#process_network_mapyaml)
4. [system_processes.yaml](#system_processesyaml)

---

## application_catalog.yaml

Unified application catalog for process generation. Consolidates image paths, PE metadata, command-line templates, and persona-based filtering into a single data source.

### Structure

```yaml
applications:
  - id: slack                                    # Unique lowercase identifier
    display_name: "Slack"                        # Human-readable name
    platforms:
      windows:
        image_path: 'C:\Users\{username}\AppData\Local\slack\app-4.38.0\slack.exe'
        pe_metadata:
          file_version: "4.38.125"
          description: "Slack"
          product: "Slack Desktop"
          company: "Slack Technologies, LLC"
          original_filename: "slack.exe"
        command_templates:
          - '"C:\Users\{username}\AppData\Local\slack\app-4.38.0\slack.exe" --process-start-args'
          - '"C:\Users\{username}\AppData\Local\slack\app-4.38.0\slack.exe" --type=renderer'
        children:                                # Optional: child processes this app spawns
          - '"C:\Users\{username}\AppData\Local\slack\app-4.38.0\slack.exe" --type=gpu-process'
      linux:
        image_path: "/usr/bin/slack"
        command_templates:
          - "slack --enable-features=WebRTCPipeWireCapturer"
    categories: [user_app]                       # Category tags
    personas: [developer, analyst, project_manager]  # Which personas spawn this app
```

### Top-Level Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | yes | Unique lowercase identifier (e.g., `slack`, `vscode`, `docker_desktop`) |
| `display_name` | string | yes | Human-readable application name |
| `platforms` | object | yes | Per-OS configuration (`windows` and/or `linux`) |
| `categories` | list[string] | yes | Category tags for persona process weight matching |
| `personas` | list[string] | yes | Which persona names may spawn this app. Include `default` for universal access. |

### Platform Fields (per OS)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `image_path` | string | yes | Fully qualified path to executable. No bare filenames. |
| `pe_metadata` | object | windows only | PE header fields for Windows process events |
| `command_templates` | list[string] | yes | Realistic command lines with `{placeholder}` support |
| `children` | list[string] | no | Command lines for child processes this app spawns |
| `loaded_modules` | list[object] | no | DLLs characteristically loaded by this application (Sysmon Event 7). See Loaded Module Fields below. |

### PE Metadata Fields (Windows only)

| Field | Type | Description |
|-------|------|-------------|
| `file_version` | string | PE file version (e.g., `"4.38.125"`) |
| `description` | string | PE file description |
| `product` | string | PE product name |
| `company` | string | PE company name |
| `original_filename` | string | PE original filename |

### Loaded Module Fields (Windows only)

DLLs characteristically loaded by this process, used for Sysmon Event 7 (ImageLoaded) generation. All fields except `path` have defaults — only specify what differs.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `path` | string | (required) | Full Windows path to the DLL (must contain `\`) |
| `signed` | bool | `true` | Whether the DLL is digitally signed |
| `signature` | string | `"Microsoft Windows"` | Signer name (e.g., `"Google LLC"`, `"Mozilla Corporation"`) |
| `signature_status` | string | `"Valid"` | One of: `Valid`, `Expired`, `Revoked`, `Unavailable` |

Every Windows process also receives the common OS loader DLLs (ntdll.dll, kernel32.dll, etc.) defined in `system_processes.yaml` under `common_loaded_modules.windows` — you don't need to repeat those in per-app profiles.

### Valid Categories

| Category | Meaning | Example Apps |
|----------|---------|-------------|
| `user_app` | General user application | Slack, Zoom, Notepad++ |
| `code` | Development tools | VS Code, IntelliJ, Sublime Text |
| `build` | Build/CI tools | Docker, npm, cargo |
| `query` | Data query tools | SQL clients, BI tools |
| `browser` | Web browsers | Chrome, Firefox, Edge |
| `office` | Office suite | Word, Excel, PowerPoint |

### Command Template Placeholders

| Placeholder | Expands To |
|------------|------------|
| `{username}` | Active user's username |
| `{internal_url}` | Random internal URL |
| `{small_int}` | Small random integer |
| `{guid}` | Random UUID |

### Conventions

- Windows paths must be fully qualified and single-quoted: `'C:\Program Files\...'`
- Group related apps with `# ===== Category =====` comment headers
- Always include `personas:` — apps without it are invisible to all users
- Use `default` in personas list for universal apps (everyone uses a browser)
- Command templates should be realistic — look at real process creation events for reference

### Overlay Examples

Overlay files go in `.eforge/config/activity/application_catalog.yaml`. They contain ONLY the entries you're adding or modifying — the engine merges them with package defaults.

**Add a persona to existing apps** (most common overlay use case). To add `nurse` to Chrome and Outlook, the overlay only needs the `id` and the fields being extended:

```yaml
applications:
  - id: chrome
    personas: [nurse]
  - id: outlook
    personas: [nurse]
```

The engine merges this with the package defaults: Chrome keeps all its existing fields (image_path, pe_metadata, command_templates, categories, etc.) and `nurse` is appended to its `personas` list. You do NOT need to copy the full entry.

**Replace an app's persona list entirely** (use `_replace: true`):

```yaml
applications:
  - id: chrome
    personas: [nurse, doctor]
    _replace: true
```

With `_replace: true`, Chrome's personas become exactly `[nurse, doctor]` — the default list is discarded. All other fields (image_path, etc.) are still preserved. Use this when you want to restrict an app to specific personas rather than add to the existing list.

**Add a completely new application:**

```yaml
applications:
  - id: ehr_client
    display_name: "EHR Client"
    platforms:
      windows:
        image_path: 'C:\Program Files\MeridianEHR\ehr.exe'
        pe_metadata:
          file_version: "3.2.1"
          description: "Meridian EHR Client"
          product: "Meridian EHR"
          company: "Meridian Healthcare Solutions"
          original_filename: "ehr.exe"
        command_templates:
          - '"C:\Program Files\MeridianEHR\ehr.exe" /login'
    categories: [user_app]
    personas: [nurse, doctor]
```

New entries (no matching `id` in defaults) are appended to the catalog as-is.

### Common Mistakes

- Bare filenames in `image_path` (e.g., `slack.exe` instead of full path)
- Missing `pe_metadata` for Windows apps (produces incomplete Sysmon events)
- Persona name typos (no validation error — app just never spawns for that persona)
- Forgetting to add the app to `spawn_rules.yaml` as a child of explorer.exe

---

## spawn_rules.yaml

Parent-to-child process spawning rules. The generator reverse-indexes this to find valid parents for any child process.

### Structure

```yaml
windows:
  parent_exe.exe:
    command_templates:                    # How the parent itself is launched
      - "C:\\Windows\\explorer.exe"
    lifetime: long                        # long (persists) or short (runs briefly)
    spawn_delay: [0.5, 3.0]             # Optional: [min_sec, max_sec] before spawning
    max_children: 5                      # Optional: cap on children (omit for unlimited)
    children:                            # Exe basenames this parent can spawn
      - child_app.exe
      - another_app.exe

linux:
  parent_process:
    command_templates:
      - "/usr/bin/parent"
    lifetime: long
    children:
      - child_process
```

### Field Reference

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `command_templates` | list[string] | yes | — | How this parent process is launched |
| `lifetime` | string | yes | — | `long` (persists for session) or `short` (runs briefly) |
| `spawn_delay` | list[float] | no | `[0.5, 3.0]` | [min, max] seconds before spawning children |
| `max_children` | int | no | unlimited | Cap on number of children spawned |
| `children` | list[string] | yes | — | Exe basenames that can be spawned |

### Conventions

- Use exe basenames only in `children:` (e.g., `chrome.exe`, not full path)
- Self-spawning apps (browsers, Electron apps) have themselves as both parent and child
- System services use `services.exe` or `svchost.exe` as parent
- User apps use `explorer.exe` as parent
- Windows entries are under `windows:`, Linux entries under `linux:`

### Common Parent-Child Patterns

| Parent | Typical Children | Why |
|--------|-----------------|-----|
| `explorer.exe` | All user apps (browsers, Office, IDEs, terminals) | Shell process spawns everything the user launches |
| `chrome.exe` | `chrome.exe` | Browser spawns renderer/GPU/utility subprocesses |
| `cmd.exe` | `powershell.exe`, `ping.exe`, `ipconfig.exe`, etc. | Command shell runs utilities |
| `powershell.exe` | `cmd.exe`, various tools | PowerShell launches processes |
| `services.exe` | `svchost.exe`, service executables | Service control manager |
| `bash` | `grep`, `awk`, `python3`, `ssh`, etc. | Shell spawns commands |

---

## process_network_map.yaml

Maps executables to the network services they generate. Used bidirectionally: exe-to-service (process initiated this connection) and service-to-exe (which process to attribute this connection to).

### Structure

```yaml
mappings:
  - exe: [chrome.exe, msedge.exe]    # List of exe basenames (case-sensitive)
    service: ssl                      # Zeek service label
    port: 443                         # Destination port
    external: true                    # true = external IPs, false = internal
```

### Field Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `exe` | list[string] | yes | Executable basenames (case-sensitive, as they appear in process events) |
| `service` | string | yes | Zeek service label (e.g., `ssl`, `http`, `dns`, `mssql`) |
| `port` | int | yes | Destination port |
| `external` | bool | yes | `true` if connection targets external IPs, `false` for internal |

### Conventions

- Group related executables in a single mapping entry
- Include both Windows (.exe) and Linux (no extension) variants where applicable
- Match exe names exactly as they appear in application_catalog image_path basenames

---

## system_processes.yaml

Baseline Windows system processes generated independently of user activity. Creates background process creation events for realism.

### Structure

```yaml
scheduled_tasks:
  - image: "C:\\Windows\\System32\\svchost.exe"     # Full image path
    command_templates:                                # Realistic command lines
      - "svchost.exe -k netsvcs -p -s {service}"
    params:                                           # Placeholder resolution
      service: [Schedule, BITS, wuauserv]
    parent: services                                  # Symbolic parent reference

system_services:
  all:                                                # Applies to all Windows hosts
    - image: "C:\\Windows\\System32\\WmiPrvSE.exe"
      command_templates:
        - "WmiPrvSE.exe -Embedding"
      parent: svchost_dcom
  domain_controller:                                  # Only on DCs
    - image: "C:\\Windows\\System32\\ntfrs.exe"
      command_templates:
        - "ntfrs"
      parent: services
```

### DLL Load Profile Sections

System processes also support DLL load profiles for Sysmon Event 7. Three locations:

1. **`common_loaded_modules.windows`** — OS loader chain (ntdll, kernel32, etc.) loaded by every Windows process. Applied automatically to all processes.
2. **`process_loaded_modules`** — Per-exe DLL profiles for processes not in system_services (e.g., explorer.exe, lsass.exe, powershell.exe). Keyed by exe basename.
3. **Inline `loaded_modules`** on system_services entries — DLLs specific to a service process (e.g., WmiPrvSE.exe loads fastprox.dll).

All use the same field schema as application catalog loaded_modules (see Loaded Module Fields above).

### Conventions

- `scheduled_tasks:` are periodic system tasks (update checks, maintenance)
- `system_services:` are role-filtered: `all` applies everywhere, named roles (e.g., `domain_controller`) restrict to that host role
- `parent:` uses symbolic names resolved at generation time (e.g., `services` = services.exe, `svchost_netsvcs` = svchost.exe -k netsvcs)
- `params:` provides lists of values for `{placeholder}` resolution in command_templates
- `loaded_modules:` optional list of DLLs loaded by this process (same schema as app catalog)
