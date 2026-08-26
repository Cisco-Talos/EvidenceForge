---
description: "SMB storage topology and typed smb_activity authoring"
---

# Scenario SMB

**Contents:** host file sets and storage topology · Windows and Samba capability · exact
`smb_activity` fields · share/client locations · mappings, credentials, validation, and presentation

Use `environment.storage` when the exercise needs named Windows or Samba volumes, mount diversity,
explicit shares, access controls, mappings, or authored seed files. Omit it when deterministic
Windows file-server and SYSVOL/NETLOGON defaults are sufficient. Inspect effective storage with:

```bash
eforge validate <scenario> --show-storage --json
```

Minimal explicit server shape, nested under `environment`:

```yaml
storage:
  population: auto
  activity: normal
  servers:
    - system: FS-01
      presets: [collaboration]
      audit: standard
      default_volume: data
      volumes:
        - id: data
          mount: 'D:\'
          filesystem: ntfs
          label: SharedData
      shares:
        - id: finance
          name: Finance
          volume: data
          root: Departments\Finance
          preset: department
          access:
            read: [Finance-Readers]
            modify: [Finance-Users]
            admin: [Domain Admins]
```

In this example, `FS-01` is a modeled Windows file server; referenced access groups must exist.
Linux Samba servers instead use absolute POSIX mounts with `ext4` or `xfs`; the default is `/srv/samba` on
ext4. A Samba share may set `smb_native_filesystem` independently of its backing filesystem; the
wire default is `NTFS`. Ordinary Samba servers never receive C$, ADMIN$, SYSVOL, or NETLOGON.
The advertised label follows Samba's version-sensitive
[`fstype` contract](https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html).

The `storage` object supports exactly `population: auto|small|medium|large` (default auto),
`activity: low|normal|high` (default normal), `file_sets`, `servers`, and `mappings` (each default
`[]`). A file set models persistent files on any Windows or Linux host without granting that host
SMB server capability:

```yaml
storage:
  file_sets:
    - id: analyst-documents
      system: WS-01
      root: 'C:\Users\analyst'
      preset: homes
      population: small
      seed_files:
        - ref: quarterly-plan
          path: 'Documents\Quarterly Plan.docx'
          size_bytes: 284672
          tags: [planning, office]
```

A file set requires a unique `id`, modeled `system`, platform-native absolute `root`, one exact
built-in or selected-pack storage-catalog `preset`, optional `population`, and optional
`seed_files`. The preset provides a bounded realistic population; seed files add exact
story-relevant names and selection refs without replacing that population. A file set is local
storage only. It does not declare a share, listener, service, or network exposure.

A server supports required `system`, optional unique `presets` from `collaboration`, `homes`,
`software`, `backup`, and `dc_policy`; `audit: minimal|standard|high` (default standard), optional
`default_volume`, optional nonempty `volumes`, `shares` (default `[]`), and `share_overrides`
(default `[]`). Multiple volumes require `default_volume`.

A volume has required `id` and absolute `mount`, `filesystem: ntfs|refs|ext4|xfs` (default ntfs),
and optional `label`. A share has required `id`, `name`, and `volume`; plus `root` (default empty),
`preset` (default collaboration), optional `population`/`activity`, `encryption:
not_required|required`, optional `smb_native_filesystem`, optional `access`, `seed_files`, and
optional `backing_file_set`.
Access lists are `read`, `modify`, `admin`, and `deny`, each defaulting to `[]`. Seed-file fields
are required `ref`, relative `path`, and nonnegative `size_bytes`, plus `tags` (default `[]`).

A share override requires `share` plus at least one of `population`, `activity`, `encryption`,
`smb_native_filesystem`, `access`, or nonempty `seed_files`. A mapping supports required `id` and
`share`; `audience`, optional `drive` (`D:`–`Z:`), optional absolute POSIX `mount`,
`credential_mode: per_user|fixed`, optional `principal`, and `lifecycle: persistent|on_demand`.
Fixed credentials require a principal; per-user credentials forbid one.

Linux `samba`, `smbd`, or `smb_server` services imply server capability, as does explicit storage
configuration. A generic Linux `file_server`, mail server, or application server does not. Linux
client capability requires `cifs-utils`, `cifs-client`, or `smbclient`; OS identity alone is not
enough. GVFS remains transport/process background texture rather than typed SMB activity.

Use typed `smb_activity` for browse, read, create, update, copy, move, and delete semantics. Its
`operation` is required. A successful generic TCP/445 `connection` is transport only; it does not
imply authentication, a share, a file, object auditing, or mutation.

## `smb_activity`

Fields: `type`, required `operation`, `purpose`, `target`, `source`, `destination`, `batch`,
`outcome`, `path_style`, `mapping`, `client`, `client_access`, `auth_protocol`, `smb_principal`,
`ids_alerts`, `technique`, and `description`.

`purpose` is `auto` (default), `interactive`, `administrative`, `software`, `backup`, `collection`,
or `ransomware`. `outcome` is `auto` (default), `success`, `access_denied`, `not_found`, or
`sharing_violation`; `path_style` is `auto`, `unc`, `mapped`, or `mounted`.

For browse/read/create/update/delete, provide `target`. For copy/move, provide `source` and
`destination` and no target; at least one endpoint must be a share location. Use exact selectors,
batches, outcomes, and path-style fields from the schema. Model external clients explicitly rather
than inventing a victim system.

| Intent | Source | Destination | Batch rule |
| --- | --- | --- | --- |
| share read/update/delete | share `target` | — | selector or exact file; optional bounded batch |
| client upload | client exact `path` or `file_set` | share exact `path` or `directory` | batch requires `file_set` and destination `directory` |
| client download | share | client exact `path` or `directory` | batch requires destination `directory` |
| share-to-share copy/move | share | share exact `path` or `directory` | batch requires destination `directory` |

`path` always means one exact file. `directory` always means a copy/move destination container.
It is relative and SMB-canonical for a share, and platform-native absolute for a client. Do not use
a trailing slash on `path` to imply a directory.

A share location has `type: share`, required `share`, and at most one of `file_ref`, `path`,
`directory`, or `selector`. `share` must be the exact case-insensitive compiled
`<system>.<share-id>` reference,
for example `FS-01.finance` or `FS-01.c_admin`. Never use the bare share `id` or display name.
Validate with `--show-storage` and copy the exact `ref` from the effective storage preview:

```yaml
target:
  type: share
  share: FS-01.finance
  path: reports\quarterly.xlsx
```

A selector may use `path_glob`, unique `extensions`, `tags_any`, `min_size_bytes`, and
`max_size_bytes`, and must set at least one criterion. A client location has `type: client` and may
use one standalone absolute OS-native `path`, a destination `directory`, or a `file_set` narrowed
by one `file_ref` or `selector`. A file set alone selects its compiled catalog. An external client
has `type: external`, required `ip`, and optional bare `hostname`.

A `batch` selects exactly one of positive `count`, `fraction` in `(0, 1]`, or `all: true`, with
optional positive `duration`. Copy/move destinations cannot use a selector or file reference, and
batched destinations cannot name one explicit file. Runtime selection is capped at 64 operations.

Client upload preserving the selected paths below one server directory:

```yaml
type: smb_activity
operation: copy
purpose: collection
source:
  type: client
  file_set: analyst-documents
  selector: {extensions: [.docx, .pdf]}
destination:
  type: share
  share: FS-01.staging
  directory: WS-01
batch: {count: 12, duration: 30s}
```

Client download into one local directory:

```yaml
type: smb_activity
operation: copy
source:
  type: share
  share: FS-01.finance
  selector: {path_glob: 'Reports\**\*.xlsx'}
destination:
  type: client
  directory: 'C:\Users\analyst\Downloads'
batch: {count: 8, duration: 20s}
```

An exported share can alias the same canonical file objects instead of compiling a parallel
catalog. The file set and share must name the same system, and the share's compiled server-local
root must exactly equal the file-set root:

```yaml
storage:
  file_sets:
    - id: published-documents
      system: FS-01
      root: 'D:\Published'
      preset: department
      population: small
  servers:
    - system: FS-01
      presets: []
      volumes: [{id: data, mount: 'D:\', filesystem: ntfs}]
      shares:
        - id: published
          name: Published
          volume: data
          root: Published
          backing_file_set: published-documents
```

A backed share cannot also declare `preset`, `population`, or `seed_files`; the file set owns the
catalog. Local and share mutations then address the same canonical file objects. SMB client/server
roles are connection-relative: a workstation may upload files without being a server, and a host
may be a client, server, or both. Only a declared share exposes files over SMB.

Keep one case-insensitive, share-relative namespace using `\` separators, distinct from Windows
UNC/drive presentation, Linux mount or `smbclient` presentation, and Windows/POSIX server-local
paths. A `type: client` location uses a drive-absolute Windows `path` or POSIX-absolute Linux path,
validated against the initiating OS.

Mappings may carry a Windows `drive`, a Linux `mount`, or both for a mixed audience. Automatic
allocation uses `H:` through `Z:` or `/mnt/<mapping-id>`. `credential_mode: per_user` uses the
activity SMB principal; `fixed` requires a declared `principal`. A fixed credential is separate
from the local application actor and Samba's effective UID/GID.

`client_access` is `auto`, `windows_native`, `cifs_mount`, or `smbclient`; `auth_protocol` is
`auto`, `kerberos`, or `ntlmssp`; optional `smb_principal` overrides the credential identity.
Mounted CIFS requires a compatible mount and `path_style: mounted`; direct `smbclient` is one-shot
and uses the share presentation. External clients require automatic access, cannot select a local
mapping, and produce no client-host telemetry. Access outcomes must agree with platform, mapping,
credential, path, and effective storage policy.
These mount and credential-ownership rules follow the upstream
[`mount.cifs` contract](https://man7.org/linux/man-pages/man8/mount.cifs.8.html).

Validate storage after composition. In a pack-backed scenario, inspect resolved storage and field
origins before adding scenario-local overrides. Keep reusable storage vocabulary or organization
modeling in its owning pack rather than copying it into one storyline.
