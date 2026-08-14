---
description: "SMB storage topology and typed smb_activity authoring"
---

# Scenario SMB

Use `environment.storage` when the exercise needs named Windows or Samba volumes, mount diversity,
explicit shares, access controls, mappings, or authored seed files. Omit it when deterministic
Windows file-server and SYSVOL/NETLOGON defaults are sufficient. Inspect effective storage with:

```bash
eforge validate <scenario> --project-root <absolute-project-root> --show-storage --json
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

Linux `samba`, `smbd`, or `smb_server` services imply server capability, as does explicit storage
configuration. A generic Linux `file_server`, mail server, or application server does not. Linux
client capability requires `cifs-utils`, `cifs-client`, or `smbclient`; OS identity alone is not
enough. GVFS remains transport/process background texture rather than typed SMB activity.

Use typed `smb_activity` for browse, read, create, update, copy, move, and delete semantics. Its
`operation` is required. A successful generic TCP/445 `connection` is transport only; it does not
imply authentication, a share, a file, object auditing, or mutation.

For browse/read/create/update/delete, provide `target`. For copy/move, provide `source` and
`destination` and no target; at least one endpoint must be a share location. Use exact selectors,
batches, outcomes, and path-style fields from the schema. Model external clients explicitly rather
than inventing a victim system.

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
