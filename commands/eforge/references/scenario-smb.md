---
description: "SMB storage topology and typed smb_activity authoring"
---

# Scenario SMB

Use `environment.storage` when the exercise needs named Windows volumes, mount diversity, explicit
shares, access controls, mappings, or authored seed files. Omit it when deterministic file-server
and SYSVOL/NETLOGON defaults are sufficient. Inspect effective storage with:

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

`FS-01` must be a modeled Windows file server and referenced access groups must exist.

Use typed `smb_activity` for browse, read, create, update, copy, move, and delete semantics. Its
`operation` is required. A successful generic TCP/445 `connection` is transport only; it does not
imply authentication, a share, a file, object auditing, or mutation.

For browse/read/create/update/delete, provide `target`. For copy/move, provide `source` and
`destination` and no target; at least one endpoint must be a share location. Use exact selectors,
batches, outcomes, and path-style fields from the schema. Model external clients explicitly rather
than inventing a victim system.

Mappings may use `D:` through `Z:`. `A:` and `B:` are reserved, `C:` is local, and an omitted drive
is allocated deterministically from `H:` through `Z:`. Access outcomes must agree with the
effective storage policy and selected identity.

Validate storage after composition. In a pack-backed scenario, inspect resolved storage and field
origins before adding scenario-local overrides. Keep reusable storage vocabulary or organization
modeling in its owning pack rather than copying it into one storyline.
