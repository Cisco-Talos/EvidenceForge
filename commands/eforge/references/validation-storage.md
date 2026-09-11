---
description: "Scenario validation and preview guidance for compiled SMB storage"
---

# Validation: SMB Storage

Read this reference only for `environment.storage`, `smb_activity`, implicit SMB defaults, or a
user-requested storage preview.

## Preview the compiled model

Use the same absolute input and current working directory as the primary validation run:

```bash
eforge validate <absolute-scenario-path> \
  --show-storage --json
```

For a resolved document, omit the project root. Preview is read-only and does not generate logs or
write `STORAGE_MANIFEST.json`.

Storage can be generation-effective even when `environment.storage` is omitted: Windows file
servers receive deterministic portfolios and domain controllers receive SYSVOL/NETLOGON defaults.
Linux hosts require Samba service markers or explicit storage; a generic Linux `file_server`, mail
server, or application server does not imply Samba. Ordinary Samba servers never receive Windows
administrative or domain shares. Use preview when implicit defaults matter; do not add explicit
storage solely to silence their presence.

## Inspect only the failing area

Use structured storage diagnostics to inspect the implicated:

- volume platform, Windows/POSIX mount, backing filesystem, label, and hosted-share count;
- host file-set ID, system/root, exact preset, population, bounded samples, and optional share
  binding;
- share reference, provider/platform, network/server-native root, backing/advertised filesystem,
  preset, population, activity, audit, and encryption;
- effective read/modify/admin/deny access;
- bounded catalog samples, path, size, MIME, and tags;
- mapping drive/mount presentations, credential mode/principal, lifecycle, and audience; or
- authored `smb_activity` share, file set, exact-file `path`, destination `directory`, selector,
  batch, OS-native client location, access mode, authentication, SMB principal, and outcome.

Generated file and directory IDs are internal. Do not load or reproduce the entire catalog when a
single path or reference failed.

## Choose the owning repair

- Edit the declaring scenario/include only for scenario-owned storage or activity.
- A qualified preset or catalog error belongs to its industry or organization pack; route it to
  `/eforge pack` or the matching pack-authoring skill.
- Project config is not a place to patch public pack storage catalogs.
- Never edit a resolved document. Regenerate it from corrected authored input.
- Access, topology, target system, share selection, batch size, and asserted outcome changes are
  semantic choices unless the validator identifies exactly one existing valid reference.

Reject Windows/POSIX mount or client-path mismatches, incompatible mapping presentations,
case-insensitive mapping collisions, fixed/per-user credential contradictions, and copy/move legs
without a presentation for each modeled client. Batched client sources require a declared host file
set; batched destinations use `directory` rather than an exact-file `path`; and one action cannot
select more than 64 operations. A share `backing_file_set` must use the same system and exact
server-local root, and cannot redeclare preset/population/seed files. `source_path` and
`destination_path` are
transfer-mode profile operands: `operand_mode: transfer` requires both; ordinary operations do not.

## Interpret resource output

The forecast separates final output from peak working disk. Peak working disk includes temporary
bounded Zeek sort runs. SMB estimates include compiled catalog metadata, retained mutations,
authored sessions/operations, and selected output families. Logical remote file sizes are metadata
and do not consume output disk unless artifact materialization is explicitly supported and enabled.

Resource warnings are advisory; path containment, regular-file, symlink, archive, include, and
composition safety failures remain blocking errors.
