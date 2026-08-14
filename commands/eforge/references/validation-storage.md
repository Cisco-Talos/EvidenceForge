---
description: "Scenario validation and preview guidance for compiled SMB storage"
---

# Validation: SMB Storage

Read this reference only for `environment.storage`, `smb_activity`, implicit SMB defaults, or a
user-requested storage preview.

## Preview the compiled model

Use the same absolute input and project root as the primary validation run:

```bash
eforge validate <absolute-scenario-path> \
  --project-root <absolute-project-root> --show-storage --json
```

For a resolved document, omit the project root. Preview is read-only and does not generate logs or
write `STORAGE_MANIFEST.json`.

Storage can be generation-effective even when `environment.storage` is omitted: Windows file
servers receive deterministic portfolios and domain controllers receive SYSVOL/NETLOGON defaults.
Use the preview when those implicit defaults matter; do not add explicit storage solely to silence
their presence.

## Inspect only the failing area

Use structured storage diagnostics to inspect the implicated:

- volume mount, filesystem, label, and hosted-share count;
- share reference, UNC/server-local root, preset, population, activity, audit, and encryption;
- effective read/modify/admin/deny access;
- bounded catalog samples, path, size, MIME, and tags;
- mapping drive, lifecycle, user/group/system audience; or
- authored `smb_activity` share, mapping, selector, batch, path, and asserted outcome.

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

## Interpret resource output

The forecast separates final output from peak working disk. Peak working disk includes temporary
bounded Zeek sort runs. SMB estimates include compiled catalog metadata, retained mutations,
authored sessions/operations, and selected output families. Logical remote file sizes are metadata
and do not consume output disk unless artifact materialization is explicitly supported and enabled.

Resource warnings are advisory; path containment, regular-file, symlink, archive, include, and
composition safety failures remain blocking errors.
