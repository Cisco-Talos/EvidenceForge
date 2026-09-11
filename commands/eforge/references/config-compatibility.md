# Public identity configuration compatibility

Use this reference only when an existing project contains a legacy public-identity overlay. New
work must use `.eforge/config/activity/public_identity_profiles.yaml` and the canonical guidance in
`config-dns-network.md`.

## EvidenceForge 2.x bridge

Two user-owned filenames remain accepted during the 2.x line:

- `external_actor_profiles.yaml` translates weighted logon, failed-logon, and C2 addresses into
  canonical role patches.
- `mail_public_identities.yaml` translates replacement domains and mail providers into canonical
  provider and `mail` role patches.

EvidenceForge applies translated values first and the user's canonical
`public_identity_profiles.yaml` overlay afterward, so canonical values win conflicts. Generation
uses only the resulting canonical registry. The original project documents remain represented in
effective-config provenance and fingerprints, and translated bindings identify their source.

## Warning behavior and removal

Only `eforge validate` warns, and only when one of these user-owned files was actually consumed.
It emits one actionable warning per file naming the replacement and the EvidenceForge 3.0 removal
target. `generate`, `resolve`, `validate-config`, `info`, evaluation, pack, and checkpoint commands
stay silent. Packaged configuration and authoritative resolved scenarios do not warn.

Migrate each project before upgrading to 3.0. Preserve role separation unless infrastructure is
deliberately shared; use `share_with_roles` for that explicit exception. Run
`eforge validate-config --json`, then `eforge validate <scenario> --json` from the selected project
root. Do not suppress the validate warning as a permanent migration strategy.
