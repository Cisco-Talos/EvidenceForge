# Canonical storage purpose/type size policy

Classification: family_level; finding new_family/distribution_texture. Prior
panel7 found15/51size-bearing policy observations above1MiB; root dedup confirms
14/48distinctUNCpath-sizeversions, not independent GPO objects. Explicit large
scripts/preferences remain possible. The defect is automatic metadata population
using a generic broad document range irrespective of purpose/type.

Owner: _StorageWorldCompiler, specifically _compile_catalog/_file_size, and
engine-owned root configuration in activity/storage_catalog.yaml. The compiled
StorageWorldModel consumes the resulting immutable metadata; it does NOT own the
numeric sampler. Initial prototype mistakenly patched that consumer and was
corrected; actual prototype passes65checks with8748compiler sampler calls.

Invariant: choose one automatic size from effective purpose/type policy before
compiling file metadata, then reuse it for every source, transfer and version.
Explicit seed sizes are authoritative even above automatic bounds; runtime
mutations/partial-read/transfer sizes remain distinct. Do not truncate one emitter
or rewrite canonical accounting. Preserve scoped catalog RNG identity and one
existing log-byte-range draw per automatic file.

Configuration: add optional engine ROOT file_size_policy to the existing cached
storage_catalog.yaml, separate from strict portable profiles vocabulary. Route
preset+extension, then extension, then preset, then default; validate positive
ordered integer supports and all references/normalized suffix keys. Parse the
policy once per _StorageWorldCompiler instance before _compile, using the existing
registered _load_catalog_config LRU. No new global cache/trust exception. If root
key is absent in historical frozen configuration, retain exact legacy numeric
bounds/RNG behavior; a present malformed/null policy rejects. Do not read new
package defaults outside an old immutable configuration snapshot. Current default
engine policy composes independently of immutable pack profile data.

Entry inventory: _compile_catalog generated loop and finite-candidate fallback;
SMB DC/user/home/department/software/backup/custom profiles; host file sets and
share catalogs; explicit seeds. File mutations and authored/runtime content retain
their own owners. Config roots/overlays/frozen resolution must retain precedence.
No scenario, industry or organization pack bytes change.

Consumers: CompiledStorageFile/FileContext and content identity, STORAGE_MANIFEST,
SMB directory/open/read/write/close offsets and transfer lifetimes, Zeek SMB/files,
Samba/Windows client/server file audit, eCAR/native file operations, deterministic
checkpoint/replay and evaluation. Shared metadata owns truth before all views.

Sibling verification: policy INI/XML/POL versus ordinary docs, script in software,
text log versus archive in backup, case-insensitive extensions, unknown custom
fallback, explicit oversized seed bypass, stable canonical IDs and repeat compile,
malformed config/overlay routing, exact legacy absent-policy draws, SMB/native/
partial-transfer/accounting and checkpoint siblings. Bounds are modeled automatic
population support, not empirical calibration or a claim of native file limits.

Residual risk: full GPO hierarchy/replication/content semantics are separate and
unproven here. A smaller canonical file population can change admitted transfer
work and visible row counts; retain actual evaluation and blind scores without
cherry-picking. Explicit large files must remain representable. No new raw temporal
RNG or inventory ceiling relaxation is permitted.
