# Pack inspect compatibility review

## Finding and cause

The released v2.1.2 `pack inspect <archive> [--json]` command calls `validate_efpack`.
Its successful JSON contains exactly `valid`, `root` and `members`. Invalid archives emit
`valid: false` plus `error` and exit 2. Human output reports a valid publisher/name or an error.
The archive filename need not end in `.efpack`, and read-only archive paths may be symlinks.
Archive members still undergo traversal, link, inventory, hash and dependency-graph checks.

Commit `46cccbd` (`feat: add portable artifact lifecycles and Studio properties`) moved that
handler to `inspect-legacy` and registered a shared lifecycle `inspect` in both CLI groups.
That inspector supplies schema, lifecycle, names, notes, ancestry and review digests for
workspace files, drafts, immutable releases, exact references and both archive formats.
The replacement added legacy-archive success fields, changed human output, rejected symlink
paths, and routed validation failures through the generic `{"error": ...}` / exit-1 emitter.
The older CLI test only asserted `valid is True`; it did not protect the exact envelope or
failure contract. The lifecycle worklog explains the need for the shared inspector but does
not document a requirement to change the released archive CLI contract. The contract change
was an incidental consequence of command registration, not a requirement of Schema 3.

## Dependency census

- Studio's `/v1/artifacts/inspect` and `/v1/items/{item_id}/lifecycle` endpoints call
  `inspect_artifact` directly. They need names, lifecycle metadata and digests; they do not
  execute `pack inspect` or read its exit codes.
- Draft/publication, lineage, comparison, properties, validation records, optimistic edit
  checks and pack-consumer reviews also call the shared Python inspector directly. Reverting
  that service's richer data would break these operations; restoring only the CLI does not.
- `scripts/verify_studio_macos.py` inspected industry and organization draft metadata using
  the new CLI behavior. Its two pack inspection calls must select the richer command.
- `commands/eforge/references/artifact-lifecycle.md`, bundled into native skills, directed
  pack draft/release inspection to the new command. That guidance must select the richer
  command and installed conversions must be regenerated.
- The older pack-release skill, `scripts/capture_validation_compatibility.py` and
  `test_pack_release_build_inspect_and_import_have_stable_json` use archive validation and
  should retain `pack inspect`. No in-repository caller was found that requires the changed
  error JSON, exit code or added lifecycle fields on a legacy archive from that command.
- `scenario inspect` is new and has no conflicting released archive contract.

This census covers the tracked repository and generated project skills. External users of
the unreleased draft-inspection spelling must switch to `pack inspect-artifact`.

## Compatibility restoration

Restore `pack inspect` to archive validation and keep `inspect-legacy` as an alias. Existing
Pack Schema 2 archives retain the exact released success payload, human output and invalid
archive contract, including arbitrary filenames and read-only symlink paths. Normalize file
access failures through the same JSON/exit-2 envelope. Do not loosen lifecycle path checks.
An `efpack.yaml` manifest takes precedence over a receipt-named companion so already-valid
legacy archives cannot be misclassified as Schema 3 releases.

Keep Schema 3 archive validation through `read_archive`, which verifies the complete inventory
and receipt before returning anything. The `valid` / `root` / `members` envelope describes its
single portable release receipt, matching the existing Schema 3 pack-import representation;
the receipt inventories frozen dependencies inside that release. A scenario receipt is rejected
by the pack archive command. Archive validation does not import or modify a library.

Expose the existing richer pack CLI as `pack inspect-artifact`, retaining its shared Python
implementation and generic error behavior. Update the verifier and canonical skill guidance;
regenerate ignored local skills through the installer. Studio, scenario inspection, generation,
publication, lineage and review-digest services require no changes or persisted migrations.

## Verification

Strengthen the existing archive CLI test to assert the complete success payload. Add contract
regressions for text and JSON, the retained alias, malformed/missing/traversing/tampered archives,
other filenames, read-only archive links, lifecycle link protection, rich legacy metadata,
both pack draft/release kinds, exact references and tampered Schema 3 archives. Extend standalone
runtime verification to assert the archive envelope/exit code and installed inspection guidance.

- Focused routine suite: **271 passed**, one slow test deselected. This includes archive CLI,
  portable release, lifecycle, lineage, properties, naming, Studio endpoints/edits and skill
  installation contracts.
- Extended CLI/skill suite: **23 passed** with `--no-cov`, including the CLI-only portable
  publication/import/generation/evaluation round trip and byte-identical generation comparison.
- Final archive suite after the manifest-precedence guard: **36 passed**, including all 12
  new inspect regressions.
- Full Ruff lint and formatting checks: passed (1,012 Python files); `git diff --check`: passed.
- Canonical native skills regenerated through the installer; inspected pack lifecycle references
  select `pack inspect-artifact` while the older pack-release workflow retains `pack inspect`.

- Final standalone Apple Silicon Studio app rebuilt successfully with the updated private runtime.
  Packaged wheel CLI sources match the final source files byte for byte. Isolated verification
  passed runtime checksum, archive inspection JSON/exit contracts, richer pack-draft inspection,
  bundled skill guidance, naming, properties, validation and checkpoint-enabled generation.
  The app remains at product version **2.1.2**; no release version bump or DMG was requested.

App: `build/studio-macos/target/aarch64-apple-darwin/release/bundle/macos/EvidenceForge Studio.app`.
Implementation verified on `dev`; Studio branding and shared product-version work remain intact.
