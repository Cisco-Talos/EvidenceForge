# Loop 16 family contract: modeled macOS directory metadata

## Root cause

`MacosExecutionMetadataProducer` allocates the same configured `directory_first_inode` sequence on every host and computes one `born_at` value from the fixed `directory_age_seconds` for every root/home directory. The modeled Endpoint Security rows therefore repeat inode bands and identical directory timestamps across both Macs, with a one-year age regardless of directory path.

## Owning layer

The owner is `MacosExecutionMetadataProducer` in `src/evidenceforge/generation/macos_execution_metadata.py`, backed by `macos_execution_metadata.yaml` and `MacosExecutionMetadataProfile`. This layer owns canonical directory metadata shared by native endpoint renderers; do not rewrite values in the Endpoint Security emitter.

## Required invariant

- Directory inode allocation is deterministic and scoped to the modeled host/filesystem, remains unique among directories on that host, and cannot overlap installed-file or terminal-device namespaces.
- Directory timestamps are deterministic and scoped to the host and canonical directory path, bounded by configured age limits, ordered as valid native metadata, and not one identical age across the fleet.
- Repeated generations with the same scenario/config produce identical metadata.
- Preserve ownership, mode, size, volume identity, and each existing source's canonical metadata relationships.

## Entry points and coverage

Cover root and home directory metadata observed in macOS Endpoint Security `stat` payloads. Add tests for repeatability, host/path-scoped variation, valid age bounds, inode uniqueness, and installed-file non-overlap. Validate the profile YAML and compare fresh output for both Macs.

## Why this is a root-cause fix

The synthetic texture comes from the shared metadata producer assigning globally identical fixture values. Host/path-scoped values in the canonical owner correct every downstream source consistently.
