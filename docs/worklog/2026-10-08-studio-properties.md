# Studio artifact properties

## Approved scope

Settings-style Properties popup from scenario, pack and bundle menus; direct draft title,
description and release-note editing with adjacent assistance and hover help. Keep workspace
publication controls compact. Published content requires a linked draft; identity changes retain
ancestry. Show available release-note history and exact provenance, with missing ancestors explicit.

Both packs and scenarios show the engine that validated their exact captured inputs. Preserve
existing compatibility declarations as advanced metadata; do not infer feature compatibility.
Bundle technical details summarize data bytes and log types without a host inventory.

File services and CLI remain authoritative and usable without Studio. No application version bump
or changes to the user's live workspace/database. Use isolated fixtures for acceptance.

## Implementation

- Added shared file-based Properties inspection, reviewed draft metadata edits, available notes
  history and bounded exact-parent comparisons. Comments and include ownership are preserved;
  changed reviews are rejected without losing the user's edits. Identifier and publisher changes
  explicitly create a linked draft; original identities and references are retained.
- Added portable successful-validation records for scenarios and both pack kinds. Exact authored
  inputs, dependencies and effective configuration determine draft freshness. Publication seals
  `validated-with.json` in its integrity inventory; export/import retains that engine record.
  Legacy inputs remain usable without inferring their validating engine.
- Added bundle inspection for generated-data bytes/files, total regular-file disk usage, selected
  log formats and captured generation inputs. It does not scan individual log records or build a
  host inventory. Partial output and changed captured scenarios produce explicit findings.
- Added authenticated Studio routes over those shared services and a Settings-style Properties
  popup from libraries, workspace titles/menus and run/bundle menus. Editable draft title,
  description and current release notes use hover help and adjacent assistance. Suggestions have
  an editable preview, explicit acceptance and a separate reviewed Save properties operation.
  Published/legacy fields remain read-only with explicit linked-draft creation. Workspace
  publication controls are compact and point into the popup for details.
- Added CLI `scenario`/`pack properties`, `edit-properties` and `check`, plus
  `scenario bundle-properties`. Updated canonical skills and references and regenerated the
  installed Claude and native ChatGPT skill conversions. No GUI or Codex dependency was added
  to file operations, validation or generation.
- Native acceptance found that the packaged runtime's unrelated `release.json` was being
  mistaken for an artifact receipt. Receipt detection now also requires the artifact's retained
  source-tree layout; regression checks cover both built-in pack kinds beneath runtime metadata.
  Existing malformed-receipt and immutable-release protections still pass.

## Verification

- Focused backend baseline: 218 passed, 15 deselected. Studio/skills/runtime contracts:
  68 passed, 22 deselected. Final properties/lifecycle/API regression set after receipt detection
  fix: 49 passed, 1 deselected. AI preview API/isolation tests: 23 passed, with simulated responses
  and no paid model calls.
- Full frontend suite: 281 passed across 27 files. After final metadata-save changes, the affected
  Properties/lifecycle/App set passed 114 tests. Frontend production build and generated type
  freshness passed. Ruff lint passed; Ruff format check passed for 1008 files.
- Rebuilt the standalone Apple Silicon macOS app. Final relocated-runtime verification passed
  checksum, isolated CLI, bundled skills/references, artifact naming/Properties, aggregate bundle
  data, validation and checkpoint-enabled deterministic generation.
- Actual native UI acceptance used only `/private/tmp/eforge-properties-native-workspace` and a
  private test Studio home. Verified direct scenario edits persisted to YAML and refreshed titles;
  stale validation disappeared and a new explicit check recorded EvidenceForge 2.1.2; notes
  history exposed draft/release/legacy ancestors; identifier sparkle proposed a value without
  publication; changing identifier and publisher produced a separate exact-parent draft;
  scenario releases remained read-only; packs showed their recorded engine; bundled packs
  retained protected menus and could create linked drafts. Workspace titles opened Properties.
  The discovered CLI bundle showed 110.9 KB of logs across 8 files, 989.5 KB total disk usage,
  Windows/Zeek formats, captured engine, seed and input digest.
- Native visual inspection corrected overlay stacking, hidden accessibility description,
  textarea styling and history-link styling. The temporary test app was closed afterward.

No application version bump, commit or PR. Existing dirty feature work was preserved. Test
artifacts and logs remain under `/private/tmp`; the user's scenario data was not edited.

## Follow-up: edit controls and bundle menus

- Replaced Identifier and Publisher's large Change buttons with accessible pencil controls.
  Both keep the existing input review and explicit linked-draft workflow.
- Moved the shared bundle menu to the far right of each run/imported-bundle summary, next to
  the disclosure arrow. It is available before expanding the bundle. Responsive layouts keep
  the controls together; mouse and keyboard menu use does not toggle the row.
- Reproduced the reported `TypeError: Load failed` with stored generation records. The
  Properties route read a nonexistent `kind` field from their payloads; kind is indexed in the
  jobs table. It now uses that index to select generations within the current workspace.
  Complete and stopped runs load; evaluation IDs and other-workspace jobs remain unavailable.
- Verified the regression fails with the original lookup and passes with the correction.
  Backend service/Properties checks: 92 passed. Full frontend: 287 passed across 28 files,
  including collapsed menus, keyboard access, all bundle sections and reviewed pencil actions.
  Production build, generated type freshness, Ruff lint/format and diff whitespace checks passed.
- Rebuilt and checked the native Apple Silicon app in the same private test home/workspace.
  A real Studio generation completed, then all three Properties sections loaded from its closed
  bundle row. Imported-bundle Properties remained available from the matching summary menu.
  Visual inspection confirmed both menus at the far right; a scenario pencil opened its reviewed
  linked-draft editor without changes. Closed the test app and stopped only its isolated helper.

## Follow-up: specific log types present

- Confirmed that manifest `formats` records requested groups/filters. Windows expands to
  Security and Sysmon with eCAR separate; Zeek selects sixteen supported concrete sources,
  many of which do not produce files in an ordinary run.
- Added portable `log_types` and `unrecognized_data_files` inspection fields. Reused evaluation's
  filename discovery contract for regular files under `data/`, including Snare Windows output,
  year-partitioned logs and shell history. Keep original `formats` for provenance. No log records,
  host inventory, generation changes, migration, or Studio database dependency were introduced.
  Recognized empty files describe presence, without promising record counts or event-kind coverage.
- Technical details now shows **Log types present**, with Security/Sysmon/EDR and individual
  Zeek names. **Captured inputs** separately shows the original **Selected formats**. Unknown
  files are explicit. Existing complete and partial bundles can use the inventory immediately.
- Regression coverage includes Security-only, Sysmon-only, both, EDR-only, Zeek connection/DNS
  and SMB subsets, Snare, year partitions, shell history, no output, symlinks and unknown files.
  A no-file-read test proves type inspection does not scan data records. Backend Properties/bundle
  set: 41 passed; service assertions and native-skill contracts also pass. Full frontend:
  287 passed across 28 files. Skill installation/reference checks: 71 passed. Build, type freshness,
  Ruff lint/format and whitespace checks passed.
- Real isolated CLI generations confirmed exactly Security+Zeek conn, Sysmon+Zeek DNS, and
  eCAR-only output. The earlier broad Windows/Zeek run reports Security, Sysmon and only six Zeek
  types. Native macOS acceptance verified both the narrow Security/conn case and that broad
  subset, with original group selections still available under Captured inputs. The test app and
  only its private helper were stopped afterward; the user's workspace was not modified.
- Updated the canonical lifecycle/schema references and refreshed native-client conversions.
  Removed redundant wording from the scenario dispatcher to retain its existing compactness gate.
