# macOS Studio integration

The user requested the Studio follow-through identified after the modeled Mac
engine and assessment sequence: platform choices, authoring guidance, source
labels, native-text previews and regression coverage. Work remains on
`codex/macos-workstation-support`.

## Changes

- Studio's application/process platform picker now derives its fallback keys from
  the existing typed custom-process schema. It offers `macos` alongside Windows
  and Linux, while preserving any platform constraint already supplied by a model.
  The displayed platform name is `macOS`; saved keys remain `macos`.
- The schema-driven host form retains its existing OS, OS build, architecture and
  workstation fields. Help includes a Mac example and explains the modeled build
  and arm64 requirements. Mac host editing shows the limited native source scope;
  native exec/exit and Gatekeeper denial remain unavailable. Engine validation
  stays authoritative, with no additional UI capability or outcome inference.
- Bundle properties show readable macOS Unified Log and Endpoint Security names.
  Existing zsh history naming already works. NDJSON previews now use JSON syntax
  highlighting without rewriting or combining records.
- Frontend schema fixtures were refreshed from the live Studio adapter, including
  the system model. Backend contracts prevent those fixtures from drifting.
  UI coverage exercises new-host review/save, optional build/architecture fields,
  existing-host edits and server errors, adding Mac software variants without
  losing Windows/Linux definitions, source labels and both native NDJSON previews.
  A real backend add/edit round trip preserves Mac metadata and the existing host.

## Validation

- Full UI suite: **347 passed across 33 files**.
- Studio asset backend suite: **38 passed**.
- Environment, desktop validation and artifact lifecycle: **22 passed**.
- TypeScript/Vite production build and generated API type check pass. Vite retains
  its large-chunk advisory; no native installer build or interactive desktop
  acceptance is claimed by this check.
- Ruff check and format pass (1,324 Python files); whitespace checks pass.
- Generation behavior remains revision **330**, surface
  `a40fa1256a66c2ebee26c2488808bc3193ca88bbb23050d60b662395c09c1247`.
  No product version or native-source gate changed.

Initial new-host component checks exposed test setup assumptions: an empty
system-only inventory started on the default user category, broad text selectors
matched help copy, and the expected request unnecessarily required an omitted
default services list. The fixture now starts on its declared category, selects
the actual optional-field summaries and checks authored host fields. The final
complete UI suite is green. No existing local logs were inspected.
