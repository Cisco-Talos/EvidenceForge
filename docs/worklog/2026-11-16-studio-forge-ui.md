# Studio "Forge" UI redesign

## Status

Active on `feature/studio-forge-ui` (from `origin/dev` at `55b639b3`). Phase 1 (tokens and
light/dark themes) is complete. Phases 2–4 have not started. The binding rules for this work live
in `AGENTS.md` § Studio UI Design Patterns.

## Current Handoff

Next: Phase 2, the consistency refactor.
- Add the shared `Modal` (Radix; `form`/`confirm`/`review`) and migrate every `.modal-backdrop`
  dialog in `App.tsx`, the BundleLibrary import form and the `window.confirm` in
  `StateMaintenance.tsx`.
- Add `StatusPill` and use it wherever `OperationStatus` icons appear in rows and headers, plus
  shared empty-state, inline-loading and error-banner components.
- Apply the verb table: rename "Clone…" to "Duplicate…" and unify the Remove/Delete labels.
- Normalize menu order, remove single-item and duplicated menus, and hide the permanently
  disabled Validate/Generate entries in `DraftObjectMenu.tsx`.
- Add Reveal in Finder. This needs a small Tauri command; nothing like it exists yet.
- Update `docs/studio.md` wording in the same change, and update tests that assert renamed labels.

Then:
- **Phase 3:** projects move into the sidebar, a flat `LibraryTable` with grouping as an opt-in
  view, one Search/Filter/Views toolbar across Scenarios, Packs, Bundles and Assets, and automatic
  library refresh.
- **Phase 4:** the workspace readiness pipeline (Author → Environment → Validate → Generate →
  Evaluate) with one next-step button derived from `scenarioStates`/`environmentState`, tabs
  instead of accordions, header facts moved to Properties, and Job center becoming an Activity
  timeline.

Phase 1 left these open:
- Spacing values were not normalized to the 4px scale.
- There is no Settings → Appearance (System/Light/Dark) control yet. `setThemePreference()` exists
  in `src/theme.ts`, but persisting the choice needs a `StudioSettings` field in the service.
- The page intros (eyebrow, large `h1`, tagline) are recolored but not yet removed; that is part of
  Phase 3's layout work.

## Decisions

- **Visual direction:** graphite neutrals, an ember-orange accent from the logo (`--accent`) for
  primary actions, selection and focus only, and teal for success. Dark is the default token set;
  `:root[data-theme="light"]` overrides it.
- **Theme selection:** `src/theme.ts` sets `data-theme` from `prefers-color-scheme` (and later a
  user preference). It is the only TypeScript that knows the theme, apart from
  `useResolvedTheme()` for theme-specific artwork (`BrandLogo`).
- **Token pass:** `App.css` was converted from 557 raw hex colors, about 20 font sizes and 15
  radii to semantic tokens. Colors were classified by saturation, hue family and CSS property (the
  blue-tinted legacy neutrals map to neutral surfaces). Font sizes map to 11/12/13/15/20/26, radii
  to 6/10/14/pill, and shadows to `--shadow-pop`/`--shadow-dialog`.
- **Syntax highlighting** uses dedicated `--syntax-*` tokens, not the semantic state colors.
- **Contrast:** the text, accent and state tokens were checked against WCAG AA, at least 4.5:1 on
  their usual surfaces in both themes. Recheck after changing any color token.
- **Sidebar brand:** the compact sidebar brand is a 28px mark plus the wordmark. The full logo
  remains on the startup, maintenance and About screens and switches artwork per theme.

## Validation

- `npm test`: 38 files, 386 tests pass. `npm run build` passes (with the existing chunk-size
  warning). `npm run types:check` is in sync.
- Visual check: an isolated preview service with `EFORGE_STUDIO_HOME` and
  `EFORGE_STUDIO_DEFAULT_WORKSPACE` under `/tmp`. Vite must run on port 1420 because the service's
  CORS allow-list only includes the Tauri dev origin. Library, workspace (with validation
  findings), Packs, Job center, Settings and ⌘K were captured in both themes through headless
  Chrome with emulated `prefers-color-scheme`.

## References

- Review and static mockups (not tracked): `/tmp/evidenceforge-studio-review/`, containing
  `studio-ux-review.md` and `mockups/index.html`.
