# Studio "Forge" UI redesign

## Status

Active on `feature/studio-forge-ui` (from `origin/dev` at `55b639b3`).
- **Phase 1 (complete):** design tokens and light/dark themes.
- **Phase 2 (complete):** the consistency refactor.
- **Phases 3–4:** not started.

The binding rules for this work live in `AGENTS.md` § Studio UI Design Patterns.

## Current Handoff

Next: Phase 3, the library.
- Move projects into the sidebar, replacing the in-page Projects rail.
- Use one flat, sortable library table for Scenarios, Packs, Bundles and Assets; grouping becomes an
  opt-in view that never opens collapsed.
- Use one Search · Filter ▾ · Views ▾ · count toolbar, folding in the Hidden and previous-versions
  toggles and the Bundles status/project selects.
- Refresh the library automatically and drop the manual "Refresh library" button.
- Remove the eyebrow, large `h1` and tagline page intros.

Then Phase 4:
- The workspace readiness pipeline (Author → Environment → Validate → Generate → Evaluate), with
  one next-step button derived from `scenarioStates`/`environmentState`.
- Tabs instead of accordions, with header facts (path, version, digests) moved to Properties.
- Job center becomes an Activity timeline.

Still open from earlier phases:
- Spacing values are not yet on the 4px scale.
- There is no Settings → Appearance control yet. `setThemePreference()` exists in `src/theme.ts`;
  persisting the choice needs a `StudioSettings` field in the service.
- Workspace section headers still use icon-only `OperationStatus` next to their titles. Phase 4's
  pipeline replaces them.

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
- **Shared components (Phase 2):**
  - **Dialogs:** every dialog uses `Modal`/`ConfirmModal` (`src/Modal.tsx`). Its title is the
    accessible name unless `ariaLabel` overrides it; the override clears Radix's
    `aria-labelledby`, which would otherwise win.
  - **Dismissal:** forms do not close on outside clicks; Esc is blocked while busy. Hidden titles
    render as non-heading text so custom headers keep a single heading.
  - **Status and feedback:** row and job status uses `StatusPill`/`JobStatusPill`/
    `summarizeStates`; empty and error states use `EmptyState`/`ErrorBanner` (`src/Feedback.tsx`).
- **Vocabulary and menu order:**
  - The verbs are Duplicate…, Export bundle…/file…/report…, Remove from Studio… (forget an entry;
    files kept), and Delete scenario…/version…/bundle… (permanent).
  - Menus render the `ActionGroup`s in this order: inspect, work, manage, locate, organize, remove.
  - Single-item and duplicate menus were removed, along with the permanently disabled
    Validate/Generate entries on draft menus.
- **Reveal in Finder:** uses `revealItemInDir` from `@tauri-apps/plugin-opener`. Its default
  permission set already allows it, so no new Tauri command was needed. `revealAction()` adds it
  beside Copy path; `SavedPath` and the export toasts offer it after a save.
- **Sidebar brand:** the compact sidebar brand is a 28px mark plus the wordmark. The full logo
  remains on the startup, maintenance and About screens and switches artwork per theme.

## Validation

- **Latest run (Phase 2):** `npm test` passes, 39 files and 393 tests. `npm run build` passes,
  with the existing chunk-size warning.
- **Preview service:** run an isolated preview service with `EFORGE_STUDIO_HOME` and
  `EFORGE_STUDIO_DEFAULT_WORKSPACE` under `/tmp`.
- **Vite port:** do not use port 1420. The user's own Tauri dev server may hold `[::1]:1420`.
  Serve Vite on `127.0.0.1:5321` and capture with a throwaway headless Chrome profile using
  `--disable-web-security`, because the service's CORS allow-list only includes the Tauri dev
  origins.
- **Guard:** have the first capture step assert the page host and a Forge-only element (for
  example `.brand-compact`), so captures cannot silently hit another server.
- **Phase 2 captures:** library pills, the row menu, the Duplicate form, the delete review, ⌘K,
  and Codex status, all checked in both themes. They caught a CSS class clash (variant
  `modal-form` versus the inner `<form>`) that hid form dialog panels. It is fixed and covered by
  a test.

## References

- Review and static mockups (not tracked): `/tmp/evidenceforge-studio-review/`, containing
  `studio-ux-review.md` and `mockups/index.html`.
