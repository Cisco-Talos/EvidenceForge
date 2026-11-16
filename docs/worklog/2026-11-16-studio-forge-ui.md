# Studio "Forge" UI redesign

## Status

Active on `feature/studio-forge-ui` (from `origin/dev` at `55b639b3`). Phases 1–4 are complete.
Remaining items are listed below; none blocks review.

The binding rules for this work live in `AGENTS.md` § Studio UI Design Patterns.

## Current Handoff

Remaining follow-ups:
- **Bundles:** it uses the shared toolbar and filters, and its groups start expanded. It is not yet
  a flat table of runs, because each run needs a details drawer for diagnostics.
- **Activity:** it filters by segment (All · Running · Queued · Needs attention · Done) but keeps
  separate Generations and Evaluations groups, because "Clear completed/finished" history actions
  are per kind. A single merged timeline needs a kind-aware clear action.
- **Workspace headers:** section headers in the Overview cards still use icon-only
  `OperationStatus`; the readiness strip carries the labeled status.
- **Spacing:** values are not yet on the 4px scale.
- **Appearance:** there is no Settings → Appearance control yet. `setThemePreference()` exists;
  persisting it needs a `StudioSettings` field.

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
- **Library (Phase 3):**
  - **Projects:** they moved into the sidebar, and its rows are drop targets.
  - **Tables:** Scenarios and Packs render through `LibraryTable`, with column widths per table
    class. A container query drops secondary columns, and it sets the widths on the rows because a
    container query cannot restyle its own container.
  - **Grouping:** "Group by project" is the `project` sort. It reuses the saved-view `sort` field,
    so it needs no schema change. Group headings are static and accept drops.
  - **Leftover state:** `expanded_groups` is still saved but no longer drives scenario or pack
    layout.
  - **Pack order:** pack families are ordered by their newest release's title, then by name,
    publisher and newest version.
  - **Page titles:** they are the top bar's `h1`.
  - **Refresh:** automatic on library entry and on focus (15s throttle), with "Refresh library"
    in ⌘K.
- **Workspace (Phase 4):**
  - **Readiness strip:** `readinessSteps` maps the existing states onto the five steps, naming
    stopped and cancelled runs rather than calling them failed. `nextStep` picks one action in
    pipeline order, skips steps in progress, and allows generation with validation warnings.
  - **No repeated actions:** section headers hide whichever action the strip is promoting, and
    card actions are secondary whenever the strip is present.
  - **Tabs:** the user confirmed tabs + Overview on 2026-11-16. This deliberately reverses the
    2026-10-02 choice that replaced subtabs with folded sections; Chat focus is unchanged.
  - **Header:** it shows title, version chip, project and description. The source path moved to
    Properties → Technical (Copy and Reveal); scenario counts moved into the Environment card.
  - **Activity:** Job center became Activity, with a segmented filter and counts in place of the
    stat strip.
- **Sidebar brand:** the compact sidebar brand is a 28px mark plus the wordmark. The full logo
  remains on the startup, maintenance and About screens and switches artwork per theme.

## Validation

- **Latest run (Phase 4):** `npm test` passes, 40 files and 398 tests. `npm run build` passes.
- **Phase 4 captures:** the Overview, the Runs and Validation tabs, a second scenario, a pack and
  Activity, in both themes.
- **Preview limits:** the isolated helper exits about 2 minutes after start when no native app
  session claims it, and a generation started there ends as "stopped". Restart the service and
  Vite together right before capturing.
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
