# Studio "Forge" UI redesign

## Status

Complete on `feature/studio-forge-ui` (from `origin/dev` at `55b639b3`), pushed to origin.
Phases 1–4 and every follow-up are done: labeled header status, Settings → Appearance, 4px
spacing, the merged Activity timeline, and a flat Bundles list. No PR is open yet.

The binding rules for this work live in `AGENTS.md` § Studio UI Design Patterns.

## Current Handoff

Ready for review as a PR into `dev`. Before merging:
- **Native check:** confirm the native app in a real Tauri session. In particular, check that
  Appearance persists across relaunch (WKWebView local storage) and how the About window looks.
  The browser preview cannot exercise either.
- **Live runs:** generation in the isolated preview helper stops once the helper exits idle, so
  completed and evaluated runs were exercised only by tests, not in screenshots.

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
- **Follow-ups:**
  - **Appearance:** stored in web storage under `evidenceforge.appearance` (and synced through
    `storage` events) rather than `StudioSettings`. A settings field would require a v4 → v5
    settings migration, a frozen reader and native upgrade gates for a cosmetic preference.
  - **Spacing:** `/tmp/eforge-forge-tools/spacing.py` snapped 589 padding/margin/gap values to 4px.
  - **Activity:** the timeline's "Clear completed" clears both kinds through the existing per-kind
    endpoint; per-kind actions stay in the History menu.
  - **Bundles:** the flat list is the default. Family grouping is the `project` order, labeled
    "Group by scenario". Run rows carry "Open scenario" through `JobCard.extraActions`.
- **Native feedback fixes (2026-11-16):**
  - **Chat appeared not to open:** "New conversation" and "Continue" seemed to do nothing. The chat
    did open, but `.workspace-sections.overview-grid { display: grid }` overrode
    `.workspace-sections[hidden]` (equal specificity, later in the file), leaving the cards
    visible above it. jsdom tests could not see this. A global `[hidden]` rule plus a stylesheet
    guard test now prevent it.
  - **Version families:** they replace the previous-versions filter and reuse the saved
    `expanded_groups` field for open families. Packs without a publisher stay separate identities
    by design.
  - **Steer now:** queued-message steering is a service operation (`ChatService.steer_queued`) so
    a failed steer cannot lose the message.
  - **Projects:** projects for packs predate this branch; the redesign only moved them into the
    sidebar.
- **Sidebar brand:** by user request the sidebar shows the full `docs/logos` artwork (anvil plus
  wordmark), 124px square, with a STUDIO caption. Narrow windows switch to the 256px anvil mark
  (`public/brand/mark-256.png`, copied from the app icon), since the 32px icon blurs when scaled.
  Startup, maintenance and About use the same theme-aware artwork.

## Validation

- **Latest run (follow-ups):** `npm test` passes, 40 files and 402 tests. `npm run build` passes.
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

- **Merge with dev's bundled examples (2026-11-16):** dev added example-only UI in the old style.
  It is now restyled: the example Project picker lives in the shared Duplicate `Modal`, and
  "New draft from example" is a shared `Modal` form. Settings → Example scenarios is now one
  setting row with one-sentence help, path, copy and `FolderOpen` buttons, and an
  Install/Update button. It shows an `ErrorBanner` with retry, and success shows as a toast.
  The Settings folder buttons also moved from `ArrowUpRight` to `FolderOpen`. The user decided
  against an "Example" badge, because membership in the Example Scenarios project already says
  so. Long example titles now truncate so the version badge stays inline.

- **Dev CI repair before landing (2026-11-16):** dev had been red since the bundled-examples
  commits. Root causes and fixes:
  - A fresh default workspace auto-installs the real shipped examples. Unrelated Studio tests
    therefore counted five extra scenarios, and the real-helper and ownership tests waited on a
    multi-second install, so their exit and replacement deadlines failed. Fixed by adding the
    Studio-only `EFORGE_STUDIO_EXAMPLES_DIR` override. `tests/conftest.py` points it at an
    empty collection, which subprocess helpers inherit, and the example tests set their own.
  - Browser Security 4689 and ASA persistent-SMB targets were intentional contract changes in
    394eeb80, so their stale tests now assert the new contract.
  - The validate skill had grown past its 150-line budget. The Mac launch-preflight rule moved
    to the macOS reference, and duplicated text-output and target wording was tightened.

## References

- Review and static mockups (not tracked): `/tmp/evidenceforge-studio-review/`, containing
  `studio-ux-review.md` and `mockups/index.html`.
