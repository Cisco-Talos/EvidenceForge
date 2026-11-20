# Converged POSIX process lifetimes and executable provenance (2026-11-19)

Branch: `feat/converged-process-lifetimes` (from `dev` at 3137c23e). Supersedes
Cisco-Talos/EvidenceForge#489 (contributed regression test generalized in
`tests/integration/test_storyline_download_ownership.py`).

## Problem

- Every non-system storyline executable on Linux and Windows received a FILE/CREATE
  attributed to the process itself, about 4 s after it started (a self-write). A
  downloaded payload therefore had two creations: one by the downloader and one by itself.
- Windows `curl.exe -o` created no download file, because `.exe` tool names were not recognized.
- macOS bounded only commands matching a spawn-profile template. Every other foreground
  command held its shell forever, so drop-then-execute could not be simulated on a Mac, even
  from the pre-existing root foothold.

## Decisions (user-approved)

- Converge macOS onto the Linux model and adapt for Mac specifics. Qualified profile
  templates keep their timing; `.app` bundles and `lifetime: long` profiles stay open; every
  other command uses the shared table.
- Listeners, followed output and bare interactive shells stay unbounded on every POSIX
  platform until an authored close.
- An implied executable creation is attributed to the launching parent (dropper,
  `parent_ref`, shell/desktop) just before launch, and ground truth marks it
  `implied_image_create`.
- `eforge validate` reports an info notice for each implied creation.
- #489: thank the author and close with an explanation and a link to the fixing commit.
  Their code was not reused (the approach differs); their test scenario was generalized.

## What changed

- `config/activity/process_lifetimes.yaml` + `generation/activity/process_lifetimes.py`:
  - An ordered, data-driven table that replaces the hardcoded Linux lifetime function.
    Linux values are preserved exactly (a legacy-value test covers this).
  - Deliberate changes: listener tools match whole tokens (`truncate`/`rsync -l` no
    longer count as listeners); bare interactive shells and `--watch` are unbounded;
    `env` takes the wrapped program's lifetime.
  - The storyline estimator reads the same long-running list.
- `executable_provenance.yaml` + `executable_provenance.py`: preinstalled prefixes plus
  checks against the catalog and system binaries.
- `typed_handlers/process.py`: implied parent creation before launch, a wait when the image
  is still being created, and download/redirect outputs recorded in
  `_storyline_file_available_at`.
- `preflight.py`: the self-write was removed. Mac bundle-pinned helpers
  (`preserve_requested_time` + `lifecycle_group_id`, i.e. mounted SMB) are session-owned
  and exempt from foreground reservation (`actors.py`).
- `storyline.py` `_extract_output_file`:
  - Strips `.exe` from tool names.
  - Adds producers: certutil `-urlcache`, bitsadmin `/transfer`, `Start-BitsTransfer`,
    `Copy-Item`, and cp/mv/copy/move/xcopy destinations.
  - No longer treats `2>&1` or `/dev/null` redirects as files.
- `baseline.py`: baseline SMB operations whose client helper would outlive the owning
  interactive session's known end are skipped. Freed Mac shells exposed this in
  iteration-test; it failed with "Authoritative generic logoff cannot fit its process graph".
- Behavior manifest revision 532.

## Verification

- iteration-test ground-truth agreement: 96.47% (dev baseline 96.37%). Same defect
  categories; acceptance passes.
- Shipped examples:
  - alderbrook, cedar-vale, northstar: byte-identical.
  - lantern-works: one eCAR row removed (the `/tmp/cache-maint` self-write); 100% agreement.
  - juniper-vale: 6 Mac files changed; 100% agreement; acceptance passes.
- Full routine and slow suites: see the PR.

## Follow-ups

- `sh -c '<payload>'`/`bash -c` take the shared default (1–8 s) on both Linux and macOS,
  whatever the payload (for example `zsh -c 'sleep 90'`). Classifying the first payload
  command would be more realistic but changes Linux broadly.
- The storyline estimator's short/medium Windows command sets remain Python constants.
- `scenarios/iteration-test-macos` fails on `dev` with `no_matching_session` (pre-existing,
  unrelated); file separately.
- Linux footholds without a login already exist for web-service actors (`www-data`,
  `apache`, `nginx`, `httpd`, `tomcat`).
