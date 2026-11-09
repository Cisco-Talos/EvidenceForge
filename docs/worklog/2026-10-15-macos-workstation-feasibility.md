# macOS workstation feasibility assessment handoff

Date: 2026-10-15
Source commit: `5ce84103fccd630a748cf59ab19808f9fa0699bc`
Scope: feasibility assessment only, with equal consideration of mixed-fleet hunting and Mac-native log investigation. Filesystem artifact generation is excluded. No product implementation, schema change, release or live telemetry capture.

## Deliverables

- [Feasibility report](../design/macos-workstation-feasibility.md): architecture owners, source
  classification, collection and ingestion boundaries, public interface considerations,
  skills/docs impact, delivery choices, proposed phases, acceptance scenarios and open decisions.
- [Executable probe](../design/macos-workstation-feasibility/probe.py) and
  [captured results](../design/macos-workstation-feasibility/evidence.json).
- One durable TODO entry for deciding the support boundary and commissioning the fixture gate.
  It does not schedule or authorize the implementation phases.

## Findings to preserve

The source catalog and software deployment compiler recognize modern Mac labels, while activity
and validation classifiers return `unknown`. All tested Mac labels receive no eCAR source
instance. The world model does not grant SSH receiver capability to the Mac test host despite
an explicit SSH service. Architecture defaults to x64 unless supplied.

Static inspection also found a non-Windows-to-Linux boot builder fallback, two-platform PID
cohort validation/allocation, Windows/Linux-only identity overrides, Linux-specific SSH
continuations, and Windows/Linux SMB/storage profiles. APFS is rejected. The content identity
layer knows `macos` but its lexical POSIX path key is not a complete APFS volume case policy.

Recommended first product boundary: one pinned macOS 26 arm64 profile, shared Mac lifecycle foundation, existing network sources, adapted eCAR, a bounded ES notification JSONL subset and selected Unified Log exports, with optional shell history. Native log containers and FSEvents are optional log-format/source extensions, not completion gates. Plists, extended attributes, databases and disk images are outside the proposal. Both managed and unmanaged collection profiles matter.

## Scope clarification

The user clarified that EvidenceForge's focus is log sources and that Mac filesystem artifacts should not be treated as necessary. The report now defines native investigation as investigation of Mac-native logs. It removes artifact production from the recommendation, delivery phases and acceptance gates, and distinguishes modeling persistence/quarantine/file state from materializing those artifacts. Unified Log containers and FSEvents remain correctly categorized as optional log encodings/sources. The TODO pointer reflects the same boundary. Paragraphs in the report remain unwrapped to preserve rendering.

## Research and execution record

- Read TODO and applicable AGENTS instructions; consulted world-capability, source-reachability
  and V2 foundation worklogs.
- Read canonical event/context/state, world/deployment/storage, source/observation/dispatcher,
  activity/boot/SSH, evaluation/target and skill reference owners.
- Consulted Apple primary documentation and the mac_apt and Mandiant macos-UnifiedLogs projects.
  Source links are adjacent to claims in the report. No third-party parser was installed or run.
- Inspected installed `/usr/share/man/man1/eslogger.1`, `/usr/share/man/man1/log.1` and
  `/usr/share/man/man5/audit.5` on macOS 26.6.2. Ran `/usr/bin/eslogger --list-events`, which lists
  capabilities without subscribing to events. No personal evidence was read.
- `uv run --no-sync` initially could not write the normal UV cache; a writable temporary cache
  resolved that. The checkout had no dependency environment, and UV created an ignored `.venv`
  containing no project dependencies. No lockfile changed.
- Used the existing UV-managed EvidenceForge interpreter with `PYTHONPATH=src`, so imports used
  this checkout rather than the installed product. Runtime Pydantic version was 2.13.5. This is
  an in-memory source probe, not a clean locked-environment release validation.

Normal reproduction from a prepared checkout:

```bash
uv run python docs/design/macos-workstation-feasibility/probe.py
```

Exact successful assessment invocation from the repository root:

```bash
PYTHONPATH=src UV_CACHE_DIR=/tmp/eforge-macos-assessment-uv \
  uv run --no-project \
  --python /Users/bianco/.local/share/uv/tools/evidence-forge/bin/python \
  python docs/design/macos-workstation-feasibility/probe.py
```

The probe creates model objects only, selects eCAR alone and records classifier, capability,
source-instance, filesystem-validation and lexical-path results. Its output destination is
unused. It is not an end-to-end generation test and does not prove a complete scenario passes
all validators. `source_commit` records HEAD; the report's original evidence is frozen separately.

## Validation and remaining gates

- In-memory probe: passed for six OS labels; captured source-instance/APFS/path outcomes match
  the report. Python syntax and explicit evidence assertions passed.
- Verified all 38 relative file/directory links in the report and worklog at the first final
  document check; added navigation uses local heading anchors.
- Full-repository Ruff check and format check passed (1,045 Python files already formatted),
  using cached Ruff 0.16.6 through UV with a temporary writable cache. The normal checkout
  dependency environment lacks Ruff/pytest; no dependencies or lockfiles were changed.
- No product tests or generation runs were required for these documentation/research artifacts.
  Native fixture collection, Mac generation, independent parser ingestion, realism review and
  performance measurement remain future gates; no result from those gates is claimed.

The next work should select the exact native build/event subset and gather sanitized lab fixtures
before finalizing implementation schemas. Keep simulated Mac support separate from the existing
macOS Studio packaging/runtime support.

## Public sample acquisition — 2026-10-15

Created `codex/macos-workstation-support` from the current local `dev`, preserving the existing assessment changes. No product implementation or version changes. The user authorized downloading public research samples inside `sample_data/macos/`; the existing `sample_data/` Git ignore rule excludes the entire corpus. Do not force-add or redistribute sample contents. Local-user records must never enter this directory, the repository, product code, tests, or documentation. Local-log inspection remains a separate future activity; no local logs or shell histories were read.

Downloaded public SpriteTree captures from The Mitten Mac, the published Calculator eslogger record, Mandiant's Unified Log test archive, and revision-pinned Plaso shell-history fixtures. The ignored `provenance.json` records original URLs, available revisions, sizes, SHA-256 values, authors, license observations, and validation. Companion `coverage.json`, `README.txt`, original provenance documents, and a ZIP member inventory are also ignored. Third-party source examples are references only; repository tests must be independently authored.

Both ZIP CRC checks passed. Mandiant's 667,297,920-byte archive matches the publisher's SHA-256 and contains `system_logs_tahoe.logarchive`; it remains compressed. Its Info.plist does not establish the exact macOS build or architecture. No native export or parser execution was performed. Four extracted SpriteTree JSONL captures contain 2,482 records across fork, exec, create, and rename, dated August–September 2023, with schema version 1 and ES message version 6. They do not close exit, authentication, launch-item, or Tahoe ES compatibility gaps. The Calculator JSON also parses successfully. Shell-history samples are parser fixtures, not a measured Mac workload.

Public provenance entry points: [SpriteTree](https://themittenmac.com/tools), [Calculator sample](https://gist.github.com/stuartjash/0c0867f1c4ea8b8ebc29cad9fdab5fe1), [Mandiant test-data instructions](https://github.com/mandiant/macos-UnifiedLogs/blob/main/BUILDING.md), and [Plaso](https://github.com/log2timeline/plaso). The ignored manifest pins the fetched revisions and archive digest; this worklog contains no copied sample records.

The agreed implementation boundary is macOS 26 arm64, with shell history and comprehensive application/process catalog coverage; Intel, Rosetta, sleep/wake, and roaming remain deferred. Native evidence gaps gate individual source/event fidelity claims, not all foundational development. Preserve existing configuration semantics and legacy scenario/overlay/pack compatibility; do not invent parallel Mac configuration. Public samples can inform generic contracts but must not become copied baseline records.

## Public sample analysis — 2026-10-15

Analyzed the downloaded public data and appended the findings and prioritized remaining gaps to the feasibility report. Safely extracted only Mandiant's Tahoe archive and invoked the installed Apple `log stats` and `log show` with explicit `--archive` paths. No live/local-user log store was read. Native NDJSON export succeeded without stderr; 4,285,501 event objects plus one completion object parsed, with 3,195,649 log events matching the native stats. Detailed scripts, exports, excerpts, inventories, and analysis provenance remain Git-ignored under `sample_data/macos/analysis/`. No external parser binary was executed and no sample content was copied into product code or fixtures.

Public kernel records identify ARM64 VM kernels and build 25A5279m. Five nonempty boot identities and widely separated dates limit representativeness. This closes the broad native NDJSON-shape gap and supplies GUI/session, launchd, registration-only background-item, and Gatekeeper assessment/prompt evidence, but not current stable-build compatibility or controlled action timelines. Broad keyword matches were reviewed: SSH candidates were directory-password-policy false positives, SMB candidates did not establish client sessions, and blocked-hash maintenance was not a Gatekeeper terminal-denial chain. Native Mac logind exists; reject Linux systemd-logind semantics, not the process basename.

All 614 SpriteTree exec pairs retain PID/start time but change pidversion; all 382 forks have a distinct child PID with matching parent PID and inherited image. SDK documentation supports separate process-lifetime and execution identities. Parent/responsible identities, nullable fields, file destination unions, and sequence discontinuities are documented. Samples cover only fork/exec/create/rename and cannot close current ES exit/authentication/launch-item/denial or synchronized cross-source timing gaps.

Local evidence priorities are now narrow: current-build structural differences, retained final Gatekeeper rejection, and actual SSH/SMB usage if any; then full launch-item transitions and GUI outcome deltas. Existing Unified Logs cannot reconstruct ES records that were never collected. Do not inspect personal histories, application inventories, or workload frequencies for catalog defaults. A later local reducer must return only approved schema/type/count/stage information; no raw message/format strings, identities, paths, commands, or timestamps. No such reducer or local capture has been run.

Updated the ignored README, coverage inventory, acquisition manifest, and separate analysis provenance with export commands, source/exporter distinctions, limitations, and checksums for 17 analysis files. Rechecked unchanged acquisition hashes, parsed metadata, reconciled event counts, and verified empty exporter stderr. All 959 public/derived files are ignored and none are tracked. `git diff --check` passed; no product tests were needed because no product behavior changed. TCC/SIP/XProtect and sudo/directory-authentication outcome chains remain explicitly unvalidated; further targeted public analysis should precede personal-log checks for those optional families.

## Authorized bounded local inspection — 2026-10-15

The user subsequently authorized a narrow inspection of existing local logs. Prepared a standalone reducer outside the checkout, reviewed its fixed output allowlists, and ran a synthetic sentinel test before granting log access. Raw JSON was consumed through an in-memory subprocess pipe; stderr was discarded and core dumps disabled. No raw exports, local records, message templates, personal identifiers, counts, or derived local results were written into the repository or public-sample directory. Only approved structural metadata, aggregate counts, and fixed candidate labels were returned in the conversation. The outside-checkout reducer contains generic processing code and no captured data.

Inspection used a 24-hour lookback, selected system-process predicates, a 45-second bound per invocation, and record/line-size limits. A second narrower query focused on SSH and Gatekeeper decision candidates. This was read-only: no SSH sessions were initiated, services enabled, security settings changed, or Endpoint Security capture started. Candidate labels are not proof of complete action lifecycles, and an unrecognized or absent marker must not become a claim that the underlying action cannot occur. This entry records authorization and procedure only; personal observations must not become product examples, templates, configuration defaults, or fixtures. Public/lab evidence remains the basis for implementation contracts.
