# Bundled example scenarios

Branch: `codex/bundled-example-scenarios`, based on `dev`.

## Approved decisions

Ship a browsable offline `examples/<scenario>/<version>/` collection of published Schema 3
scenario releases under the existing `evidenceforge` publisher. The collection may be empty;
real example authoring is deferred. Reuse shared file services, with no new CLI commands or
required skill changes. Preserve all authored source companions in managed publication/forks.

First run enrolls only the new OS user's original default workspace and creates an Example
Scenarios project, including for an empty collection. Existing users are never automatically
enrolled. New versions/additions install on launch/return to that workspace while its tracked
project exists. Project renames preserve enrollment; project deletion stops automatic updates.
Individual deletion suppresses its scenario family until manual installation. Custom workspaces
remain manual-only even after installation. Settings offers install/update and folder opening.

Use the existing Packs latest-version presentation. Forks select a destination project (default
Ungrouped), configured user publisher or the ordinary anonymous-draft behavior, with exact official
ancestry. Preserve releases, user work and deliberate project moves. Deleted releases can only be
restored using their original recorded digest, without freeing reserved identities.

## Implementation

Added shared receipt-based source/installed collection discovery and wheel resource inclusion,
directory import and exact-digest restoration. Managed source capture preserves nested authored
companions while retaining include/corpus checks. Trusted package-resource reads support package
manager hardlinks; workspace imports remain independent regular files and ordinary artifact
operations retain their default hardlink rejection.

Database migration `studio-db-0004` adds frozen example installation records without enrolling
existing users. First-run enrollment precedes initialization completion. Additive installation,
family exclusions, pending restoration and index intents preserve project placement across
interruptions. Settings installs bind their requests to the reviewed workspace. Project deletion
cancels pending manual installation and serializes with library installation.

Studio Settings provides install/update, retry, empty-collection feedback and folder access.
New draft and Clone from an installed example select a project and use configured/anonymous publisher
semantics. Existing latest-release filtering remains shared with Packs. Contributor and operator
documentation explain how to add published content later; no real scenarios were added.

The existing Studio CI source gate now includes the fast integration module. Shared collection
integrity tests run in routine CI, generation is marked slow, and existing packaged verification
checks inventory parity and imports one release when the collection is populated.

## Validation

- Routine collection/lifecycle/Studio checks passed, including five collection tests,
  fourteen installation/API tests and thirty lifecycle tests. Separate lineage/removal/properties regression checks passed
  after retaining repairable-semantic-error behavior in source capture.
- State migration, recovery, edges and frozen contracts: 174 passed, one skipped.
- Full Studio source gate: 607 passed, sixteen platform skips and one outdated project-count
  expectation. Updated that test to preserve/check the new default project; the entire affected
  service module plus the example integration module then passed cleanly (118 tests).
- Frontend: all 387 tests passed, including the official-example Clone project selector; the
  App/Settings/lifecycle subset also passed (131 tests). TypeScript/production build and generated API checks passed. The existing
  bundle-size advisory remains.
- Slow installed-example generation passed after removing the entire authoring workspace.
- Wheel and source archive built; packaged example README bytes match the source inventory.
- Assembled an isolated Apple Silicon runtime. Relocated runtime verification passed checksum,
  isolated CLI/resources, empty example inventory, skills, pack/artifact operations, validation,
  checkpoint-enabled generation and native Mac generation/evaluation.
- A final relocated package probe used a test-only hardlinked example collection, installed it
  through the real first-run service and reopened it successfully. Workspace copies had one link
  and retained their examples project. The shipping collection remains empty.
- Ruff check/format and diff whitespace checks passed. Product version and generation behavior
  revision remain unchanged; no release or installer publication was performed.

## Scenario planning follow-up

On November 16, the user accepted retaining DNS tunneling in the proposed macOS example
with an intentional visibility gap: analysts correlate network DNS evidence with endpoint
process activity by host and time, without requiring a direct query-to-payload PID link.
The shared `dns_tunnel` event/handler currently lacks an explicit originating process
reference across platforms; inferred resolver ownership is not proof of payload identity.
Explicit linkage is now a P1 roadmap item, independent of this example's collection design.
Check eventual output for misleading inferred attribution rather than treating an incorrect
process identity as missing visibility. Switching to SSH would not resolve this shared gap.

LaunchDaemon persistence remains a candidate pending the complete DNS payload choice and
qualification. Temporary modeling probes confirmed native launchd process coverage for zsh
with a script argument and installed Homebrew curl, plus curl ownership of an explicit HTTPS
connection. Those checks do not qualify a complete DNS payload; the tested Python candidate
failed complete native process coverage. No proposed example scenarios have been authored.

## Five-example authoring

The user approved authoring all five proposed examples with the following collection sizes
(warmup is one additional hour). All are published local Schema 3 releases, version `1.0.0`,
under `examples/<name>/1.0.0/`, with `source/scenario.yaml`, `release.json`, dependencies and
frozen configuration. No product release, remote publication or version bump is involved.

| Name | Organization / packs | Users | Hosts | Hours |
| --- | --- | ---: | ---: | ---: |
| cedar-vale-invoice-phishing | Cedar Vale Advisory / Finance 1.0.0 | 6 | 8 | 8 |
| northstar-stolen-credentials | Northstar Health 1.1.0 / Healthcare 1.0.0 | 5 | 9 | 8 |
| lantern-works-web-compromise | Lantern Works Software / Technology 1.0.0 | 4 | 6 | 6 |
| alderbrook-insider-exfiltration | Alderbrook Lending / Finance 1.0.0 | 8 | 10 | 24 |
| juniper-vale-macos-dns | Juniper Vale Engineering / Technology 1.0.0 | 4 | 6 | 8 |

Every source tree includes an attack-free `ENVIRONMENT.md` derived from non-writing effective
composition inspection, an `INSTRUCTOR_GUIDE.md` with questions, intended answers, timelines
and evidence limits, a `RESEARCH.md` with verified ATT&CK sources, and CLI usage instructions.
Cedar Vale includes eight authored corpus entries (benign and phishing) with an invented receipt
attachment. Generated email, run ground truth, logs and checkpoints stay outside the collection.
Northstar retains its pack roster and adds exercise-specific staged software and a permissive
firewall policy for the modeled routed traffic. The other organizations remain scenario-local.

The final Mac design uses the installed Homebrew Python interpreter directly as the explicit
LaunchDaemon target, with a pre-staged modeled `agent.py`. Allocation-free deployment inspection
for the exact November 9 environment resolves its own installed Mach-O, signing and runtime
security facts under both root and the assigned user; baseline native-launch preflight has no
issues. This replaces the earlier inconclusive fixture probe, without changing engine metadata
or borrowing another executable's identity. No shell/helper tree is inferred. The DNS attribution
gap remains intentional; no reboot, KeepAlive, timer trigger, native plist or launchd ULF evidence
is claimed. The fictional payload is represented by invocation/storage/network intent; no runnable
malware is distributed.

Input validation passed for all five. The web example retains two reviewed path advisories:
`/usr/sbin/php-fpm8.3` and `/tmp/cache-maint` intentionally differ from the validator's generic
`/usr/bin/<name>` fallback. Other reported findings are informational collection boundaries.
Publication used the existing CLI in an isolated project with explicitly configured official
publisher identity, then copied complete releases into the collection. The authoring workspace
is `/private/tmp/eforge-shipping-examples-dob6ex_k`; shipping files do not depend on it.

Added a real-collection integration check that imports and independently forks each shipping
release in an unrelated workspace, recompiles it, checks lineage and compares every authored
companion byte. Dataset generation/evaluation is a separate workflow and has not been run for
these authored examples.

Validation of the populated collection:

- Collection and Studio integration modules: 20 passed, one slow generation test deselected.
- Fresh isolated Studio default workspace: all five actual releases installed into Example
  Scenarios; a repeat scan preserved the same five entries and their project assignment.
- Offline wheel build passed. All 107 example files match the checkout byte for byte, and
  discovery verifies five complete releases extracted from the wheel.
- An optional whole-repository source-distribution build was stopped during its prolonged
  backend traversal; no source-archive result is claimed. The direct wheel build and actual
  collection packaging/import checks above completed independently.
- Ruff check and format checks, plus diff whitespace checks, passed.

## Validation precision and multipart failure follow-up

The user authorized fixing the shared validation diagnostics and the pasted Alderbrook
generation failure, with CI regression coverage. The attachment shows an HTTP multipart upload
failure for `board-review.zip`, not email generation. Preserve the user's failed run under
`/private/tmp/eforge-first-run.VIej1H/`; all reproduction uses separate temporary outputs.

Implemented changes:

- Validator path comparisons now disable last-resort executable-path guesses, preserving
  genuine catalog/system path mismatch warnings. Ordinary missing-firewall notes are removed;
  explicitly requested ASA without a compatible sensor remains an error.
- Typed-fact coverage considers selected formats and host-platform applicability. Generic
  conditional routing/timing and unrequested alternatives no longer emit per-action info.
  Configured loss/disabled sources retain diagnostics, and `https` joins `ssl` for opaque HTTP
  result checks. Existing encryption/coverage warnings remain enabled. The curated collection gate now requires zero errors/info and only the two reviewed
  opaque-HTTPS warnings (Alderbrook and Juniper); the other three examples are clean.
- Archive output sizing/publication already existed, but its shared local artifact registry was
  provisioned only for Mac workloads. File-backed authored multipart now also requests that
  canonical owner before activity/checkpoint initialization. HTTP connection/beacon construction
  resolves retained content sizes using exact host/principal/path bindings. Request size bindings
  are kept separate from response-side metadata. No archive length is invented in the scenario.
- Added fast command-created archive -> multipart connection/beacon regressions and parametrized
  slow CLI generation of every actual shipping release after import. The latter also checks Cedar
  Vale's materialized email. These tests are discovered by the existing routine and four-shard
  slow CI workflows; no separate workflow or registration is needed. Negative tests protect exact
  host/principal/path ownership and prevent request sizes from being reused for response files.
- Full generation uncovered a separate Juniper deployment error: its machine-wide applications
  whitelist omitted `/bin/sh`, required by the modeled pre-existing root foothold. Published
  `juniper-vale-macos-dns@1.0.1` through the normal draft/publish CLI, retaining standard machine
  software and restricting only per-user application assignments. The story, collection, and
  counts are unchanged. It still directly launches the installed Python payload interpreter.
  The old 1.0.0 bytes remain in the isolated authoring workspace (including a withdrawn copy);
  they are no longer included in the shipping collection. User-installed releases are untouched.
- Native launch preflight now checks the root-shell prerequisite using WorldModel's existing
  foothold ownership, so this installation error is reported during validation, before bootstrap.
  Fast tests cover both an incomplete whitelist and the retained standard OS installation.
- Generation behavior revision 521 and its final surface digest are current. Product version
  stays unchanged. Previously published release bytes were not edited or resealed.

Verification:

- Final affected fast suite: **266 passed, 8 deselected** in 74.32 seconds (validation, multipart,
  runtime content, application catalog, native launch/root ownership, behavior manifest, actual
  collection import/fork, archive uploads and Studio install/update lifecycle).
- Full CLI generation after import passed Cedar Vale, Northstar, Lantern Works and Alderbrook
  at their complete authored durations; the original Juniper failure led to the new release above.
  See `/private/tmp/eforge-shipping-generation-tests.log` (4 passed, original Mac failed).
- Corrected Juniper 1.0.1 full generation passed at its complete 8-hour duration after
  import into an unrelated workspace. See `/private/tmp/eforge-mac-fixed-generation.log`.
  All five latest shipping examples now pass full CLI generation, including Cedar Vale email
  materialization and Alderbrook's 24-hour archive-upload sequence.
- Ruff check and format checks, generation-behavior manifest verification and diff whitespace
  checks passed. Operator and reference docs explain the refined visibility checks and canonical
  file-backed multipart sizing. These are generation/integrity checks, not an evidence-quality
  evaluation or a completed blind realism assessment.

For an existing Studio workspace, use Settings install/update examples to import Juniper 1.0.1,
then open its latest version and create a new generation job. Alderbrook uses the same scenario
release with the corrected engine. Preserve failed runs; no forced replacement is needed.


## Organization naming follow-up

The user requested distinct organization names for Cedar Vale and the Mac example. Renamed the
Mac organization to **Kestrel Ridge Engineering**, including its display name, analyst briefing,
instructor/research guides, email domain, host prefixes, sensor and updater artifacts. Published
version **1.0.2** through the existing draft/publish CLI. The stable `juniper-vale-macos-dns`
identifier is retained so Studio installs this as the latest version of the existing family.
Historical parent identities stay exact; previous release bytes are preserved in the isolated
authoring workspace and user-installed copies are untouched. Only 1.0.2 ships in the collection.

Validation has zero errors/info and the same intentional opaque-HTTPS warning. Non-writing
effective composition confirms Technology 1.0.0 with unchanged digest and the renamed roster
(4 users, 6 hosts, 8 hours). No new generated dataset is claimed for this naming revision.

Collection integrity/import and Studio install/update regression checks: **20 passed, 6 slow
cases deselected**. Ruff check/format and diff whitespace checks passed.


## Read-only generation and evaluation review

The user requested fresh validation, full generation and deterministic evaluation for every
current shipping example, explicitly without repairs. All inputs retain their authored durations,
seeds and formats; rendering target is `default`, checkpoint cadence 24 hours. Every validation
used `--show-storage`. Five fresh bundles and their separate stdout/stderr reports are preserved at
`/private/tmp/eforge-example-review-pe1xvhof/`, with commands/exits/timings in `status.json` and a
full readable review in `REPORT.md`. The source checkout is HEAD `f50a520b` plus the existing
uncommitted feature work, using engine version 3.0.0rc1.

| Example | Version | Validation | Generation | Records | Overall score | Acceptance | Ground truth |
| --- | --- | --- | --- | ---: | ---: | --- | ---: |
| Cedar Vale | 1.0.0 | Clean | Complete | 47,681 | 93.97 | PASS | 98.74 |
| Northstar | 1.0.0 | Clean | Complete | 38,302 | 94.90 | PASS | 95.16 |
| Lantern Works | 1.0.0 | Clean | Complete | 86,518 | 97.44 | PASS | 98.79 |
| Alderbrook | 1.0.0 | 1 intentional warning | Complete | 142,854 | 94.35 | FAIL | 91.52 |
| Kestrel Ridge | 1.0.2 | 1 intentional warning | Complete | 100,356 | 95.90 | PASS | 97.17 |

All five evaluation processes exited 0 and independently accepted authoritative bundle integrity;
that exit means evaluation completed, not acceptance passed. All five source-schema categories
score 100%. Total evaluated records: 415,711. The only input messages are the two agreed opaque
HTTPS-result warnings (Alderbrook upload and Kestrel benign status check), with zero errors/info;
these still meet the user's intentional-visibility exception. Release integrity was rechecked
afterward and all five source release digests are unchanged. No repairs were made.

Alderbrook fails the required 95 ground-truth gate. Its 33 file-audit cardinality findings comprise
24 bulk-copy and 9 benign-export checks. Samples find one exact file event, but an EventID/logon
selector also selects neighboring file operations (8 or 3 rows); cardinality appears to use this
broader selection. This suggests a matching defect, not missing archive/upload output. The two
personal-upload actions score 100. Confirm the owning layer before any scenario change.

Passing examples retain non-blocking findings: Cedar's OCSP/SMTP comparisons, process/OCSP
presence, extra projections and two missing narrative pivots; Kestrel's 60 DNS TXT representation
comparisons, six shell-history matching ambiguities, and cross-source HTTP status comparisons;
Lantern's scanner IDS expectations/web matching and HTTP status comparisons; Northstar's ASA
absence/extras, Linux syslog capability decisions, extra endpoint evidence and timing dependency.
Northstar's ground-truth margin is only 0.16 points. Kestrel's DNS action scores 76.65 and Northstar's
benign Linux action 74.07 despite their overall acceptance passes. Other diagnostics include
statistical distribution fit, sampled anomaly rate and service cadence. Some timing heuristics
flag the intentional overnight gap or a realistic fast child-process spawn. Detailed report
samples support matching/normalization hypotheses; these are not yet confirmed root causes.
