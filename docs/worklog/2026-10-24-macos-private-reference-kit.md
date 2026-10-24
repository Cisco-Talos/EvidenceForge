# Private macOS reference test kit

The user requested a local route to ES-R1/GK-R1 without VMs, with two overriding
conditions: no potentially sensitive information is seen by an agent and no
captured logs enter the repository. They permitted an eslogger filter, then
explicitly selected **prepare the kit; they will run collection privately**.
Agent-run capture and native-record inspection remain unauthorized. No native
collection, live probe execution, host inventory, permission changes or gate
opening occurred during this preparation.

## Implemented boundary

- `scripts/macos_reference_capture.py prepare` copies code and instructions into
  a new private directory outside Git. It does not build, collect, inspect the
  host or install anything. The separate `capture --private-run` command is for
  the human after closing agents, using standalone Terminal and existing access.
- The normal-user probe uses a clean explicit environment, a parent-controlled
  start barrier and four harmless fork/exec/wait cases: exit 7, SIGTERM, a
  returning ENOENT failed exec and Apple's true utility. Probe stdout is private
  machine-readable control data. Its C source was checked for syntax/warnings
  only; it was not executed by the agent.
- eslogger's stdout goes directly into a bounded in-memory filter. Exact process
  identities include PID, PID version and start time. Unsupported/unowned
  transitions reject; unrelated records are discarded before any disk write.
  Full matched native lines are preserved only in private mode-0600 files in a
  new mode-0700 run directory. A separate account does not isolate the ambient
  stream; system memory, existing monitoring and backup policies remain local
  privacy considerations explained in the human instructions.
- Candidate checks compare the known v10 envelope/process shapes, parent and
  execution relationships, controlled argv/environment/cwd/descriptors, native
  exit status versus independent wait results, returning failed exec, lifecycle
  delivery and sequence continuity. The candidate envelope does not expand the
  production parser's v10 fork-only admission.
- Exact build/command/timing and probe hashes stay in private provenance. The
  public report model forbids extras and allows only fixed keys and enumerated
  check/error codes. No exception values, native strings, identifiers, paths or
  record snippets are exported. Unexpected exceptions have a constant hook that
  never formats the exception. Only human-reviewed report text may be shared.
- The shareable report always retains `reference_review: REQUIRED` and
  `gate_status: NOT_EVALUATED`. Evidence review, build scope and production
  parser/generation/filter/checkpoint admission remain separate. Gatekeeper and
  Unified Log collection are not part of this kit; a separate item-specific
  private protocol/checker is still needed before that experiment.

The old full-stream capture instructions and permission to copy private records
into ignored sample_data were removed. The updated procedure forbids all native
record copies into Git, fixtures, worklogs, PR attachments and CI artifacts.
No product version or generation behavior changed.

## Verification

Tests use independently invented records and mocked processes, including a
complete filter-to-file run. They cover ambient-record removal, exact raw-byte
preservation for matched records, PID reuse/identity mismatches, invalid exec
targets, unknown shapes/null presence, counter gaps/reversals, wrong controls,
input/FD/credential/parent mismatches, missing lifecycle, limits, malformed JSON,
interruption/read/startup failures and partial input. Error/output tests check
canary exclusion and fixed report vocabulary; preparation tests reject Git
worktrees, reused directories and dangling Git links, and prohibit native tool
launches. The existing production v10 exec rejection remains tested.

Validation: all 93 selected tests pass (54 kit/privacy tests plus 39 existing
native contract tests). Full Ruff check and format checks pass for 1,328 Python
files; git diff whitespace check passes. The C probe passes clang C11 syntax
and warning checks with `-Wall -Wextra -Werror -fsyntax-only`; it was not run.
The collector retains the standalone Terminal session so the human's private
`sudo -v` ticket can be used without an agent terminal or password prompt.

A code-only copy was staged at
`/private/tmp/eforge-native-reference-kit-t16gn9oy`. Its isolated `--help` command
loads successfully with the documented existing Python environment. This path
is a **human-only private capture location after handoff**: future agents must
not scan it, open reports or read its contents. The user will paste only a
personally reviewed fixed report. No live test was run to validate the native
collector; all process/record execution in tests is mocked or invented.

## Fixed-code preflight follow-up

The user reported the old fixed `PLATFORM` error, including after switching to
normal-user Python. That code combined four checks and therefore cannot identify
the failing predicate. It occurs before probe compilation, new run-directory
creation or eslogger startup; it supplies no native reference evidence.

The helper now shares one target guard between capture and a human-only
`preflight` command. The guard reports only ROOT_USER, OS_FAMILY, PYTHON_ARCH or
OS_MAJOR (plus existing location/error codes), never actual identities, machine
details or OS/build values. The preflight does not compile, collect or write
data. Python-process architecture is not a claim about physical hardware.
The macOS 26/arm64 and normal-user requirements remain enforced. The old
PLATFORM code stays in the report vocabulary for backwards readability.

The standalone Terminal command is now documented as `sudo -v && python ...`
so authentication and normal-user Python cannot be accidentally combined into
one sudo invocation. Agents must not execute preflight or capture, inspect old
private directories, or copy evidence into the repository. The user will run
the prepared update privately and share only the fixed code/report.

Validation: 102 selected tests pass (63 kit tests and 39 native contract tests),
including mocked success/rejection paths proving preflight never launches a
collector, compiles or writes files; simulated platform values contain an
invented canary that is absent from all exported diagnostics. Full Ruff check
and format checks pass. No live platform diagnostics or native tests were run.

The updated code-only kit is staged at
`/private/tmp/eforge-native-reference-kit-ow630c_8`. Only its static `--help` was
executed. Like the original path, it becomes human-only after handoff: agents
must not inspect it or run preflight/capture. All original private files are
untouched. Await only the user's reviewed fixed code/report.

## Reference acquisition across OS majors

The user disclosed that their workstation uses macOS 27 and authorized removing
the capture tool's exact OS-major restriction, while retaining version-aware
validation. This supersedes the prior acquisition-only macOS 26 requirement;
production generation profiles and evidence admission are unchanged.

The version-2 kit accepts a numeric local macOS version after the existing
Darwin, arm64, normal-user and private-outside-Git guards. The actual OS/build
and matched native message versions stay in private provenance. It never
changes a captured header to match a candidate model or infers a wire version
from OS major. The fixed public `wire_profile` classifies only matched headers;
`message_shapes` invokes the known v10 candidate check only for that profile.
V11/other/mixed/unknown-schema records remain `INCONCLUSIVE`, with fixed
`WIRE_PROFILE`; invalid discriminants fail. Native qualification never passes
for an unsupported profile and the CLI does not return a success status for an
unqualified wire report. Legacy version-1 fixed reports remain readable.

Unknown full wire layouts may still yield safely scoped reference records and
independent lifecycle/status checks. Their matched original bytes remain
private for local qualification; WIRE_PROFILE alone is not a reason to collect
again. If incarnation/path ownership cannot be established, records are not
retained. Every tracked source executable is now also checked against its
execution-owned path before retention, in addition to PID/version/start time.

Tests use invented v10, v11, other/mixed headers, extra private canaries and
invalid discriminants. They prove exact retained bytes, no unqualified shape
pass, distinct fixed reports, no public canary leakage, and acquisition-only
preflight on multiple simulated OS majors. No live checks, collectors, native
probes, private files, permission changes or OS upgrades were run by the agent.
No captured records, raw examples or evidence fixtures are committed.

Validation: all 115 selected tests pass (76 private-kit and 39 existing native
contract tests). Full Ruff check and format check pass for 1,328 Python files;
git diff whitespace check passes. New-version tests forbid invoking the v10
validator at all, and the mocked filter-to-file experiment proves unknown v11
headers/extra fields survive byte-for-byte only in the scoped private output.

Version-2 code-only kit:
`/private/tmp/eforge-native-reference-kit-sw9_ioqo`. Its static `--help` loads
with the documented interpreter. It becomes human-only after handoff, just like
the earlier kit directories; agents must not inspect contents or execute live
preflight/capture. Earlier private directories remain untouched.

## Delivery/readiness troubleshooting — kit version 3

The user shared only a fixed version-2 report: platform and independent probe
controls passed, while the wire profile was NOT_OBSERVED and delivery/linkage
checks failed. This establishes zero retained native records, not a failure of
the harmless commands or a known cause of missing evidence. No private output,
old kit directory, native stream or host inventory was inspected. Inspection
of source identified a half-second sleep followed by immediately running all
four cases, which could miss every test during a slower collector startup.
The old matcher also recognized only array tokens and literal executable paths.
These are source-level weaknesses; the actual cause on the user's workstation
has not been established.

The updated helper waits up to 10 seconds for a known probe warm-up fork and
its child exit before releasing the four cases. At most eight harmless warm-up
children can be requested, at least one second apart. Once a root fork is seen,
the checker waits for its matching exit rather than sending more requests.
Pre-barrier warm-up records are processed only in memory. Delayed warm-up rows
after the barrier remain inside the same strictly bounded, exact private probe
family. The existing 15-second experiment deadline, record/byte limits and
bounded collector/probe cleanup remain. If readiness fails, unrun case checks
are INCONCLUSIVE; delivery fails. Fixed stream/identity/image/readiness checks
make the next report useful without native values, counts or error snippets.

Acquisition identity recognition now accepts explicit full eight-word array,
named and val-wrapper audit tokens and explicit string/timeval birth forms.
No missing words, booleans, partial births, PID-only or prefix matches are
accepted. The human-run helper samples device/inode identity only for the newly
compiled probe and planned true utility; native paths never trigger filesystem
lookups. Exact object ownership handles path aliases while the full incarnation
and tracked ancestry checks remain. These acquisition adapters do not alter
the production codec, qualify new native layouts, rewrite raw records or open
ES-R1/GK-R1. Full unknown wire versions remain INCONCLUSIVE/WIRE_PROFILE.

Verification uses only invented inputs and mocked child/collector processes.
It covers delayed readiness, bounded timeout, missing warm-up exit, absent
stream, unrecognized identity, executable mismatch, explicit token/birth forms,
owned aliases and refusal to resolve arbitrary native paths, alongside the
existing raw-byte retention, unrelated-record exclusion, controls and cleanup
contracts. The C source is checked for syntax/warnings only and is never run
by the agent. Earlier handed-off kit directories remain off-limits.

Validation: all 139 selected tests pass (100 private-kit and 39 existing native
contract tests). Full Ruff check and format checks pass for 1,328 Python files;
git diff whitespace check passes. The C probe passes C11 syntax/warning checks
with `-Wall -Wextra -Werror -fsyntax-only`, without being executed.

Version-3 code-only kit:
`/private/tmp/eforge-native-reference-kit-6onosyh6`. Only preparation and its
isolated static `--help` were run. This new directory becomes human-only at
handoff: agents must not inspect it, run preflight/capture, or revisit older
private kit locations. The user will run it privately and may share only their
reviewed fixed report. No captured logs or private provenance enter Git.

## User-reported successful bounded capture

The user returned only the reviewed fixed version-3 report. Platform, stream
delivery, full probe identity, exact probe-image ownership and collector
readiness all pass. Independent probe controls, bounded delivery, fork/exec/exit
linkage, controlled exec inputs and descriptors, exit-status agreement,
returning failed-exec control and sequence continuity also pass. This supports
the bounded experiment's behavioral checks on the user's disclosed macOS 27
system. It does not identify which earlier acquisition weakness caused the
version-2 empty result.

The retained header profile is V11_UNQUALIFIED. WIRE_PROFILE and inconclusive
message_shapes/candidate_v10_shapes are the expected guard for that profile,
not a collection failure. The current full candidate model is v10 only. No
new collection is required just to change that result. All private directories,
records, controls and provenance remain human-only; the agent has inspected
none of them and has run no native commands.

The next evidence step is a human-run read-only offline checker against the
existing private capture, with only fixed known-field/type/absence/null results
exported. That checker is not implemented yet. Qualify the complete v11
serialization from public contracts plus private human review before admitting
its parser/generator profile. Apple's
[message-version guidance](https://developer.apple.com/documentation/endpointsecurity/es_message_t/version)
requires version-aware field access; it does not establish eslogger's complete
v11 JSON serialization. Do not retag v11 rows as v10 or expand an allowlist solely
because the behavioral checks passed. Subsequent source admission must retain
parser, correlated lifecycle, filtering, manifest and checkpoint acceptance.
macOS 27 evidence does not qualify macOS 26, and this experiment supplies no
Gatekeeper-denial evidence. ES-R1/GK-R1 remain open with this narrower progress
recorded, rather than treating evidence acquisition as still unsuccessful.

## Public v11 research

The user requested online research into v11. No private capture directory,
installed SDK, host inventory or local log was inspected. Research used public
Apple documentation, a pinned public Apple SDK header mirror, and public code/
example searches. Public documents were processed in memory; no native example
records or copied SDK sources were added to the repository.

Findings and limits:

- Apple's [message-version discussion](https://developer.apple.com/videos/play/wwdc2020/10159/?time=1750)
  describes structure compatibility and version-gated fields. Message version
  is distinct from eslogger's JSON schema version. The Apple-authored
  [eslogger manual](https://keith.github.io/xcode-man-pages/eslogger.1.html),
  hosted as an SDK-manual mirror, explicitly distinguishes these numbers.
- Current Apple documentation exposes
  [es_process_t.cdhash_full](https://developer.apple.com/documentation/endpointsecurity/es_process_t/cdhash_full)
  with type [es_token_t](https://developer.apple.com/documentation/endpointsecurity/es_token_t):
  a byte buffer plus byte count. The official documentation JSON was fetched
  directly from developer.apple.com because the browser reader could not load
  its JavaScript/Markdown pages. The field is absent from the public
  [macOS 26.5 ESMessageCore.h baseline](https://github.com/alexey-lysiuk/macos-sdk/blob/896cd40df984b847d486723edce50e247385617e/MacOSX26.5.sdk/usr/include/EndpointSecurity/ESMessageCore.h),
  which declares the existing process fields through cs_validation_category
  (message >=10). This establishes a concrete current API difference, not its
  exact eslogger serialization or exhaustive v11 coverage. No v11-specific
  original SDK header or complete v11 JSON example was located in this bounded
  primary-source search. Third-party indexing associates cdhash_full with v11,
  but that association was not independently established from a v11 SDK header
  and must not be used alone to admit a profile.
- Our ESProcess and MachOCodeSignature models store only the existing 40-hex
  cdhash. The latter derives a synthetic CodeDirectory identity in its own
  namespace and truncates it to that legacy extent. A full digest requires
  explicit canonical ownership; neither padding the legacy value nor using a
  whole-file SHA-256 supplies missing CodeDirectory facts. Its hash algorithm,
  byte extent, legacy/full relationship and JSON encoding still need a bounded
  supported contract. Do not assume a 32-byte digest or a particular encoding
  from the generic es_token_t type.
- Apple's [eslogger introduction](https://developer.apple.com/videos/play/wwdc2022/110345/)
  explains that JSON reflects native structures and can change with software
  updates. The API type alone does not settle absent/null behavior or whether
  that binary token appears as text, bytes, an object or another representation.
  Existing process snapshots at the source, fork child and exec target all need
  the same version-aware field contract. No new event semantics were established
  merely by finding this added field.

Recommended next implementation: a human-run read-only offline diagnostic for
the already captured bounded experiment. Check the documented field set,
required/absent/null distinctions, token representation, and unexpected-field
presence using only fixed whitelisted report keys/codes. Unknown keys and all
values remain private. Then define the supported v11 codec, add explicit full
signature facts where required, and run independently authored parser/source/
filtering/manifest/checkpoint tests. No new capture or version-number bypass is
justified by the current report. The offline tool and v11 admission are still
unimplemented; ES-R1/GK-R1 remain open.

A separate public lead surfaced while searching: the original reporter's
[Rancher Desktop issue](https://github.com/rancher-sandbox/rancher-desktop/issues/9839)
contains v10 exit records with named audit tokens. The issue labels its original
environment macOS 26.2/25C56 arm64, but that does not independently establish the
exact later comment's capture build or supply the controlled v11 experiment.
Treat it as a v10 exit qualification lead, not v11 or complete lifecycle proof;
no records were copied into Git and no production allowlist was changed.

## Prepared human-only offline diagnostic

The user authorized the recommended sequence. The first dependency is now
implemented as `scripts/macos_reference_review.py`: a separate standalone
offline tool, with code-only preparation and a human-only review command. It
contains no collector, subprocess invocation or network client. The human
selects the existing private-run directory through a hidden interactive prompt;
the agent must never locate that directory or invoke review against it.

The reader opens only SHAREABLE-REPORT.json and probe-events.jsonl, using a
retained directory descriptor, read-only/no-follow/nonblocking file opens,
regular-file/current-owner/private-mode/single-link checks, and explicit byte,
record and JSON-depth bounds. It rejects Git locations, malformed/duplicate or
nonfinite JSON, inconsistent headers and unsuccessful/non-v3 capture reports.
It writes no files, changes no permissions and reads no private provenance,
controls, executable, SDK or host inventory. The report is a consistency check,
not a cryptographic custody proof or a repeat of the live behavior experiment.

Fixed diagnostics compare known envelope/process/event fields without changing
the original v11 tags or records. Existing process models are applied only to
an explicit legacy-field diagnostic view; missing/unknown keys are checked
separately and cannot become a complete-layout pass. Audit/birth representation
classes preserve unsupported distinctions. The full-hash report distinguishes
absence, null, string, byte-array and candidate size/data objects. Hex, canonical
base64 and strict byte-array interpretations are checked independently, with
fixed extent buckets, declared-size consistency and conditional legacy-prefix
comparisons. Ambiguous text can pass multiple encodings; the tool never chooses
one or infers an algorithm. Unknown field names, arbitrary counts, raw values,
paths, hashes and exception text are excluded from the export model.

All results retain OFFLINE_ONLY, SHAPE_DIAGNOSTIC_ONLY, REQUIRED,
NOT_EVALUATED and inconclusive full message_shapes. Diagnostic completion and a
zero exit code do not qualify v11. Full layout/algorithm/nullable semantics and
the canonical metadata/parser/generator/filtering/manifest/checkpoint changes
depend on the human-run fixed report and subsequent reference qualification.
Those changes have not been guessed or enabled. No new capture is needed.
This human checkpoint follows the user's critical privacy requirement, not an
additional approval requirement; only the human may access the private inputs.

Validation: all 236 selected tests pass (97 new offline diagnostics/privacy
tests, 100 capture-kit tests and 39 existing native contract tests). Tests use
only invented records and temporary directories. They verify exact two-file
access and unchanged input bytes while forbidding writes, commands, connections
and permission changes; malformed/bounded inputs, link/FIFO/directory/Git and
permission rejection; absent/null/mixed/ambiguous hash forms; strict tags and
required nullable fields; hidden input; exception/canary exclusion; and the
continued production v11 rejection. Full Ruff check and format checks pass for
1,330 Python files; git diff whitespace check passes. No native records,
private provenance or generated diagnostic fixtures are committed.

New code-only review kit:
`/private/tmp/eforge-native-review-kit-huehc9hi`. Only prepare and its isolated
static --help were executed. It contains only private_review.py and
OFFLINE-REVIEW.md. This directory becomes human-only at handoff; agents must
not inspect it after handoff, run private review, or revisit any prior capture
kit. Every existing private capture remains untouched. The human will share
only the personally reviewed fixed JSON diagnostic.
