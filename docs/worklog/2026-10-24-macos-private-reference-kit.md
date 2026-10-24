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
