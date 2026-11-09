# Remaining Mac catalog qualification

**Current status: complete within the agreed scope at revision 482.** Standard
persona launches, reference CLI/runtime checks, exact recovery and fresh MacOS-test
evaluation pass. The four desktop main models remain provisional; the P2 full
catalog installation audit across all platforms is recorded in `TODO.md`.

The user authorized researched/model-assumption qualification of IntelliJ IDEA,
Sublime Text, Postman and Thunderbird without installing those desktop apps.
Homebrew-installable command-line tools and shared runtimes should be installed
and tested on the authorized second Mac over SSH. Unavailable runtime
installations may use the same explicitly provisional research approach. A P2
backlog item covers specific installs/tests of the entire catalog on all platforms.
Keep complete process coverage; do not hide unsupported baseline candidates.

The November 7 read-only audit found 19 ordinary selectable catalog entries using
16 executables with launch/metadata gaps. Developer defaults expose 18 entries,
sysadmin eight, security analyst Postman, and HR/accountant/executive Thunderbird.
The default persona exposes Thunderbird, Vim and 7-Zip. Additional query entries
PowerShell, Redis CLI and ldapsearch also lack metadata, and preflight currently
omits the query category. Python's bundled interpreter must use command semantics
despite its `.app/Contents/MacOS` path. These owner-level defects are in scope.

Reference preflight succeeds on macOS 27.0.1 build 26A434 arm64 with Homebrew 7.0.12
and command-line tools. Git 2.56.0 and Node 26.12.0 are already installed; Python
3.15 is present but does not replace inspection of the catalog's Python 3.14.
Docker Desktop was previously installed by the user; its CLI can be tested without
changing the Desktop installation or launching containers. No application accounts,
private projects, shell profiles, kubeconfigs or Docker credentials are test inputs.

Work is pending. Product version remains 2.2.0a4. No integration, release gates,
publication or new helper-graph expansion is authorized by this increment.

## Installed references and implementation

All requested Homebrew tool/runtime installations succeed. The 15 inspected native
executables cover 18 CLI catalog entries because .NET/MSBuild, Node/npm and
Python/pip/pytest share images. Existing Git/Node/Docker CLI are tested in place.
PowerShell also has an available formula and was installed, so no runtime fallback
was needed. Redis/OpenLDAP/PowerShell close the additional query-tool metadata gaps.
New installations and dependencies remain installed as requested; no launchd services were
enabled/started and no Docker containers/images were created or pulled. No privileged
collector ran, and desktop applications were not downloaded/installed/launched.

Remote technical results are in
`/private/tmp/eforge-catalog-qualification.uRNasy`. Local fixed summaries are
`/private/tmp/eforge-macos-root-fixes-20261107/catalog-cli-reference-final.json`.
The 35 functional controls all pass; two additional direct PowerShell controls
verify expected status 131 without DOTNET_ROOT and status 0 with its wrapper default.
The Python strict resource-seal diagnostic is preserved, with separate successful
main-code verification ignoring resources and successful execution tests. Full
static hashes, measured versions and the exact modeled-versus-observed boundary are
in the catalog metadata document. No raw native telemetry or user data is in Git.

Implementation adds the measured native image/signature/entitlement templates and
explicit modeled runtime validation. Four desktop main models use researched
bundle/team vocabulary with explicitly provisional entitlement/runtime assumptions.
Existing selected versions remain simulated catalog releases rather than claims of
exact parity with the freshly installed references. Canonical content IDs/UUIDs
stay synthetic. Helper graphs and unspecified command completion are not inferred.

Preflight now covers query categories. Bundled Python follows the existing explicit
shell ownership declaration, shared with the process owner instead of treating
all `.app/Contents/MacOS` paths as GUI mains. PowerShell addresses its real native
libexec executable, with its required DOTNET_ROOT default in canonical execution
metadata. Existing supplied environment values/duplicates remain authoritative;
unknown environment stays unknown. The shell-root process path and shared exec
producer apply the same rule before State/publication, not inside an emitter.

The first qualification run passes 40 cases and fails only its final environment
utility test because the test requested installed metadata before initializing the
engine's deployment owner. The test setup is corrected and the complete selection
is rerunning. Forty-eight desktop main native/filtered cases pass. Configuration
validation has zero errors/warnings/info across 101 files. Revision 481 is material;
product version is unchanged. Fresh MacOS-test generation and both exact recovery
checks run against this frozen implementation; final results are pending.

Both revision-481 exact recovery cases pass in 77.72 seconds, including positive
filesystem operations/evaluation and native-only byte equivalence. Seventy metadata,
SSH PTY, process-collector and POSIX checkpoint regressions pass (ten extended cases
deselected). Whole-repository Ruff/format checks pass (1,508 files). The final
catalog/launch/command/Finder selection remains running; its full 41-case new
qualification module has now passed, covering all sixteen standard/default persona
profiles, the three query negative controls, eighteen real native CLI launch cases
and environment validation/preservation. MacOS-test output/evaluation is pending.

## Runtime signing follow-through (revision 482)

The 136-case catalog/launch/command/Finder selection passes (one extended case
deselected). Revision-481 MacOS-test generation completes in 320.29 seconds with an
authoritative bundle. It is retained as an intermediate candidate; no evaluation
was run on it because the following signing-field measurement is a material change.

Static-signature flags do not establish runtime process flags. A bounded unprivileged
probe used Apple's start-suspended spawn option for only its own child and queried
read-only csops STATUS/VALIDATION_CATEGORY before resuming/reaping it. The probe has
an eight-second child deadline and never changes signing/security state. No ambient
process list, native collector, privilege or account data is involved. Two fixed
15-image passes agree exactly; all thirty version invocations return zero. The
second pass confines .NET CLI state to the experiment's existing scratch home.

The snapshots measure ordinary flags 0x22000201, linker-signed-tool flags 0x22020201,
.NET flags 0x22000205 and Docker flags 0x22011311, with category 10 except Docker's
category 6. These differ from the provisional static-derived flags in revision 481.
Revision 482 replaces only these fifteen new CLI/runtime policies with the measured
startup values; four uninstalled desktop policies remain explicitly provisional.
The catalog versions remain existing modeled releases, so exact vendor-build parity
is still not claimed. No new wire families or helper graphs are admitted.

`catalog-runtime-signing.json` holds the fixed local snapshots; remote
`cli-runtime-signing.json` and `cli-runtime-signing-repeat.json` preserve both passes.
The real-engine CLI regression now independently checks canonical and native output
flags against these measured values, and PowerShell's exec environment against its
required root. Final revision-482 verification is pending.

Final startup-field regressions pass **41/41** on revision 482, including native
output flags and PowerShell's published exec environment. Both exact recovery tests
pass again in **75.56s** after the measured-field update. The first .NET SDK cleanup
attempt omitted the experiment's TMPDIR and failed its MSBuild synchronization lookup;
retrying with the original scratch environment succeeds for both MSBuild and the
VB/C# compiler server. Both reports remain remote. Future scratch builds disable
build servers explicitly. No launchd service or user profile change was made.

The final unchanged MacOS-test revision-482 generation remains in progress at
`bundle-v482`. The completed revision-481 candidate is preserved and is not promoted
as the final acceptance snapshot. Evaluation will run once on the final bundle.

## Final result

**PASS for the bounded standard-persona launch scope at revision 482.** All sixteen
standard/default persona profiles pass shared preflight. Eighteen CLI catalog entries
share fifteen installed/tested images; the four desktop mains have accepted
provisional models. No ordinary/query candidate was filtered to make the test pass.
The new independent runtime assertions pass 41/41; the preceding 136-case catalog/
launch/command/Finder selection and 70 metadata/SSH/checkpoint regressions pass.
Both current exact recovery/filter tests pass, including positive filesystem
operations and evaluation. Configuration validation is clean across 101 files.

Fresh unchanged MacOS-test generation finishes in **312.502s** at `bundle-v482`.
Its authoritative evaluation is **PASS 95.69993178263871**, **251,687 records**,
with no failed applicable hard criteria. All 35 manifest hashes verify. Native
census remains **200/200 forks, 256/256 execs and 176/176 known/published exits**,
with zero aggregate starts/unknown outcomes. All 85 authored Mac starts have native
evidence. Exact exec/credential joins and separately qualified fork/exit joins have
zero unmatched phases or eCAR terminals missing native exits. Native sequences are
ordered/unique, same-profile browser overlaps are zero, and attributed FILE/FLOW
checks have zero failures. Unattributed network rows retain their prior qualification.

All **28 generated data files are byte-identical to accepted revision 480**; current
resolved configuration/manifest metadata reflects the catalog expansion. This workload
does not launch the newly qualified developer tools or Code filesystem activity;
positive real-engine CLI, desktop native/filtered and recovery fixtures remain their
separate evidence. The user source SHA256 remains
`18be80547b29d767406b76a2665f69c0ced5c6c6a36938caccdfb080cd95c263`.
Seed, formats, baseline, authored events, deployment and window were unchanged.
No output was overwritten, acceptance threshold lowered or unsupported-app selection
suppressed. Revision-481 output remains an unevaluated intermediate candidate.

Reports outside Git include `generation-v482-execution.json`, `evaluation-v482.json`,
`exact-joins-v482.json`, `browser-overlaps-v482.json`, `bounded-review-v482.json` and
`manifest-verification-v482.json`. Use exact identity joins, not the bounded review's
old 100ms process-join diagnostic. The evaluation retains the prior aspirational
anomaly-rate flag and existing ASA additional-field warnings; no external-parser
certification or new blind authenticity assessment is implied.

The P1 standard-persona launch task is closed. The user's new P2 audit explicitly
covers the entire catalog across Windows, Linux and macOS with specific installs/
tests, including versions, paths, signing, helpers, completion and network attribution.
Four desktop entitlement/runtime models remain provisional; all selected versions
remain simulated catalog releases. Helper breadth, full wrapper/child graphs,
unsupported filesystem behavior, Studio user acceptance and release gates remain
within their separate scopes. Product version stays 2.2.0a4. No commit, push, PR,
merge, installer publication or release-gate campaign was performed.
