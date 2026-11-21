# Engine capability comparison for assessment planning

## Scope and baseline

Read-only engine investigation on November 20, 2026; this note is the only added
artifact. Compared stable `v2.1.2` with current `dev` at `b1c78393` (behavior
revision 533). `gh release list` confirms v2.1.2 (September 24) remains Latest;
v3.0.0rc1 and the 2.2 alphas are prereleases. No generation, evaluation, tests,
scenario edits or blind review were run for this comparison.

## Capability delta

- **New simulated platform:** bounded macOS 27 arm64 workstations in mixed fleets.
  Target admission is independent of the machine running generation. New source
  families include native Endpoint Security v11 process/selected file NDJSON,
  selected Unified Log messages and interactive zsh history; Mac eCAR and shared
  sensor/server evidence correlate through canonical events.
- **POSIX process semantics:** retained fork versus same-PID exec identities,
  explicit argv/environment, process groups/sessions/TTY, credentials and audit
  origins, event-time ancestry/responsibility, descriptors, loaded executable and
  script identities, and explicit known normal/signal outcomes. Native Mac
  observations project these facts; they do not independently invent them.
- **Qualified Mac producers:** fresh Terminal/iTerm2, Finder application launches,
  selected Chrome/Code helper roles with resident reuse, SSH clients and non-PTY/
  explicit PTY receivers, and selected system jobs. Catalog availability does not
  establish arbitrary helper or launch-method support.
- **Authored Mac control:** `process.launch_method: finder`, bounded `denied`,
  `exec_failed`, `policy_refused` outcomes, `ssh_session.pty`, and
  `macos_launch_item` write/bootstrap/activate/exit/unload/remove stages. Launchd
  definitions, leader/descendant ownership and cleanup persist through recovery;
  general launchd Unified Log and native plist artifacts remain unsupported.
- **Selected native file telemetry:** a live qualified Code document workload
  shares file/content/inode identity across eCAR and ES create/close/rename/unlink.
  Generic file effects/downloads/SMB do not automatically get these native rows.
- **Coverage and recovery:** independent complete modeled process-start census,
  explicit unknown-exit accounting, exact native filtering/checkpoint recovery,
  and source deployment/observation overrides extended to the Mac sources.
- **Windows/Linux and shared evidence upgrades:** session-specific Windows SMSS
  ancestry and browser versions/User-Agents; Linux pipeline child expansion and
  parent lifetimes; logind allocation and sysstat schedule repairs; browser reuse,
  endpoint attribution and interactive-history ownership; scheduling on non-hour
  boundaries, sub-second and collection-window lifecycle fixes; protocol, mail,
  firewall/NAT and source-timing corrections. These extend existing families.
- **Ground truth and evaluation:** schema 5 occurrence/consequence/source-expectation
  JSONL, strict authored-intent accounting and replayable command derivations;
  fifth Ground Truth Agreement pillar with 95% acceptance gate. Corpus-wide
  evaluation can spill to disk under a memory budget instead of fixed corpus caps.
  Earlier bundles retain legacy evaluation semantics.
- **Reproducible input workflow:** optional project/scenario configuration contexts,
  Schema 3 immutable authored scenario/pack releases and frozen queued inputs.
  Studio and portable installers are major delivery changes, separate from the
  simulated telemetry capabilities.

## Important changes after rc1

- `a503e96b`: data-driven Linux/macOS foreground lifetime convergence. Mac qualified
  profile timing, app bundles and long-lived catalog apps retain their exceptions;
  other commands now complete and release their shell. Listeners, followed output
  and bare interactive shells remain unbounded subject to lifecycle ownership;
  `env` follows its wrapped executable. Listener matching no longer mistakes
  `truncate` or `rsync -l` for listener intent.
- The same commit removes executable self-creation after launch. Installed images
  and images already produced by storyline actions are reused; launch waits for an
  image still being produced. Otherwise the launching parent creates it just before
  execution, with `implied_image_create` provenance and a validation info notice.
  Windows curl.exe/certutil/BITS/PowerShell and copy/move output recognition improves.
  SMB work that would outlive its client session is skipped.
- `7b2c539e`: compatibility RDP sessions execute storyline commands without requiring
  eCAR/reconnect-manager ownership.
- `ae8bff6e`: canonical network-sensor identity prevents hostname-case-dependent
  UID, capture-policy and ground-truth disagreements.
- `38337de6`: validation rejects authored logoffs without an earlier possible
  storyline owner; retired Mac iteration variant resynchronized with canonical input.

## Assessment implications and limits

Canonical `scenarios/iteration-test` already contains two Mac workstations, native
sources, Finder, policy refusal, PTY SSH and launch-item stages; Mac coverage is
not starting from zero. A complete capability-to-event/probe audit is still needed.
Next review should especially check sequential foreground completion, download/
copy/redirect then execute, implicit versus explicit image creation, long-lived
controls, process identity through exec, teardown and recovery/filter equivalence.

Do not infer arbitrary shell-string execution, complete app helper graphs, general
Unified Log or filesystem coverage, Mac SMB serving, Intel/Rosetta, sleep/wake or
native binary archives. Known Mac exits include declared model assumptions; an
unknown outcome remains unknown. The current lifetime table does not interpret a
`sh -c` payload to infer its duration. DNS-tunnel originating-process attribution
is still durable backlog work. Passing completeness/evaluation is not an independent
native-authenticity claim.

## Evidence

- `CHANGELOG.md`, v2.1.2 through v3.0.0rc1, and Git history/diffs to HEAD.
- `docs/macos.md` and the current capability matrix (prefer the guide over dated
  historical matrix entries when scope has subsequently advanced).
- `src/evidenceforge/models/scenario.py` and canonical POSIX process occurrences.
- `config/activity/process_lifetimes.yaml` and `executable_provenance.yaml` under
  `src/evidenceforge/`, their loaders, and the November 19 convergence worklog.
- November 17 ground-truth acceptance and November 11 streaming-evaluation worklogs.
- Canonical and retained Mac iteration-test READMEs and current scenario YAML.

## Scenario realism-coverage audit (November 20)

The follow-up request is about the realism of rendered logs, explicitly excluding
crash/functional qualification. Read the canonical scenario, both YAML includes,
current expert briefing/personas, latest retained loop-98 synthesis and endpoint
review, and the native document-workload eligibility code. No scenario changes,
generation or new assessment were performed.

### Existing authored exposure

The scenario has 120 storyline/red-herring groups containing 222 typed entries
(bulk entries can expand into many occurrences). Of these, 57 groups/93 entries
target the two Macs: 55 process intents, 20 launch-item stages, six logoffs, six
portal connections, four logons and two SSH sessions. These are authored counts,
not generated-record counts or proof of reviewer coverage.

- Windows/Linux retain extensive intrusion, remote auth, command/process, SMB,
  database dump/archive/SCP, C2, scanning, DNS, firewall, proxy and mail exposure.
- Macs deliberately expose local Terminal/iTerm2 queries (14 task groups), Finder
  applications, Chrome main/renderer/GPU/network helpers, repeated portal use,
  policy refusal, Mac-to-Mac non-PTY and PTY SSH and Mac-to-Linux administration.
- Both Macs have persistent root shells and the same inventory launch job, each
  with write, bootstrap, three short successful activations, unload then remove.
- Mac SMB mounts exist to Windows and Samba shares, but all 20 authored SMB
  operations belong to non-Mac groups; Mac operation exposure relies on baseline.
- Native ES/ULF, eCAR and Bash/zsh histories are selected. Existing fork/exec,
  audit/credential/TTY/descriptor fields are exercised by qualified launch and SSH
  paths even though they are not separate authored event types.

### Recommended scenario changes, in realism-value order

1. **Add a coherent download-to-execution sequence, starting on a Mac, with compact
   Windows/Linux counterparts.** Existing curl use is upload, and the encoded
   PowerShell DownloadString does not establish a saved-image-then-execution chain.
   Use the exact produced path, a plausible permission step on POSIX, the real
   launching parent and subsequent shell work. Review file-before-exec ordering,
   creator/parent attribution, image/hash continuity where observable, transport
   and transfer accounting, command duration, natural exit and shell reuse. Compare
   with existing installed-tool launches; do not fabricate a fresh creation for
   every installed image. One Mac sequence can use the existing root foothold;
   preserve normal-user local/SSH examples to retain their different identities.
2. **Provision and visibly launch VS Code on one Mac for an engineering work
   period.** Explicit application lists currently omit `vscode` on both Macs;
   the native filesystem workload accepts only live qualified `vscode` executions.
   Word and Documents queries cannot trigger it. This leaves the new ES document
   create/modified-close/atomic-replace/unlink family without an eligible actor.
   Assess actual produced save sequences against eCAR actor/path/inode identity,
   pre-operation rename/unlink metadata, timing and process lifetime. Saves and
   cleanup are probabilistic; verify rendered presence before claiming coverage,
   without turning every probability to one or manufacturing native rows.
3. **Replace a few repeated Mac query groups with ordinary multi-step engineering
   work.** Keep short queries, but include a transfer/archive or supported script
   followed by another command, and a purposeful longer-lived observation in a
   separately owned terminal/session where supported. Existing root shells/GUI
   apps already provide persistent lifetimes. Judge duration texture, foreground
   serialization, parent/exec continuity and logout effects; do not add one example
   per lifetime-table rule or infer execution inside arbitrary shell strings.
4. **Add a small explicit Mac mounted-share workflow.** Reuse existing mounts for
   a credible read/save or artifact handoff to Windows/Samba. Judge client/server
   paths and principals, helper lifetime, protocol/auth and network evidence.
   Do not require ES file records from SMB, which the bounded native workload does
   not supply. This makes assessment less dependent on sampled baseline operations.
5. **Diversify one of the duplicate launch-item lifecycles.** Keep one ordinary
   unload-then-remove sequence. On the other, remove the on-disk definition while
   retaining the registered job, then explicitly activate and eventually unload
   it. Review whether observable execution and file effects preserve that distinction.
   The current short `sw_vers` jobs already expose known exits; arbitrary surviving
   descendant graphs, new daemon families and launchd ULF are not prerequisites.
6. **Optional: add one supported returning-exec-failure continuation.** Current
   `policy_refused` does not cover `exec_failed`/`denied`. Only add an additional
   outcome if it supplies distinguishable collected evidence: the caller continues
   and later does real work, without a fabricated successful child or its effects.
   An absence with no positive source evidence adds little to a blind realism panel.

### Assessment method changes

Loop 98 endpoint review examined 17 representative records and two exact process
pivots; its explicit limits exclude exhaustive job, policy, history and session
analysis. Its good score does not establish those families were assessed. Keep
the four broad reviewers and add a structured coverage accounting for complete
observed process/file/session sequences, including the new sequences above and
baseline examples. Reviewers still receive logs only, not scenario IDs, ground
truth, intended outcomes or prior findings. Neutral instructions can request
observed download/execution, save and remote-session pivots without revealing
which artifacts are authored. Record families not found/not examined separately
from realism findings; missing coverage is not itself a synthetic indicator.

Keep source-native semantics central: native ES versus eCAR versus ULF versus
interactive history, process lifetime versus successive executable versions,
known versus unknown outcomes and source-dependent observations. Ground-truth
agreement can help the coordinator identify omitted authored activity; it must
not supply the blind verdict or be confused with an authenticity score.

Do not add installer, Studio, memory-spill, config-publication or checkpoint failure
matrices to this scenario. They do not add realism-bearing behavior to raw logs.
Do not automatically raise the deliberately low baseline or add failures to make
the story look messier. Revisit baseline only for demonstrated source volume,
distribution or background-behavior issues. A six-hour window can assess local
pacing and lifecycle relationships, not weekend/weekly distributions. Keep the
six-hour core; a longer companion can address temporal realism separately if needed.

The first three scenario changes plus deliberate sequence review offer the most
value before another assessment loop. The remainder can be small follow-ups,
preserving broad existing Windows/Linux/network/mail coverage.

## User decisions and isolated candidate

The user approved cross-platform download/execute/follow-up activity, VS Code on
one Mac, replacement of repetitive Mac queries and explicit Mac mounted-share
read/save activity. They rejected changing Mac launch-item lifecycles and reviewer
requirements. This supersedes the earlier proposed assessment-method changes:
reviewers must remain free to judge authenticity without targeted examination
requirements or attention directed toward specific deficiencies. No reviewer
instructions or skills were edited. The optional failure-outcome addition was
not selected and is not included.

Implemented only in `scenarios/iteration-test-realism-candidate/`, a copy of the
five authored input/briefing files with fresh README/provenance. Original includes,
corpus and relative references are preserved; old generated bundles, ORIGIN data,
scores and review history are not adopted as candidate evidence. The new origin
record captures the actual source-file hashes. Three existing Mac task groups
change, and six groups add two local logons, Windows/Linux downloads, the Code
launch and mounted-share work. Mac curl uses its configured canonical Homebrew
path. Download HTTP evidence stays owned by automatic command URL expansion.

The final candidate validates with no errors; eight retained warnings comprise
the five inherited low-baseline/warmup warnings plus three missing-sibling URL
warnings for automatically inferred downloads. Successful exact composition uses
`package:evidenceforge:industry:technology@1.0.0` with digest
`11e90fb8aa02c2a97d55b6a90fb9b7c192470215174f10f2832da6c253c62928`.
Scenario 2.0, seed, time window, low baseline, topology, source selection, original
attack/red-herring groups and both Mac launch-item lifecycles remain unchanged.
No generation, evaluation or realism verdict is claimed for the candidate.

## Candidate loop 1 generation attempt

The user subsequently requested generation and one assessment loop with unchanged
reviewer instructions, isolated from the canonical benchmark. Artifacts are under
`scenarios/iteration-test-realism-candidate/blind-test/loop-1/`. Validation passed;
the seed-42/default-target behavior-533 generation failed in collection hour 1
with exit 21 and `foreground_shell_unavailable`. No complete authoritative bundle,
evaluation or blind review exists. Preserve the failed `bundle/` and diagnostics;
it has no committed recovery point. No scenario or engine changes were made.

The rejected intent is the Mac download sequence's follow-up `ls`. Its preceding
noninteractive `/bin/bash .../connector-check.sh --check-config` inherits the Mac
catalog's unbounded long lifetime. Read-only reproduction returns 1–8 seconds for
the shared POSIX and Linux classifiers, unbounded for macOS, while the interactive
shell predicate returns false. Owner: `_macos_foreground_lifetime` in
`generation/activity/process_helpers.py`. The failed attempt's report and
`generation-diagnosis.json` retain exact identities and evidence. No synthetic
score is inferred from this functional failure.

Requested user approval to expand the assessment into a focused engine repair
and retry of the unchanged candidate. The four existing reviewer prompts were
prepared in a neutral temporary location with no targeted additions, but no
reviewer has received the partial data. Canonical artifacts remain untouched.

### Approved lifecycle correction and retry

The user approved the focused engine repair and retry. Family owner is shared
Mac foreground lifetime policy, upstream of process execution and native/EDR
rendering. Invariant: noninteractive shell commands obey the configured POSIX
command lifetime table, while interactive shells and explicit keep-alive intent
remain unbounded. Storyline, baseline and SSH command paths consume this owner;
native ES, eCAR and histories consume the resulting lifecycle. No emitter-level
timing adjustment or scenario change is involved. Other long-lived catalog apps
and qualified short-command timing retain their existing policy.

`process_helpers.py` now recognizes configured shell executable names before the
generic long-profile exception and delegates their command semantics to the shared
table. Regression cases cover Bash/zsh scripts, `sh -c`, and env-wrapped Bash;
existing interactive/listener controls stay covered. The focused lifecycle suites
passed 162 tests. Ruff check/format and behavior-surface validation pass; behavior
revision 534 declares the localized output change. The first broader test command
used a nonexistent behavior-test filename and collected nothing; it was corrected
to `test_generation_behavior_manifest.py` for the actual run.

Fresh output is `loop-1/retry/bundle`; the failed original `loop-1/bundle` remains
preserved. Retry provenance records behavior 534, code-diff hash and matching
candidate source hashes. The original input remains unchanged.

The repaired engine then completed all six simulated hours, but native coverage
finalization rejected `/usr/bin/tar` (52/53 execs on the first Mac). This is an
authoring mistake in the added workload: tar is not a qualified native command
in this scope. The failed retry is preserved. Corrected the same two replacement
groups to use the already downloaded Bash diagnostic script plus resolver checks,
and dscl/find/du configuration/document work. A provisional plutil invocation was
rejected at validation and replaced with the already qualified dscl executable;
that validation-only attempt is also retained. No native coverage relaxation,
renderer workaround, new launch-item lifecycle or reviewer instruction was added.
The four approved scenario changes remain represented. Fresh validation again
passes with zero errors and eight documented warnings; output is now isolated
in `loop-1/retry-3/bundle` with new candidate hashes recorded there.
The download-ownership and behavior-manifest suites additionally pass 35 tests.

### Completed generation and quantitative evaluation

`retry-3/bundle` completed successfully with behavior 534, seed 42, default
target, no OOB hosts and the unchanged exact technology-pack digest. Rendering
and final publication took substantially longer than simulated-hour execution;
staged source files continued growing and the run was allowed to finish. Its
completion manifest and resolved input are intact. Evaluation exited 0 and
verified bundle integrity: 142,155 records, overall 98.363482, all applicable
hard requirements PASS, and Ground Truth Agreement 96.895453. Other pillars:
Parseability 100, Plausibility 96.827800, Causality 99.532923, Timing 98.561234.
The text report was rendered from saved JSON without evaluating a second time.

The four reviewers were launched independently with `fork_turns: none`, exact
existing briefing/persona text and standard existing context boilerplate, no
targeted instructions and no candidate identity or quantitative results. They
received a neutral temporary data-only copy of 117 files (84,569,888 bytes),
verified byte for byte against the completed bundle and checked to exclude
generator metadata, ground truth and scenario/briefing files. Source instruction
hashes remain unchanged. Canonical source hashes still match the original copy.

### Completed candidate loop 1

Initial independent reports: Threat Inconclusive / confidence 83 / synthetic 46;
Detection Inconclusive / 84 / 47; Network Real / 66 / 27; Host Inconclusive / 78 / 35.
Mean synthetic-confidence is 38.75 (mostly realistic). All four reports preserve
the existing structure and separate confidence fields. No hard contradiction was
established. Verdict disagreement triggered the existing deliberation process;
the four experts supplied actual written revisions before a fresh facilitator
summarized them. Final positions are unanimously Inconclusive: Threat 87/52,
Detection 88/47, Network 84/44, Host 84/45 (confidence/synthetic). Final mean is 47.
Initial and deliberation results remain distinct in score artifacts and reporting.

The highest-priority distribution concern is eight machine-account/source pairs
with 721 of 795 successful TGT events (82–109 per pair). Four native PowerShell/
SSH parent-child pairs also share exactly 4.334-second delays. Weaker observations
are six Mac cat-based Office/PDF reads, 58/95 normalized Mac fork/first-exec gaps
of 1 ms, and a 35-query/17-client late TXT burst. Operational alternatives remain
viable; none is promoted to impossible behavior. Post-panel coordinator checks
confirm the top-eight TGT count, four SSH intervals and six cat execution rows.

The final report, verbatim initial reviews, actual deliberation responses,
facilitator summary, full/text evaluation, provenance, attempts, verification and
canonical scores JSON are isolated in candidate `blind-test/loop-1/`. The
candidate-only one-loop SVG dashboard uses initial scores only and parses as XML;
38.75 is its rolling mean with n=1, not evidence of a trend. No canonical output,
reviewer requirement, launch-item lifecycle or score history changed. Candidate
was not promoted and no additional loop or finding-driven code fix was run.

## Canonical promotion and history reset

Promoted the approved candidate to `scenarios/iteration-test`, retaining its
activity but restoring the canonical name and destination. The new history is
empty, epoch `2026-11-20-realism`, and starts at loop 1; no scores are inherited.
Validation and exact composition pass with the same eight documented warnings.

User clarified that preserving a previous version means YAML inputs only, not
archiving datasets/findings/reports. Previous scenario.yaml and required YAML
includes are therefore the only files in `iteration-test-previous-2026-11-20`.
Existing old output/history files remain in `iteration-test-retired-history`
pending a deletion instruction; none were deleted or duplicated. The initial
overly broad archival arrangement was corrected. Approximate allocated usage:
older assessment roots 9.68 GiB, of which identified generated data trees account
for 9.58 GiB; candidate trial 292 MiB, plus this chat temporary review copy 81 MiB.
These totals exclude unrelated generated exercises and Git object storage.
