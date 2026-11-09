# macOS realism follow through

The user authorized public research into OS and catalog application helpers,
root-cause repairs for task pacing/browser instances/application attribution,
Studio fixes, and a packaged Mac-native generation/evaluation smoke. The user has
now agreed to plan focused process and filesystem reference collection on a second
macOS 27.x system accessible over SSH. Native file-event admission depends on that
reference evidence. Release gates and the product documentation
revision pass are deferred until these items are addressed. Existing local
assessment artifacts and the integration hold remain preserved.

## Owning contracts

- Pacing: baseline process activities redundantly reserve the shell at the
  command's lifetime upper bound after the process bundle has already sampled and
  registered its real canonical completion. Editors with a 95-second upper bound
  consequently repeat on an approximately 96-second grid. Remove the redundant
  reservation; retain completion, shell-release, pipeline and session ownership.
  This specific measured finding is Linux developer activity in the mixed fleet,
  not a demonstrated Mac-only defect.
- Browser instances: existing reuse is Windows-only and can pick an unrelated
  browser family. Resolve the requested executable and modeled/explicit user-data
  directory without querying the host, share that rule across supported platforms,
  and allow ordinary Mac Finder launches to consume the existing reuse owner.
  Authored fresh process intent and helper starts retain their explicit semantics.
  Reusing a main process must not repeatedly spawn its startup helper tree.
- Attribution: process identity must constrain inferred application requests before
  headers, wire sizes and proxy affinity freeze. Preserve explicit request intent
  and header overrides. Do not invent a Zoom agent string or blank a header merely
  to clear a probe. Investigate the generic TLS-to-browser-request inference.
- Studio: expose a compact saved host census, preserve unmeasured historical exits
  and partial collection, and correct the Mac help text. Generic evaluation PASS
  does not replace the dedicated native census.
- Packaging: exercise a small invented Mac workload through the actual CLI passed
  into packaged-runtime verification, including native ES/ULF, shell history,
  canonical census and authoritative evaluation. No release publication is implied.

## Research direction

Apple distinguishes system daemons, per-user agents and app-scoped on-demand XPC
services. Their parents, principals, triggers and lifetime owners differ; they
cannot all be modeled as children created whenever an app opens. Source:
[Apple XPC](https://developer.apple.com/documentation/XPC),
[launchd lifecycle](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/Lifecycle.html).

The initial catalog inventory contains 48 non-OS Mac application IDs plus native
OS, terminal, SSH and helper identities. Research should group related runtimes
while checking each installed catalog variant. Existing Chrome/Terminal/iTerm/SSH
native contracts provide the first safe implementation surface. Exact unqualified
helper signatures, argv, descriptors and lifecycle facts must remain unavailable.

Useful public sources already identified:

- [Chromium user-data directories](https://github.com/chromium/chromium/blob/main/docs/user_data_dir.md)
  and [process singleton](https://chromium.googlesource.com/chromium/src/+/master/chrome/browser/process_singleton.h).
- [Firefox process model](https://firefox-source-docs.mozilla.org/dom/ipc/process_model.html).
- [Electron process model](https://www.electronjs.org/docs/latest/tutorial/process-model)
  and [utility processes](https://www.electronjs.org/docs/latest/api/utility-process).
- [VS Code extension hosts](https://code.visualstudio.com/api/advanced-topics/extension-host).
- [Docker Mac helper permissions](https://docs.docker.com/desktop/setup/install/mac-permission-requirements/)
  and [network ownership](https://docs.docker.com/desktop/features/networking/).
  Current documentation explicitly versions its older privileged-helper behavior;
  do not apply it automatically to the catalog's selected older release or confuse
  Docker's CLI executable with the Desktop backend and its Linux VM processes.

## Native file telemetry decision

Current eCAR file observations already describe modeled file activity. Adding
native Endpoint Security file evidence would create an additional source-native
view linked to the same process execution and file identity. A possible bounded
slice is create, rename, unlink and modified-close. It is separate from generating
actual file payloads, plist artifacts, a logarchive or an APFS image. Historical
wire decoders do not qualify current-version generation. Reads, atomic replacement,
memory-mapped writes and metadata changes need additional semantic contracts.
No native file-event source is enabled by the completed implementation slice.

For a bounded follow-on, Apple documents separate
[create](https://developer.apple.com/documentation/endpointsecurity/es_event_create_t),
[rename](https://developer.apple.com/documentation/endpointsecurity/es_event_rename_t)
and [close](https://developer.apple.com/documentation/endpointsecurity/es_event_close_t)
records. Create/rename destination shapes depend on whether the destination
already exists; close carries `modified` and writable-mapping information. Those
are distinct operations, not interchangeable renderings of a generic file write.
One high-level save may involve a temporary file, modified close and rename over
an existing path. A download may be performed by a background service rather than
the visible GUI process. Canonical file-operation bundles must own those facts,
stable device/inode identity and metadata before any native emitter renders them.

Recommendation: treat bounded native create/rename/unlink/modified-close support
as a separate capability decision. It is useful for native file-focused exercises;
existing eCAR file evidence remains useful for the current bounded process/network
scope. No recommendation here implies an APFS/FSEvents artifact, universal reads,
all save workflows, or unqualified current-build wire metadata.

## Implemented changes

- Removed the baseline lifetime-maximum shell reservation, independent guessed
  history dwell for process-owned catalog commands, and the second completion
  sample. The existing canonical completion now controls readiness, followed by a
  data-driven 0.8–18 second modeled think interval. Command accounting and session
  activity still belong to the session at the final scheduled submission time.
  A repeated-editor regression exercises actual starts and terminations rather
  than checking only a helper's return value.
- Browser reuse resolves executable and modeled/explicit user-data identity
  across Windows/Linux/Mac from YAML defaults and live canonical processes. It no
  longer substitutes another browser family. Ordinary Finder launches may reuse
  a main; authored fresh starts retain their explicit semantics. Later navigation
  does not move back to the main process's original start timestamp. Literal POSIX
  argv parsing preserves explicit directories with spaces after canonical quoting;
  malformed or ambiguous options cannot silently reuse the modeled default.
- Qualified Chrome helpers consult exact live parent object identity and roles.
  GPU/network residents are reused; a later renderer is allowed. No new OS or
  vendor-native family is enabled. Research covers all 48 non-OS catalog IDs with
  concrete component leads, qualified first steps and unresolved build facts in
  the [research record](../design/macos-workstation-feasibility/background-process-research.md).
- Fixed the service-to-executable case loss that excluded `Google Chrome` and
  `Microsoft Outlook` from compiled Mac inference while retaining `zoom.us`.
  Inferred browsing selects installed browsers. Explicit application bindings and
  supplied HTTP headers remain authoritative. Header inference happens before
  request byte accounting and affinity; a bare owned nonbrowser CONNECT no
  longer acquires an invented desktop-browser agent.
- Studio's saved scorecard now projects compact per-host native fork/exec/exit
  census data. Start completeness, exit completeness, unknown results, historical
  unmeasured results and partial collection stay distinct. Updated the supported
  ULF/complete-coverage help and removed an incorrect example OS build number.
- Added `tests/fixtures/scenarios/macos-native-smoke.yaml` and a shared installed
  CLI generation/evaluation verifier. The isolated packaged-runtime check already
  called by native CI now uses the same workload. It requires positive ES v11,
  ULF/history evidence, `id`/`sw_vers` execution, complete start/exit census and
  authoritative evaluation acceptance. This is an automated simulated-data smoke,
  not live host telemetry collection. No new installer was built in this session.
- Declared material generation behavior revision 472; product version unchanged.

## Validation

The implementation slice and focused verification are complete. Additional OS and
vendor-native helper families remain research/qualification work, not enabled
capabilities. Release gates and the product documentation revision pass remain
deferred by the user. No release campaign, new native capture or blind assessment
loop was started.

- Core process/planner/header/Studio coverage/helper/behavior selection: 661 passed,
  2 deselected, including canonical argument quoting and session accounting.
- Related process, foreground, browser, proxy/network, native helper, behavior and
  Studio service/assets contracts: 253 passed (some behavior tests overlap the
  preceding selection).
- Installed/source CLI Mac smoke and combined exact checkpoint/resume/native-only
  filter equivalence: 2 passed, 56.09 seconds after the final browser quoting fix.
- Studio frontend: all 348 tests pass; generated types check and production build
  pass. Build retains the existing large-chunk advisory.
- Configuration validation: 101 files, zero errors/warnings/info.
- Ruff check and full formatting check pass.

## Second Mac collection plan

On November 6 the user offered a second macOS 27.x system for agent-driven
collection over SSH. This supplies the next reference host; the earlier stopping
rule for launchd ULF and the privacy boundaries around existing personal-Mac
captures remain intact. The supplied SSH target has now passed connection and
architecture preflight; the user has completed privileged collector setup. This
plan covers new, bounded experiments on the second host. It does not reuse private
capture directories from the original host or reopen launchd ULF collection.

### Host preparation and preflight

- Use the supplied SSH alias/host and key-based authentication. Record the exact
  OS version/build, hardware architecture, native event version and selected app
  versions. Compare them with the existing macOS 27 arm64 profile; a different
  build/app version is its own evidence target rather than assumed catalog parity.
- Prefer a dedicated test account with an active desktop login, invented workspace
  files and fresh app profiles. Keep personal cloud accounts and existing work out
  of the exercises. GUI starts must execute in the intended desktop session, with
  actual launch method and audit/parent/responsible ownership checked explicitly.
  An SSH invocation alone does not qualify a Finder launch.
- The user supplies initial OS privacy grants and a way to perform the bounded
  privileged collector start. Apple documents that eslogger requires superuser
  execution and Full Disk Access for its responsible process, including SSH:
  [Endpoint Security tooling](https://developer.apple.com/videos/play/wwdc2022/110345/?time=488).
  [Remote Login](https://support.apple.com/en-au/guide/mac-help/mchlp1066/mac)
  has a separate full-disk-access option. Verify a harmless readiness control on
  the actual host before capturing a workload. Do not assume sudo alone establishes
  collection readiness or grant broad passwordless administrator access.
- Check installed selected applications, compiler tools and collector capabilities
  before preparing the executable kit. App installation/first-run setup and privacy
  prompts are host preparation dependencies. Verify GUI launch control and cleanup
  independently of collection before combining them.

### Initial finite matrix

| Family | Controlled exercise | Evidence sought |
| --- | --- | --- |
| Filesystem primitives | In one owned scratch directory: create/write/close, unmodified close as a control, rename to a new destination, replace an existing destination, unlink | Current native shapes, actor execution linkage, source/destination variants, file-object identity/stat transitions and operation order |
| VS Code | Fresh profile and invented local workspace; initial window, second window, one file save, ordinary quit | Main and helper roles, reuse, actual launch/parent/audit/responsible ownership, argv/FD/environment shapes and observed completion |
| Shared OS services | Observe Dock and the selected preferences/DNS/trust services before and during controlled desktop activity | Exact installed identities, launch domains/principals and resident/service ownership; native births only when genuinely observed |
| Docker Desktop | If installed and initialized: start, readiness, one disposable controlled workload if needed for attribution, ordinary quit | Actual host backend/helper graph, installed version/VM configuration and host-versus-Linux-VM ownership |

Start with filesystem primitives and VS Code, then the OS set and Docker. The
current Docker CLI catalog entry does not imply Desktop is installed. Existing
Docker containers and user workspaces are outside the exercise. Keep local/remote
VS Code extension placement and Docker host/guest activity separate. A resident
service snapshot qualifies resident facts, not an unobserved startup or exit.

The initial filesystem generation scope remains create, rename, unlink and
modified-close. A VS Code save qualifies only the observed save workflow; reads,
memory mapping, cross-volume moves and other applications remain independent.
An unmodified-close control does not introduce a native file-read capability.

### Remote runner and retained evidence

Build a fresh SSH-compatible runner from the existing collector/probe mechanisms.
The older kits have human-only entry points and local network-disconnection
instructions; their procedures cannot be reused unchanged for remote automation.
SSH remains reachable throughout, and invented content uses local services.
Inspect the remote runner code and test with invented records before deployment.

- Start with one readiness control and two bounded runs per selected workflow.
  Initial per-run ceilings: filesystem 30 seconds, OS observations 60 seconds,
  VS Code 90 seconds, Docker 180 seconds; at most 64 MiB of retained evidence per
  run. Specify finite candidate-buffer, input-line and record-count caps in the
  kit manifest before execution. Hitting a cap is reported as incomplete evidence.
- Stream native events into a bounded in-memory filter. Persist only the exact
  test execution graph and scratch-file operations, with identity-bound ancestry
  needed to explain them. App names, PID alone and broad path prefixes are
  insufficient selectors. Unrelated activity is discarded before persistence.
- Store raw references and provenance in a new owner-only directory on the second
  Mac, outside Git and synced storage. Run bounded local checkers there. SSH returns
  technical summaries, fixed diagnostics and opaque aliases; raw event/environment
  values and unrelated process listings are not sent into chat or committed.
- Preserve exact OS/app/profile versions, collector configuration, source/tool
  hashes, case inputs, event-version observations, control results and truncation
  status. Keep observed records unchanged. Derived reports and invented regression
  fixtures are separate from the raw evidence.
- An independent deadline guard stops owned collectors and helpers even if SSH
  disconnects. Cleanup targets only this run's verified resources and reports its
  result. Verify normal quit and post-quit helper observation explicitly; helpers
  still alive at the window boundary have a censored lifetime, not an invented exit.
- On failure, use one targeted bounded diagnostic, then report the remaining gap.
  Do not expand automatically into repeated broad captures or another assessment
  loop. A missing event is inconclusive unless delivery and workload controls
  establish the narrower conclusion.

### From references to implementation

Extract the observed contracts into the owning deployment, action-bundle,
process/session and file-state layers. Reuse service instances and exact process
executions across their evidence. Enable only operations/launch methods supported
by the target reference, render through existing native ingress, and retain
unsupported outcomes as unknown.

For each admitted slice, add invented source-shape and lifecycle/correlation
regressions, positive and negative capture-checker controls, and targeted exact
checkpoint/filter verification. Native source loss and intentional filtering are
separate. Public constants and synthetic fixtures can enter Git; captured host
identifiers and raw records remain remote. Finish the deferred product documentation
pass after these increments; release gates remain later work.

### SSH preflight and collector staging

The user supplied `biancomac-d.local` and authorized using their real SSH client
and existing key. The sandbox's first attempt could not resolve its `.local` name;
the authorized host SSH invocation outside the sandbox connected successfully.
No host-key checking was disabled and no password or private key was requested.

- Target: macOS 27.0.1, build 26A434, arm64; the remote account also owns an active
  console login. Command Line Tools and `/usr/bin/eslogger` are present.
- Selected installed apps: VS Code 1.143.0 and Chrome 157.0.8103.38. Their releases
  need independent qualification against the current frozen catalog. Docker was
  not found at `/Applications/Docker.app`; no broader app inventory was performed.
- Built-in Python is 3.9.6. The future remote runner must be standalone/compatible
  or ship a selected runtime, rather than assuming the project's Python 3.12 exists.
- Both `sudo -n true` and a non-interactive policy query for the collector required
  interactive setup. Full Disk Access and actual native event delivery are therefore
  not yet established. No collector, GUI workload or filesystem exercise was run.
- Prepared a new fixed-command guard in
  `docs/design/macos-workstation-feasibility/remote-reference/collector_guard.c`.
  The production guard requires root, accepts only two modes, has independent
  30/180-second ceilings, stops on pipe closure/signals and reaps its fixed child.
  Tests use only an invented collector binary, not any ES/native process capture.
- Staged and compiled the production guard unprivileged in the remote code-only
  kit `/private/tmp/eforge-remote-reference.RiKEy0`; its source hash matches the
  repository copy. A staged narrow sudo policy passes `visudo -cf`. Neither policy
  nor privileged helper is installed. One-time setup and removal commands are in
  the [remote collector instructions](../design/macos-workstation-feasibility/remote-reference/README.md).

Six invented-input guard tests pass, covering deadline, cancellation/stop, reaping
and rejection of arbitrary commands. Full Ruff/format and whitespace checks pass.
The reviewed setup commands are also staged as `enable-collector.sh` and pass
remote shell syntax validation. An asynchronous setup request explains the
unavailable non-interactive sudo and points to that specific script. It has not
been executed by the agent. The next dependent step is administrator setup on the
second Mac. The filtered filesystem runner and app-specific filters remain to be
built; privileged access alone does not enable an unfiltered capture.

### Completed filesystem reference collection

The user's setup output passes `visudo`. SSH verification confirms root-owned
helper mode 0755, root-owned policy mode 0440 and non-interactive access to both
literal modes. Actual collection also establishes that Full Disk Access is ready;
no additional privacy grant is currently needed.

Added a standalone Python 3.9-compatible filesystem runner, a fixed scratch-file
C probe, and an offline reviewer. The C probe's SDK assertions independently check
close/create/rename/unlink event discriminants. Native retention requires the
probe's full audit token, birth time, executable file object and exact scratch
names/directory identity. Ambient records are discarded before persistence.
Root collection has a 30-second independent guard, the runner a 20-second exercise
ceiling, and the probe a 25-second alarm. Control files, native references and
hash/provenance records stay remote and owner-only.

Both planned captures completed all eight operations, collector readiness and
cleanup, with zero observed stream sequence gaps/reordering. Each retained 3
creates, 5 closes, 2 renames, 2 unlinks and 1 normal exit in message version 11.
The offline comparison passes actor, create/close/rename/unlink file identity,
native property shape, control and exit checks for both. Source stat semantics:

- Create reports zero size before the subsequent write.
- Write-close is modified, read-only close is unmodified; no writable mapping.
- Rename replacement describes the old destination object, while the source
  object's identity survives at the new destination.
- Unlink reports pre-removal link count, not the eventual zero-link state.

The initial offline shape failure was a Python 3.9 calendar-parser limitation for
nine fractional digits. Calendar-only validation now preserves the source
nanoseconds unchanged; a regression covers that runtime difference. No recapture
or raw-data rewrite was needed. Production native file generation remains pending
canonical operation contracts and explicit admission; the raw collector reports
intentionally retain `reference_admission: NOT_EVALUATED`.

VS Code's installed main is `Code`, consistent with the existing catalog and
Microsoft's documented rename. A first static check incorrectly assumed the old
`Electron` name; this was corrected before launching anything. Inline codesign
requirements also require the leading `=`; with the correct syntax the main and
all four declared helper bundles verify against the Microsoft signer. Unknown
static values and native records were not returned. Docker remains absent at the
standard path. The user asked why it was needed: the proposed experiment concerns
Docker Desktop's Mac helper/backend graph, not a dependency of EvidenceForge or
the collector. Installation is optional; continue without it and leave that family
pending.

### Code first-launch diagnosis and bounded reference results

The user opened VS Code and accepted macOS's downloaded-application confirmation.
They reported that it then closed almost immediately. The authored controls
confirm that the reference extension had saved its invented file, opened the
second window and requested ordinary quit. This was the expected workload close.
Before that approval, LaunchServices accepted requests without creating the fresh
profile's logs or controls. Collector-free driver/event-loop checks and one failed
capture remain preserved; they do not qualify app startup.

After approval, a workflow-successful run still retained no authenticated native
graph. One fixed-predicate diagnostic isolated CDHash string comparison: exact
installed file object/path, signer, profile and workspace matched, while hash
letter case differed. Strict twenty-byte hexadecimal comparison fixes the filter;
arm64 static-signature selection is now explicit. No ownership criterion was
replaced with a PID-only or bundle-prefix match.

The first authenticated run exposed an isolation defect in the experiment: Code's
normal shell-environment discovery ran account startup scripts despite its fresh
editor profile. That run remains preserved and unqualified. Disabling the main
environment lookup alone still left secondary component discovery. The final
driver also supplies an empty ZDOTDIR and controlled launch environment. The root
exec independently confirms these settings; shell startup behavior is outside this
case. No startup scripts or captured environment values were returned into chat.

The final two repeats have immutable per-run tool-source/binary snapshots and
OS/build provenance. A separate offline reviewer checks private artifact ownership,
modes/hashes, exact execution edges, v11 wire shapes, arm64 execs, source ordering,
nonce-linked save/second-window controls and ordinary quit. Both pass:

- One main, two renderers, one GPU and one network helper execution each.
- Six Node utility executions: one shared process, one agent host, two extension
  hosts and two file watchers. Role labels come from predeclared public Code
  entrypoints; no terminal/PTY-host behavior was exercised.
- Thirteen observed fork births and fourteen closed lifetimes, including the
  main's observed exec-to-exit lifetime. Every observed lifetime closes; no stream
  gap or reordering is measured.
- Three other execs include two still-unclassified descendant executables. Their
  private source records are retained by exact ancestry, without inventing a role.

The main's initial fork is **not observed**. Do not claim complete main birth,
guess those two descendant templates, or copy the 1.143.0 reference onto the
existing 1.142.0 catalog deployment. All capture/reviewer reports retain
`reference_admission: NOT_EVALUATED`; reference checking is distinct from native
generation admission. The kit is
`/private/tmp/eforge-vscode-reference.4KJyaE`. The helper stays installed for the
ongoing reference effort; no collector or app workload remains running.

### Wire ingestion increment and checks

The native wire decoder now admits the independently measured v11 create, close,
rename and unlink variants. Close preserves both modified and mapped-writable
flags, including unmodified-close controls; unlink requires its parent directory.
The existing create/rename unions remain bounded to observed variants. Older
source versions do not gain close/unlink support. No canonical operation bundle,
native file emitter or production filesystem generation is enabled by this change.

Invented regressions preserve empty pre-write creates, replacement destination
identity, pre-unlink link counts, strict booleans, required metadata, ingestion
and source nanoseconds. Revision 472 records the decoder admission along with
the earlier pacing/ownership/attribution changes; product versions are unchanged.
The first final check caught an overlong behavior-summary string; shortening it
fixed the manifest and installed-CLI smoke. This was metadata validation, not a
native reference failure.

Final validation: 233 focused native codec/ingestion/manifest/reference-tool tests
and the installed-CLI Mac generation/evaluation smoke pass. Full Ruff, formatting
and whitespace checks pass. Additional raw evidence was not downloaded or added to
Git. Shared OS-service qualification, Code's remaining admission gaps and canonical
filesystem generation remain pending; product documentation revision and release
gates remain deferred as requested.

### Docker initialization, controlled references and remaining limits

The user subsequently installed Docker Desktop, completed first-run setup and
signed in. Sign-in was not needed by the planned experiment. Read-only preflight
verified Desktop 4.98.0 (245422), Linux arm64 Engine 29.9.2, the standard local
socket and zero existing containers. The new owner-only kit is
`/private/tmp/eforge-docker-reference.k6kgpz_e`. No account credential/config file
was opened by the runner; all CLI commands use a new config directory and an
explicit local Engine endpoint. No images or containers were created or pulled.

The initial precondition attempt collected no native rows: Desktop CLI status
reported stopped while the local Engine responded. Fixed read-only diagnostics
confirmed that mismatch under isolated configs, an explicitly local context and
the actual account home. An isolated pointer to the existing control socket did
not resolve it. Do not call this a proven product defect or use that CLI state as
the source of truth. The runner instead uses ordinary macOS application control,
plus independent local Engine readiness/unavailability checks.

An initial successful native run used one application object for quit and lacked
the empty zsh-startup directory. Preserve it separately. Its known root/GUI/build
lifetimes exposed a controller ownership weakness: a single matching application
instance was insufficient, and a subsequent initial-quit check rejected multiple
matches before collection. The reviewed controller now selects a bounded group by
the exact installed root/UI bundle and executable file objects, retains the
application objects, requests normal quit and waits for them. No force quit or
PID-only signal is used. A separate start-only mode leaves no experiment-specific
environment overrides on the restored app.

Final capture profile: a unique run environment marker plus exact signed backend
image authenticates the root, and only its proven fork/exec graph and exact
backward ancestry are persisted. Each fresh run also has an empty ZDOTDIR. The
root is independently corroborated against the application launch control through
the retained signed backend execution chain; a daemon/bootstrap chain need not
make the returned application object the first backend execution in the stream.
The capture ceiling is 150 seconds, inside the fixed 180-second collector guard;
probe and control deadlines are 170 seconds. Native buffers and retention limits
are unchanged from the reviewed bounded process filter.

Both final repeats complete startup, positive guest-engine readiness, empty
inventory, accepted normal quit, application-object termination and Engine
unavailability. Both restore Docker running and preserve installed image hashes.
The independent offline reviewer verifies private artifact modes and hashes,
native v11 shapes, exact retained execution edges, launch ownership, arm64 execs
and ordering. Each observes:

- 55 fork births, 61 execs, 50 terminal lifetimes and six unclosed lifetimes at
  cutoff; no observed stream sequence gap/reordering.
- Three backend executions, one build service, one virtualization executable,
  one Desktop GUI, two generic helper executions and two renderer executions.
  The generic helper role switches cover GPU and network service. Do not invent
  use of the separate named GPU helper binary or infer three resident mains.
- 51 execs outside the selected signed-image inventory. Fixed labels account for
  some standard OS tools; 35 remain unclassified. These are not enabled templates.
- 48 normal native wait results and two signalled results among observed exits.
  An ordinary quit must not be projected as universally successful zero exits.

The six unclosed lifetimes and unobserved graph-root fork remain explicit
qualification gaps. Do not interpret missing exits as proof of continued liveness.
They may reflect timing or an overly strict snapshot/identity filter. A future
lifecycle audit should distinguish those possibilities using independent terminal
controls before changing admission; do not synthesize terminal statuses or force
processes to make a census pass. The empty ZDOTDIR is a zsh lookup control, not a
claim that all signed-in application behavior is account-independent. This
host-only reference does not measure guest processes, network attribution or
filesystem effects. The finite two-repeat collection is complete; no open-ended
capture loop is authorized by these residual findings.

Static inspection also confirms that neither standard privileged helper
`com.docker.vmnetd` nor `com.docker.socket` is installed at its privileged-helper
destination. Their bundled executables or vendor documentation do not justify
creating root helper children on every synthetic Docker CLI or Desktop launch.

The offline summary preserves two earlier profile attempts and one failed
precondition separately, with two final references, zero invalid artifacts and no
run-limit violation. No raw native rows, host identities or captured environment
values entered Git or chat. A final non-capture restore confirms zero containers,
normal quit, Engine unavailability, normal launch without injected experiment
overrides and restored Engine readiness (`NORMAL_RESTORE.json`, remote/private).
Sign-in is unchanged. The fixed root helper remains installed for the ongoing OS
reference effort; no collector or automation workload remains active.

Validation: 74 invented-input collector/filter/reviewer tests pass, including
rejection of wrong run markers, reused identities, unowned children, altered
artifacts, public permissions, incomplete provenance and unknown output labels.
Both Code and Docker controller builds pass the main-queue self-test. Full Ruff,
formatting and whitespace checks pass. No production generation behavior, product
version or release gate changed in this Docker reference increment. Native Docker
admission, shared OS-service qualification and canonical filesystem generation
remain pending.

### Bounded population and native filesystem publication implementation

User authorized the conservative OS/Code expansion, Docker deferral and as much
of the previously scoped filesystem work as practical. This increment reused the
saved Code/filesystem references; no new privileged capture ran. Additional SSH
reads returned only selected public binary metadata and fixed technical classes.
The reference Mac's accounts, normal apps and raw captures were not changed.

**Population.** Mac Code now selects 1.143.0 and owns its main plus independently
qualified generic GPU, network and shared Node helper roles. Code's own signing/
entitlement/runtime facts replace generic Electron assumptions. GPU/network roles
reuse the existing sandbox-pipe contract with selected explicit slots. Shared Node
has a separate descriptor policy: inherited vnode stdin, two distinct transactional
output pipes, no seatbelt argument and its explicit shared-process entrypoint.
Two references each contain exactly one matching shared-process exec with this
layout. Inherited environment markers alone also matched a descendant; the final
review additionally required the exact signed helper and both Node role switches.
Repeated app activity reuses each resident role under the exact main. Synthetic
counts/delays remain configurable nominal policy. Renderer, extension/watcher/
agent/PTY and unclassified descendant templates remain gated.

Root cfprefsd (`daemon`) and launchservicesd now seed one shared inventory member
per host through the existing boot fleet. Their root/init/exact-argument classes
were independently confirmed without starting or restarting them. Only their
selected static signing metadata is added. They precede collection, survive app
activity and checkpoint through normal State ownership. Their runtime validation
is still unknown; inventory does not manufacture an in-window native start/exit
or service-activity noise. User instances and mDNSResponder's separate account
remain deferred. The resident guard rejects attempts to place these unqualified
starts inside collection. No Dock/restart/launchd-ULF collection was attempted.

**Filesystem.** Added an immutable canonical operation observation and a shared
MacosFilesystemActionBundle. Explicit caller/file/parent-directory facts enter
one State + artifact + timing + effect + exact-source journal. Supported native
v11 occurrences are empty pre-write create, modified/unmodified unmapped close,
same-directory rename (including replacement) and pre-removal unlink. A modified
close may publish a new content version while retaining the same object/inode;
rename preserves content/object/inode and exposes the old destination's stat.
The eCAR FILE view shares actor, file/content versions and rename source path.
The renderer owns no stat, file identity, PID, timing or sequence allocation.

Placement guards run while canonical owners are reversible and again within the
registry's commit fence. They reject changed/competing destinations, stale current
versions and backdated/unknown bounded placement history. Exact recovery retains
the source tail after canonical commit; a retry does not recreate the file or
repeat a rename/unlink. Source ingress now admits file families into the same
chronological counter stream without counting them as process births/exits. The
new process/file source profile has its own ID and coherent subscription/counters;
old frozen process-only catalogs remain process-only, including their historical
configuration hashes. Product behavior revision 473 is material; product version
is unchanged.

**Remaining filesystem boundary:** this is a working canonical publication API,
not automatic native output for all existing generic file effects. Most generic
producers still lack complete file-object/allocation and event-time mutable parent
directory facts. This increment deliberately does not invent those facts or turn
a final-size eCAR create into an empty native create. Wiring concrete workload
producers to that API, with directory mutation/checkpoint ownership, remains open.
There is no general authored filesystem schema or universal baseline file noise.
Broader reads, mappings, APFS artifacts and logarchive remain outside scope. The
existing controlled references are sufficient for the admitted operation shapes;
this remaining integration is primarily implementation work.

Validation: the focused native/engine matrix covers 509 distinct routine tests
across the family runs, including the five added frozen-profile/subscription cases
and four added Code Node commit/retry cases. The first 500-test run found 26 stale
GUI fixture assertions expecting only three counter families (474 passed); the
updated 46-case GUI suite passes and asserts all seven subscribed counters. The
69-case source/file suite, eight helper retry cases and final 17-case mixed
Code/filesystem suite pass. Source-tail and artifact failures, replacement races,
chronological placement, eCAR identity, filtered counters and exact checkpoint
native bytes are covered. Mixed installed Code/file output retains the complete
four-fork/five-exec process census; file rows do not become process counts.

Another 73 source/config tests pass. The shared contract/identity/timing matrix
has 108 passing cases after adding the two new closed kinds to the reviewed
constructor census. The extractor now recognizes the filesystem bundle's finite
dynamic domain; only the new event rows/classification decisions were appended,
leaving the historical review inventory and conclusions intact. Full inventory
regeneration would cause unrelated historical churn and was not performed.

The installed-CLI Mac generation/evaluation smoke passes. Full Ruff, formatting,
whitespace and behavior-manifest checks pass. The Mac filesystem publication API
requires an explicitly bound artifact registry; generic engine scenarios do not
acquire one solely by enabling ES. Concrete workload integration must include the
normal engine initialization/checkpoint wiring as well as file/directory facts.
No raw reference data entered Git. Product version remains 2.2.0a4; no commit,
release publication or integration PR was made. The wider documentation revision,
user acceptance and release gates remain deferred.


### Concrete filesystem workload integration

User requested the next integration increment. This section supersedes the
API-only boundary recorded above. Ordinary supported Mac baseline generation now
initializes its shared runtime artifact owner and emits bounded Code-owned
Documents activity through MacosFilesystemActionBundle. There is no test-only
registry binding or emitter-local PID/stat/file creation. Eligibility requires an
actual live installed main with qualified execution facts; the whole operation
must fit its owning session and foreground lifetime. An installed-CLI check caught
a session-end eligibility gap, which is fixed at workload selection. Tasks are
sampled once, paced without overlap and retained as one bounded page on retry.

Configured nominal saves include in-place create/write/close and probabilistic
same-directory atomic replacement and cleanup. In-place writes preserve the file
object/inode; replacements allocate a new object, expose the old destination,
and preserve content through the rename. Unlink withdraws the exact placement
while its retained version remains available. Current-placement leases protect
files through the model window; old placement leases are released idempotently
after authenticated canonical commit. They do not release loaded-image leases.
These are modeled document activities under a qualified app owner, not a claim
that the reference measured Code's actual save strategy or APFS allocation.

State owns the monotonic host inode allocator and mutable directory facts, bounded
to 256 directories per host and 128 observations per directory. Retired history
fails explicitly. Fork/exec obtains current shared stat while preserving immutable
directory identity and original execution snapshots. Directory/inode state rolls
back with failed file publication and checkpoints with current artifact placements
and leases. State head v14 explicitly restores v13 with empty new maps, preserving
its process census, and continues accepting the established older contracts.
Unfinished filesystem pages block a checkpoint barrier until their retained exact
source tails finish; retries do not repeat canonical operations or resample tasks.

The reference Mac initially returned No route to host. Once the user made it
available, two fixed scratch captures completed under the existing collector;
no additional privileges or ambient collection were introduced. New controls at
`/private/tmp/eforge-fs-parent-reference.9avbwqq7` verify pre-operation stat for the
fresh-rename parent, both rename sources, and both unlink sources/parents in each
run. Counts/shapes/identity joins and stream checks all pass. Raw evidence stays
remote. Only the probe's stat controls and offline fixed-label reviewer changed;
collector event lists, deadlines, scratch names and ownership filter are unchanged.

A separate positive filesystem fixture drives all four native event families in
real CLI checkpoint/resume and native-only format-selection acceptance. The
existing installed-runtime smoke retains its stronger complete-exit fixture. The
new longer Code fixture intentionally does not assert a known exit for every
ordinary app cleanup: an unclassified end remains unknown rather than receiving
an invented successful native exit. The typed Finder adapter also canonicalizes
its display command from its parsed argv, fixing quoted app paths with spaces.

Broader authored filesystem schema, generic file-effect conversion, mappings,
read-only-close workloads, wider APFS behavior and logarchive remain outside this
increment. Documentation revision, user acceptance and release gates stay deferred.
No product version bump, commit, PR, tag or release publication was performed.

Validation for this integration: 102 filesystem/reference/directory/checkpoint
routine tests and 427 shared State/cohort/checkpoint/Finder/Code/config-context
routine tests pass (529 distinct cases; the latter run deselects nine extended
tests). The existing installed-CLI Mac smoke and the new filesystem CLI acceptance
both pass without coverage. The latter positively asserts create/close/rename/
unlink, nonempty shared filesystem State at suspension, the normal artifact
checkpoint participant, exact resumed/uninterrupted bundle equality, identical
native bytes under native-only format selection, and authoritative evaluation
acceptance. A test-only config overlay forces the four operation families; nominal
production rates/probabilities remain configurable and conservative. Fault tests
cover rollback and lost returns across every phase, including rename/unlink;
unfinished-page reentry drains the original sampled intents without further RNG.

Full Ruff, formatting, whitespace and behavior-surface checks pass. Generation
behavior revision 474 is material; product version remains 2.2.0a4. The broad
release coverage/slow gates were not run or represented as complete.
