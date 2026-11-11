# Simulating macOS workstations

This guide describes the **current source checkout's experimental macOS 27 arm64
workstation model**. Published installers contain the capabilities of their own
release; check that release's notes and installed `eforge info formats --json`.
The source checkout has not yet completed its next release acceptance gates.

## Simulation target and execution host

A simulated Mac needs `os: macOS 27`, `architecture: arm64` and `type: workstation`.
An optional `os_build` identifies a modeled build. macOS 26, Intel/Rosetta and
other unqualified Mac targets fail validation regardless of output selection.

The computer running EvidenceForge is independent of the simulated OS. A Linux
host can generate Mac evidence, and a Mac host can generate Windows or Linux
evidence. Generation uses scenario/catalog/state values; it does not inspect the
host's accounts, installed apps, filesystem, processes or logs, and runs no native
collector. Studio installer platforms are described in the [Studio guide](studio.md).

## Available evidence

| Format ID | Evidence | Boundary |
| --- | --- | --- |
| `macos_endpoint_security` | v11 fork, exec, known exit, create, close, rename and unlink NDJSON | Qualified process producers and explicitly modeled regular-file operations. |
| `macos_unified_log` | Loginwindow workspace-method entry, bounded app-policy refusal and accepted SSH authentication | Selected messages; not a general process/service inventory or a native logarchive. |
| `ecar` | Correlated process, credential, session, file and endpoint-flow observations | Simulated EDR; available object families vary by platform. |
| `zsh_history` | Per-user interactive zsh submissions | Single-line ASCII, extended incremental history; submission does not prove execution or success. |
| `bash_history` | Explicit interactive Bash submissions | Not emitted merely because a Mac process or SSH command exists. |

Mac activity can also appear in configured Zeek, firewall and IDS sensors, and in
the web/proxy or Linux/Windows server receiving that activity. Those logs belong
to their sensor/server, not the Mac client. Windows Security, Sysmon and Linux
syslog are not emitted as Mac host logs. Web/proxy server roles currently belong
to Windows/Linux hosts.

Formats are selected through the existing `output.logs` list and host/source
collection settings. Selection alone does not create activity, deploy a sensor,
or establish third-party ingestion support. See the [format reference](reference/EVIDENCE_FORMATS.md).

## Start with an example

From the repository root:

```sh
uv run eforge validate scenarios/macos-workstation-example/scenario.yaml
uv run eforge generate scenarios/macos-workstation-example/scenario.yaml --output ./output/mac-example
uv run eforge eval ./output/mac-example --format json
```

Choose an unused destination. That example selects eCAR, network and history
evidence; it does not select every available native format. Its
[README](../scenarios/macos-workstation-example/README.md) explains the mixed-fleet,
mounted-SMB, SSH and workspace-entry variants. The
[combined native workload](../scenarios/macos-workstation-recovery/README.md) and
[system-job example](../scenarios/macos-persistence-example/README.md) exercise
additional supported families. Historical macOS 26 assessment inputs remain
historical evidence, not currently admitted generation targets.

## Process and application scope

Installation in the application catalog does not establish native launch support.
For complete native process coverage, validation checks reachable installed apps
against the same exact-binary and launch-policy query used by generation. Missing
signing facts or launch mechanisms fail before activity generation; unsupported
apps are not silently removed from baseline choices. Standard persona app/tool
launches now have native metadata and launch policies. IntelliJ IDEA, Sublime Text,
Postman and Thunderbird use provisional researched main-image models accepted for
this release; their entitlement/runtime details await the P2 installation audit.
CLI and shared-runtime templates have bounded reference-Mac execution checks.
These declarations do not establish every helper graph or command outcome. See the
[metadata references and limits](design/macos-workstation-feasibility/catalog-native-metadata.md).

The native producers cover fresh Apple Terminal and iTerm2 3.7.6 startup, supported
literal local/SSH commands, non-PTY and explicit PTY SSH receivers, qualified fresh
Finder app launches, and the selected root/system-job preset. Quoted shell text
describes the shell's literal argv; it does not automatically execute or expand
all commands inside a string.

Catalog presence is distinct from native qualification. Selected GUI mains have
their own installed/signing templates; this does not qualify every helper or
launch method. The helper expansion includes:

- Chrome renderer, generic GPU and network-service roles, owned by the exact main.
  Resident GPU/network helpers are reused rather than respawned for each visit.
- VS Code 1.143.0 main and generic GPU, network and shared Node roles. The Node
  role has its own argument/descriptor contract. Renderer, extension, watcher,
  agent and PTY helper families remain outside this qualified subset.
- One pre-window shared root `cfprefsd` and `launchservicesd` inventory member per
  host. Their presence does not invent an observed native birth, exit or service
  message. Other principals and service families remain separately qualified.

Docker Desktop references inform future work; the complete Desktop/backend/VM
helper graph is not admitted. A Docker CLI catalog entry does not imply Desktop
or its optional privileged helpers, and Linux VM processes are not Mac host
processes. Browser reuse follows the host, user, executable and user-data profile;
explicit fresh launches and distinct profiles preserve their intended semantics.
Persona traffic is planned in timestamp order within each host/hour. Flexible
inferred activity may wait for an already planned browser to become ready;
fixed-deadline connections require a process visible by that deadline. Historical
network attribution resolves the execution active at the connection time, including
bounded retained lifetimes, without reviving a closed process.
Ordinary Finder activity reuses its live per-session process, starting it lazily
when first needed. Supported regular-GUI main templates include Safari, Edge,
Teams and Excel; these declarations do not add their helper graphs. Safari's full
entitlement dictionary uses the bounded version-two property-object capability;
older native source capabilities retain their narrower admission rules.

## Bounded filesystem telemetry

Ordinary baseline activity can select an actually live qualified Code main for a
small modeled `Documents` workload. It produces empty-file create, write followed
by modified close, optional same-directory atomic rename/replacement, and optional
unlink. eCAR and ES share the actor, file/content versions, path and inode truth.
In-place writes retain the inode; atomic replacement has a new file object and
reports the old destination. Rename/unlink expose the qualified pre-operation
stat view. Directory changes and file placements survive exact checkpoint resume.

`activity/macos_execution_metadata.yaml` contains the `filesystem_workload`
configuration: eligible applications, directory and filenames, count/size/delay
bounds, idle/atomic-replacement/cleanup probabilities, permissions and allocation.
The defaults are **nominal simulation policy**, not a measurement of Code's exact
save implementation, workload frequency or APFS allocation. No eligible live main
means no invented file activity. File work fits its process/session lifetime.

There is no new authored filesystem event type. Generic file effects, downloads,
SMB operations and launch-item file stages do not automatically acquire native
file records. The operation bundle also supports explicit unmodified-close facts;
the default document workload does not model broad file reads, writable mappings,
cross-volume moves or arbitrary metadata changes. No file payload, APFS image,
FSEvents database or plist artifact is produced by this telemetry layer.

## Reading coverage and quality

Selecting ES defaults `macos_process_coverage` to `complete`. With eligible lossless
collection, every modeled in-window fork and successful image activation must
reconcile with independently retained canonical State and native output. Missing
qualification or required observations fail generation. Use `partial` explicitly
for intentionally incomplete diagnostic workloads.

The generation receipt in `GROUND_TRUTH.json.macos_native_coverage` and its Markdown
summary distinguish complete starts, known exits, unknown results and historical
unmeasured results. This all-process census supports the generation completeness
guard. New evaluation reports and Studio omit its duplicate, macOS-only host process
counters and implementation coverage notes; evaluation uses the shared source inventory
and authored-action agreement checks. Historical report files remain readable unchanged.
A process already running before collection has no retrospective
start; one surviving collection has no in-window exit obligation. An unknown
terminal result stays unknown and omits a native exit. Selected ordinary-close
outcomes are explicit model policy, not universal measured shutdown behavior.

The process census counts process starts/exits; file records do not become process
births or prove complete filesystem capture. A passing quality evaluation proves
its declared checks, not full native fidelity or a complete population of real
background tasks. The installed-CLI smoke and combined exact-resume/native-filter
tests are engineering acceptance within this scope.

## Remaining limits

General app/service Unified Log, launchd messages, VERBOSE SSH session messages,
Dock/Spotlight attribution, restored/existing-app window startup, arbitrary helper
graphs and complex shell execution plans remain gated. Current SSH ULF includes
observed PAM acceptance and source-derived plain-public-key acceptance through
the qualified logger; it does not claim every key/certificate or session message.
Mac SMB serving, OpenBSM, binary logarchive, sleep/wake, roaming and Intel/Rosetta
remain outside this target. Native Mac SIEM parser/normalization support is not
established by choosing `sof-elk` or `splunk`.

See the [capability matrix](design/macos-workstation-feasibility/capability-matrix.md),
[authoring reference](../commands/eforge/references/evidence-endpoint-macos.md) and
[implementation/validation record](worklog/2026-11-06-macos-realism-follow-through.md)
for detailed contracts and evidence boundaries.
