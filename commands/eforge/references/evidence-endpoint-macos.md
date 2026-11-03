---
description: "Current macOS 27 workstation sources, authoring contracts and evidence limits"
---

# Modeled macOS workstation evidence

Contents: [sources](#select-sources-by-the-evidence-needed) ·
[complete process starts](#complete-process-starts-and-explicit-limits) ·
[launch families](#supported-launch-families) · [SSH](#ssh-clients-receivers-and-commands) ·
[system launch items](#explicit-system-launch-item-stages) ·
[Unified Log and outcomes](#unified-log-families-and-policy-outcomes) ·
[other evidence](#other-evidence-and-interpretation)

The active generation target is **macOS 27, arm64, workstation**. Use existing system
fields (`os`, optional `os_build`, `architecture`, `type`), user placement, software
deployment and collection settings. Every other unqualified Mac target fails validation,
including macOS 26, independently of selected output formats. The profile catalog can
support more targets later; historical decoder support does not enable generation.

Running EvidenceForge or Studio on a Mac is a separate capability. Generation uses
invented catalog/state values and never queries the generator host's applications,
processes, accounts or logs. No collector runs on that host during generation.

## Select sources by the evidence needed

| Source ID | Current generated evidence | Important boundary |
| --- | --- | --- |
| `macos_endpoint_security` | Message-v11 fork, exec and known exit records | The process-start source. Complete canonical metadata and eligible collection are required. |
| `macos_unified_log` | Loginwindow workspace-method entry, bounded ASP policy refusal, accepted SSH PAM/plain-public-key authentication | Selected message families, not a process inventory. Launching an app or service does not automatically produce ULF. |
| `ecar` | Correlated process, credential, session, flow and file observations | Shared modeled endpoint facts; do not describe this as Apple's native ES export. |
| `zsh_history` | Live interactive zsh command submissions | Extended incremental history, single-line ASCII, zero duration; submission does not prove command success or a child process. |
| `bash_history` | Submissions from an explicitly modeled interactive Bash shell | Not a substitute for zsh or noninteractive process logging. |

Existing network, firewall, IDS, proxy, mail and server sources describe Mac interactions
only with the corresponding routing, deployment and sensor visibility. Windows Security/
Sysmon and Linux syslog remain local to their actual owners. No OpenBSM, native logarchive,
APFS image, general native filesystem-event or Mac SMB-server source is implemented.

Use `eforge info formats --json` to inspect the CLI actually being used. The current
checkout exposes both native Mac format IDs above and `zsh_history`. Do not conclude
that an older installed CLI has this branch's capabilities from its product version alone.
Selecting a format or output target does not establish SOF-ELK or Splunk ingestion support.

## Complete process starts and explicit limits

Selecting native ES defaults `macos_process_coverage` to `complete`. With eligible,
lossless collection, every modeled in-window fork and successful image activation must
reconcile with independently retained canonical State and native output, or generation
fails with the missing requirements. Multiple execs in one PID remain distinct records.
Unsupported launches cannot quietly succeed with missing native process output.

Use `macos_process_coverage: partial` only for an explicitly narrower diagnostic or
lossy collection request. It does not claim the complete guarantee. Runtime filtering
must preserve a complete request rather than silently removing required ES output.
Processes already running before collection do not get retrospective start records.
Builtins, reuse of an existing process, failed exec and policy refusal retain their
distinct semantics; none should acquire a fabricated successful exec.

`GROUND_TRUTH.json.macos_native_coverage` and its Markdown summary distinguish the
independent process census, qualification blockers, filtered/dropped/out-of-window
observations and authored activity. Exit has a separate obligation: an explicit completed
result is required. Unknown GUI/SSH teardown is reported and omits native exit; it never
becomes success. The current fixed workload reconciles 33 forks/39 execs, and its positive
background recovery companion 63/78. This is bounded workload acceptance, not every app.

Complete native facts include the exact execution, parent/responsible/audit identities,
installed image/signature, runtime security, thread, cwd, argv, ordered environment and
FD table. The v11 entitlement profile admits explicit null or bounded flat objects with
Boolean, signed-64-bit integer, string or string-array values, including an explicit empty
object. Unknown is distinct from empty/null. Old frozen profiles retain their narrower
capabilities. Public source rows must render supplied canonical facts rather than invent
missing descriptors, metadata, outcomes or identities.

## Supported launch families

Apple Terminal (`macos-terminal`) and iTerm2 (`macos-iterm2`) share a retained native
startup/command owner, with independent signing and helper metadata. Both include the
launchd fork, xpcproxy exec, GUI audit adoption and same-PID app exec. Terminal then forks
login and initial zsh: three forks/four execs in total. iTerm2 3.7.6 adds iTermServer and
ShellLauncher: four forks/six execs. Login's setuid/drop, controlling terminal, job control
and app-specific descriptor layouts are explicit. Existing active shells are reused.
New windows/restored jobs in an already running app remain separately unsupported.

Select the terminal through existing `environment.deployment_overrides.user_applications`
assignments. If both are eligible, Apple Terminal is the stable default. Profiled literal
local commands use the same canonical process owner and can emit ES, eCAR and history.
Quoted shell command text may qualify the shell's own exec; inner commands are not
automatically expanded. Explicitly author the child activity when supported. Pipelines,
redirections, substitutions, scripts and effect-bearing commands need their own qualified
execution/descriptor plans; command text alone is not one.

A fresh supported GUI app can use `process.launch_method: finder`, its installed absolute
`.app/Contents/MacOS/<executable>` path, a literal command line and `supplementary: none`.
An existing local GUI login owns audit identity. This producer owns the launchd fork,
root xpcproxy exec, GUI credential/audit transition and app exec. The latter phases share
one PID/lifetime; the app is not an invented child of xpcproxy. `parent_ref` and unsuccessful
outcomes are incompatible with this fresh-launch contract. Qualified reference-app and
Chrome producers use it; arbitrary apps/signing classes and Dock/Spotlight attribution
remain outside qualification. Every accepted start still has to satisfy complete coverage.

Chrome supports a fresh Finder main and three bounded direct helper roles: renderer
(`--type=renderer`), generic-helper GPU (`--type=gpu-process`) and generic-helper network
service (`--type=utility --utility-sub-type=network.mojom.NetworkService`). Use the frozen
catalog's exact executable paths and `parent_ref` naming the browser, with
`supplementary: none`. The producer owns the matching seatbelt argument and canonical
pipe; do not invent FD numbers in command text. Helpers have their own deployed
signer/entitlements. Crashpad, alerts, the dedicated GPU image, arbitrary helpers, browser
IPC and helper-attributed connections remain outside this model. The private reference's
installed release differed from the frozen catalog; exact build parity is not claimed.

## SSH clients, receivers and commands

Use `ssh_session` on the receiver with the existing `source_ip` to identify a modeled
client. A live Mac GUI/terminal session can own catalog `/usr/bin/ssh`, ancestry and
interactive history, including either terminal variant. Client observation fits before
authentication and remains alive through transport close. Missing source ownership must
not invent a session or PID. Mac receivers require `services: [ssh]` and a local actor
placed through existing `assigned_user` or `primary_system`; root/service-account login
and SCP/SFTP receiver helpers are unavailable. Type-10 `logon` is not the authoring interface.

The shared bundle owns transport, authentication, helper/credential transitions, readiness,
commands and close. Non-PTY startup has six real forks, six execs and three known short-
helper exits, including the launchd/xpcproxy prefix and distinct fork-only children.
An existing paired `logoff` can set the close deadline; the retained SSH continuation
performs closure through interruption and checkpoint recovery.

`pty: true` qualifies initial zsh startup and literal installed foreground commands.
One controlling terminal owns its standard vnodes; command groups remain distinct from
the shell's POSIX session and audit origin. Non-PTY commands use channel-owned pipes.
Use later `process` events with `supplementary: none`. Additional login shells, complex
shell plans, background jobs and unsupported helper families remain gated; unsupported
commands reject before allocating a child. Generic final-worker results remain unknown.

## Explicit system launch-item stages

`macos_launch_item` provides root/system `write`, `bootstrap`, `activate`, `exit`, `unload`
and `remove` stages. Supply an earlier root `process_ref` as `caller_ref`, an explicit label,
and a `/Library/LaunchDaemons/*.plist` path for write. Write includes program, exact
arguments and positive modeled byte size. Registration is distinct from activation; removal
of a file does not unload its retained definition. Replacement needs an increasing version.
Exit may supply a known `exit_code`; unload closes the retained group without inventing an
unknown terminal status. Explicit unload before scenario end is required.

For native ES startup select write-stage `launch_profile: root_xpcproxy_v11`, installed
`/usr/bin/true` or `/usr/bin/sw_vers`, and RunAtLoad false. The loaded definition freezes its
clean environment. Each activation owns a launchd fork, xpcproxy exec, setsid and target
exec; a known exit is explicit. Other images/domains/triggers remain gated. The example
`scenarios/macos-persistence-example/native-system-job.yaml` provisions its caller before
collection. The older example without this preset retains partial aggregate activation.

File/process stages can produce eCAR. Registration and dormant unload have no admitted
native observation. GUI LaunchAgents, automatic KeepAlive/timer/socket activation, native
plist artifacts and launchd ULF messages remain unavailable. Do not invent ULF lifecycle
messages merely because a job has ES process evidence.

## Unified Log families and policy outcomes

A local interactive login requests loginwindow's `-[Login1 launchWorkspace]` entry.
That is method entry, not desktop-completion proof, and SSH/service sessions do not
request it. Explicit `process.outcome: policy_refused` supplies a bounded ASP kernel
refusal. Its target PID/path belong to the attempt; the refusal does not create a running
child, successful exec, command effects or history. Use an earlier live initiator
`parent_ref` and a bundle executable path; `process_ref` is forbidden. Cause, actual
parentage and target execution stage remain unclassified.

`outcome: denied` is a separate pre-child refusal with no native Gatekeeper claim.
`outcome: exec_failed` preserves the referenced caller's old image/lifetime, leaves errno
unknown and suppresses success effects. Neither form invents a successful child or exit.

Accepted SSH authentication shares the root receiver's exact audit-adoption occurrence,
peer/user/session and retained eCAR/ULF journal in both PTY modes. Password intent uses
the observed keyboard-interactive/PAM payload. Plain-public-key intent uses canonical
type/SHA256 fingerprint and source-derived text through the same qualified Info/static
`%.500s` logger. Its semantic basis is distinct from the local PAM reference. Certificates
and missing/noncanonical keys produce no invented row. Synthetic build offsets/frames are
explicit; private system addresses or stack frames are not used. The profile models the
reference's visible text, not every collector's privacy/persistence setting.

Ordinary daemon verbosity is retained. VERBOSE session-start/close messages, other
unqualified PAM/disconnect families, generic app ULF and launchd ULF remain gated. The
final bounded launchd capture passed controls and cleanup but retained zero rows. The
agreed collection sequence has ended; this is not proof of global absence and does not
change ES coverage. No new capture or alternate diagnostic-file source is requested.

## Other evidence and interpretation

Mac file populations use existing `environment.storage.file_sets` with absolute POSIX
roots. Experimental mounted SMB clients reuse existing mappings with automatic/mounted
path presentation; they do not make a Mac an SMB server. Client eCAR and selected network/
Windows/Samba server evidence remain owned by their actual platforms. Native Mac SMB
messages and broader APFS alias/case behavior are unavailable.

History needs a live interactive shell in the owning session. Noninteractive commands,
multiline/metafied records, erasure and delayed exit-only persistence are unsupported.
Authored `spillage` / `surface: shell_history` supports ASCII invented values under an
ordinary local Mac user and live zsh owner. It records submission, without asserting a
child process or success. Root/service-account and SSH-owned exposures remain outside
that profile. Output filtering must not choose a different shell or create missing facts.

Internal `process_fork`, `process_exec`, `process_audit_bind`, privilege/service drops,
job-control and workspace occurrences are bundle-owned; do not author them or substitute
raw messages. eCAR extensions preserve actor/subject and before/after execution identity.
Native export has its own qualified projections; eCAR availability alone does not prove it.

`eforge eval` discovers host-scoped `macos_unified_log.ndjson` and
`macos_endpoint_security.ndjson`. Native UID/audit/PID roles and nanosecond timestamp text
are preserved; directory provenance is not an embedded native hostname or username.
Historical v6/v9/v10 imports remain separate from current v11 generation. Parsing is not
proof of lifecycle completeness, native fidelity or external SIEM normalization.
