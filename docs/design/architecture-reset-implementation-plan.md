# Architecture Reset Implementation Plan

Status: accepted implementation direction, SSH/proxy/browser-session/RDP/Windows-remote-admin/file-transfer/Linux-shell-command/process-execution/auth-session/network-connection/DHCP-lease/DNS-lookup action-bundle slices complete; later slices pending

## Summary

EvidenceForge will use Option B from `architecture-reset-recommendation.md`: an
evolutionary architecture reset with partial rewrites behind stable interfaces.

The first implementation slice is SSH sessions. The slice preserves public scenario
schema, CLI behavior, generated bundle layout, concrete format names, and existing
emitters while introducing an internal action-bundle layer above canonical
`SecurityEvent`s.

## Phase 0 Guardrails

- `ActionBundle` sits above `SecurityEvent`.
- One `SecurityEvent` represents one logical evidence-producing occurrence.
- Multiple contexts on a `SecurityEvent` describe facets of the same occurrence.
- Multi-phase activities produce multiple coordinated `SecurityEvent`s.
- Cross-event lifecycle, timing, observation, and durable identity ownership belong
  in bundle/lifecycle/timing/observation layers.
- Emitters render source-native views of canonical facts and do not repair upstream
  lifecycle contradictions.

## First Slice: SSH Sessions

The SSH slice introduces an internal action-bundle adapter for SSH session
generation. Current callers keep using the existing `generate_ssh_session()`
entrypoint, so storyline events, baseline/world-planner bootstrap, red herrings,
and scanner/noise paths retain their public behavior while routing through the new
bundle contract.

The initial implementation is intentionally compatibility-first. It establishes
the action-bundle ownership boundary and tests that callers route through it.

The next extraction slice moves SSH session expansion itself into
`SshSessionActionBundle.execute()`. `ActivityGenerator.generate_ssh_session()` now
builds a `SshSessionRequest` and supplies runtime hooks for shared state,
dispatch, host-context construction, TCP accounting, source timing, and existing
SSH process helpers. Public scenario YAML, CLI behavior, output layout, and
concrete format names stay unchanged.

The hardening follow-up splits `SshSessionActionBundle.execute()` into explicit
transport planning/open, session event construction, Linux auth planning, EDR
readiness, and source-native syslog dispatch phases. SSH syslog timestamping and
Linux UID rendering are now bundle-local helpers rather than generator runtime
hooks. Regression probes cover identical-input evidence signatures, auth/syslog
ordering, destination-side sshd ownership, EDR login readiness, and network-close
ordering.

The ownership follow-up migrates remaining modeled SSH-session paths that were
still hand-rolling lifecycle evidence. Baseline remote-admin SSH noise now calls
the SSH bundle for transport, syslog auth/PAM/logind, endpoint session evidence,
and optional close semantics. Storyline `scp` activity calls the SSH bundle when
the receiver is a modeled Linux host, then emits only the receiver-side file
creation as transfer-specific evidence. Generic SSH connections to external or
unmodeled targets remain ordinary connection evidence until a later file-transfer
or external-service bundle is introduced. SSH action identity now distinguishes
intent anchors from execution anchors that include the resolved source port.

The temporal constraint graph slice adds the first shared timing foundation
without broad emitter or bundle rewrites. `TemporalConstraintGraph` resolves
preferred timestamps, hard bounds, lifecycle windows, and directed causal edges
deterministically. `SourceTimingPlanner` now routes paired source rows and
"source after source" dependencies through that graph, preserving current public
behavior while creating the API action bundles can use for multi-event lifecycle
timing.

The SSH temporal-graph migration moves bundle-owned SSH auth/syslog lifecycle and
EDR login-readiness timing onto graph-owned constraints. The bundle still
preserves existing scenario schema, CLI behavior, and output layout, but SSH
connection, accepted-auth, PAM, logind, and endpoint login observations now share
one causal timing model instead of separate local clamps.

The proxy temporal-graph migration starts with explicit forward-proxy request
handoff. Client-to-proxy request visibility and proxy-to-origin egress are now
resolved with graph constraints so origin egress waits for the source-observable
client proxy request window, even when per-source observation jitter would
otherwise make a local timestamp clamp too weak. Denied and cache-hit proxy
requests still stop at client/proxy evidence and do not emit downstream origin
transactions.

The proxy action-bundle extraction moves explicit forward-proxy transaction
expansion into `ProxyTransactionActionBundle.execute()`. `ActivityGenerator`
continues to provide the compatibility entrypoint, proxy route selection, and
shared runtime hooks, while the bundle owns client-to-proxy evidence, proxy
access shaping, CONNECT tunnel reuse, deny/cache terminal behavior, proxy-origin
DNS, proxy-to-origin egress, and temporal graph constraints. Public scenario YAML,
CLI behavior, output layout, concrete proxy/eCAR format names, and authoring
skills remain unchanged for this slice because the generated evidence semantics
are preserved.

The browser-session action-bundle extraction moves browser-like page-session
expansion into `BrowserSessionActionBundle.execute_with_result()`. Outbound
persona browsing and inbound human web-server visitor sessions now share the same
bundle for request grouping, transaction depth, page/subresource timing,
referrer chains, static-asset cache suppression, response MIME/status metadata,
and direct-vs-explicit-proxy handoff through canonical connection generation.
Single tool requests, scanners, raw storyline HTTP events, and source-local web
server noise remain direct canonical events unless they model a browser session.
Public scenario YAML, CLI behavior, output layout, and authoring skills remain
unchanged for this slice.

The RDP/remote interactive session action-bundle extraction moves RDP session
expansion into `RdpSessionActionBundle.execute()`. `ActivityGenerator` keeps the
existing compatibility entrypoint, while `WorldPlanner` now lets the bundle own
source-side `mstsc.exe` materialization when a modeled source host exists. The
bundle owns TCP/3389 transport emission, source-port reuse, target Type 10 logon
timing, preallocated target session metadata, transport PID, source-ready time,
and network-close time. Public scenario YAML, CLI behavior, output layout, and
authoring skills remain unchanged for this slice.

The Windows remote-admin action-bundle extraction moves explicit credential use
and remote service-install expansion into internal action bundles.
`ExplicitCredentialUseActionBundle` owns 4648 subject selection, visible
caller-process materialization/validation, source endpoint semantics, and
source-visible caller timing. `WindowsServiceInstallActionBundle` owns
service-control/service-install evidence: SMB/RPC companion transport, dropped
service-binary file creation when applicable, and target service-install records.
`ActivityGenerator` keeps the existing compatibility entrypoints, and public
scenario YAML, CLI behavior, output layout, and authoring skills remain
unchanged for this slice.

The file-transfer action-bundle extraction moves transfer-specific evidence
ownership into internal bundle helpers. HTTP response file-analysis metadata and
substantial SMB files.log metadata now share bundle-owned FUID/hash/MIME/filename
construction. Storyline staged-archive exfil prep now emits its SMB archive read
through `StagedArchiveSmbReadActionBundle`, and modeled SCP receiver-side file
creation now routes through `ScpReceiverFileActionBundle` after the SSH bundle
has owned transport/auth/session timing. Public scenario YAML, CLI behavior,
output layout, and authoring skills remain unchanged for this slice.

The Linux shell-command action-bundle extraction moves bash-history command
execution orchestration into `LinuxShellCommandActionBundle`. The bundle resolves
activity keys or literal commands, applies Linux source-native command
preparation, schedules bash history after session readiness, emits the
`bash_command` event, and optionally emits foreground process telemetry through
existing adapter hooks. Public scenario YAML, CLI behavior, output layout, and
authoring skills remain unchanged for this slice.

The process-execution action-bundle extraction moves canonical process
create/terminate orchestration behind `ProcessExecutionActionBundle` and
`ProcessTerminationActionBundle`. `ActivityGenerator.generate_process()` and
`generate_process_termination()` remain the public compatibility entrypoints,
while the bundles own the internal boundary for parent/session ownership,
source-visible process lifecycle timing, command-owned network effects,
guaranteed process-image file evidence, and probabilistic file/module/registry
endpoint side effects. Public scenario YAML, CLI behavior, output layout, and
authoring skills remain unchanged for this slice.

The auth/session lifecycle action-bundle extraction moves successful logon,
failed-logon, and logoff orchestration behind `LogonActionBundle`,
`FailedLogonActionBundle`, and `LogoffActionBundle`. Public generator
entrypoints remain stable, while the bundles own the internal boundary for
session allocation/reuse, logon IDs, source endpoint semantics,
transport/syslog companions, DC-side validation evidence, failed-auth network
companions, and session termination ordering after dependent activity. Public
scenario YAML, CLI behavior, output layout, and authoring skills remain
unchanged for this slice.

The network-connection action-bundle extraction moves canonical connection
orchestration behind `NetworkConnectionActionBundle`. `ActivityGenerator`
continues to expose `generate_connection()` as the compatibility entrypoint,
while the bundle owns the internal boundary for tuple identity, source and
destination semantics, source-port allocation, hostname/DNS/TLS/HTTP/file
metadata, proxy/firewall/IDS/EDR flow correlation, packet accounting, visibility
handoff, Zeek UID/state identity, source endpoint process ownership, and Windows
WFP companions. Public scenario YAML, CLI behavior, output layout, concrete
format names, and authoring skills remain unchanged for this slice.

The DHCP lease action-bundle extraction moves DHCP acquisition and renewal
orchestration behind `DhcpLeaseActionBundle`. `ActivityGenerator` continues to
expose `generate_dhcp_lease()` as the compatibility entrypoint, while the bundle
owns the internal boundary for lease identity, MAC/IP/server/domain metadata,
Zeek DHCP plus connection fan-out, link-local visibility semantics, and Linux
`dhclient` syslog companion ordering. Public scenario YAML, CLI behavior, output
layout, concrete format names, and authoring skills remain unchanged for this
slice.

The DNS lookup action-bundle extraction moves automatic connection-prerequisite
DNS lookup orchestration behind `DnsLookupActionBundle`. `ActivityGenerator`
continues to expose `_emit_dns_lookup()` as the compatibility adapter used by
causal expansion, while the bundle owns the internal boundary for resolver
selection, DNS cache behavior, query/answer semantics, TTL observations, Zeek
DNS plus UDP/53 connection fan-out, Sysmon DNS visibility, AD SRV discovery
companions, and low-volume resolver companion questions. Public scenario YAML,
CLI behavior, output layout, concrete format names, and authoring skills remain
unchanged for this slice.

## Migration Gates

- No public YAML or CLI changes in the first slice.
- Existing typed `ssh_session` events continue to generate Zeek, syslog, EDR/eCAR,
  and bash-history evidence through the current output files.
- Existing tests remain migration assets. Replace brittle implementation tests only
  when the new bundle contract supersedes their assumptions.
- Generated output should be preserved unless current behavior contradicts
  lifecycle, ordering, observation, or source-native realism requirements.
- Skills, skill references, source-format docs, and tests must be updated whenever
  user-facing authoring guidance or generated evidence semantics change.

## Verification

- Focused unit tests cover action-bundle request identity, deterministic anchors,
  SSH entrypoint delegation, direct bundle expansion, lifecycle ordering, and
  context-vs-bundle responsibility rules.
- SSH hardening probes cover deterministic identical-input regeneration at the
  bundle evidence-signature level plus session-owned source-readiness and
  transport-close invariants.
- SSH ownership follow-up probes cover resolved source-port execution anchors,
  public-key auth rendering, optional close dispatch, baseline bundle routing,
  and storyline `scp` routing for modeled Linux receivers.
- Temporal graph probes cover unconstrained resolution, causal chains,
  conflict handling where causality wins over upper bounds, deterministic
  insertion-order behavior, missing-node failures, cycle failures, and
  `SourceTimingPlanner` integration for source-after-source dependencies.
- SSH/proxy migration probes cover collapsed SSH auth preferences, EDR
  login-readiness ordering, explicit proxy client-request-to-origin-egress
  ordering, and preservation of existing explicit proxy origin request semantics.
- Proxy bundle probes cover deterministic transaction anchors, explicit-proxy
  `generate_connection()` delegation, tunnel reuse/terminal behavior, source
  visibility, User-Agent/domain preservation, and existing storyline proxy
  behavior.
- Browser-session probes cover deterministic session anchors, bundle expansion
  into grouped HTTP flows, referrer/transaction-depth preservation, static cache
  suppression, cache/partial-status preservation, and existing inbound/outbound
  browser-session behavior.
- RDP probes cover stable bundle anchors, source-side `mstsc.exe` materialization,
  source-port reuse between TCP/3389 and Type 10 logon evidence, preallocated
  session metadata updates, source-host correction for impossible self-sourced
  RDP, and world-planner baseline/storyline behavior preservation.
- Windows remote-admin probes cover stable explicit-credential and service-install
  anchors, 4648 caller-process ownership, subject-logon bootstrap, local-vs-remote
  endpoint semantics, dropped service payload ordering, and SMB/RPC companion
  transport preservation.
- File-transfer probes cover stable HTTP, SMB, staged-archive, and SCP receiver
  anchors, HTTP response files.log metadata, SMB transfer direction/filename/hash
  construction, staged-archive SMB read preservation, and SCP receiver file
  ordering after source-visible process creation.
- Linux shell-command probes cover stable shell-command anchors plus preservation
  of bash-history dwell, same-user cross-host second deconfliction, scheduled
  bash/process timing, process telemetry suppression, alias/interpreter/pipeline
  process expansion, and foreground serialization.
- Process-execution probes cover stable process create/terminate anchors,
  bundle-to-adapter delegation, existing process-create behavior, process
  termination behavior, parent/session repair, command-owned network effects,
  and file/module/registry side-effect preservation.
- Auth/session probes cover stable logon/logoff/failed-logon anchors,
  bundle-to-adapter delegation, existing successful-logon session allocation and
  reuse, failed-logon source endpoint/network companions, and logoff lifecycle
  ordering after dependent activity.
- Network connection probes cover stable connection anchors, bundle-to-adapter
  delegation, command-owned HTTP/proxy metadata preservation, scanner transport
  evidence, and remote-logon transport semantics.
- DHCP lease probes cover stable lease anchors, bundle-to-adapter delegation,
  Zeek DHCP dispatch, default AD-domain metadata, Linux `dhclient` syslog
  ordering, DHCP setup state, and link-local visibility behavior.
- DNS lookup probes cover stable lookup anchors, bundle-to-adapter delegation,
  Zeek DNS/conn UID correlation, source-time ordering before connections,
  qtype-specific answer semantics, public DNS profile rendering, and
  multi-sensor DNS packet-accounting preservation.
- Existing SSH, world-model, syslog, Zeek, EDR/eCAR, bash-history, validation, and
  ground-truth tests remain the regression suite for behavior preservation.
- Normal validation before committing remains:
  - `uv run pytest --no-cov`
  - `uv run ruff check .`
  - `uv run ruff format --check .`
