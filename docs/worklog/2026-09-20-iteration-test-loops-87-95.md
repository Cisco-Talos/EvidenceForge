# Iteration-Test Assessment Loops 87–96

This worklog continues the requested ten-loop assessment run after Loop 86. The authoritative
blind artifacts live under `scenarios/iteration-test/blind-test/v2-loop-N/`; this file retains only
family contracts, implementation/verification handoff facts, and surviving priorities.

## Loop 87 Family Contract

### Process-bound HTTP client identity

- **Classification:** `hard_contradiction` plus `family_level`; Loop 86 joined endpoint process
  identities and source ports to HTTP observations showing one Edge PID emit Edge and Firefox
  agents and persistent Firefox/Chrome PIDs reverse major versions. Identical host-local curl paths
  also advertised different versions without a visible override.
- **Owning abstractions:** canonical process state owns the application image and durable client
  profile; the network transaction planner owns projection of that profile into HTTP, transparent
  proxy, and explicit-proxy evidence. Baseline/storyline adapters must request the process-bound
  profile rather than independently sampling a request-level agent.
- **Invariant:** every HTTP request attributed to one modeled browser process uses one compatible
  browser family and full version for that process lifetime. Generated command-line client versions
  are stable for a host-local executable path. A different agent is permitted only when the command
  or authored occurrence contains an explicit, log-visible override; absent such an override,
  destination, request type, proxy route, and generation path cannot change client identity.
- **Entry paths:** baseline persona browsing, application-catalog connections, automatic HTTP
  evidence, transparent and explicit proxy transactions, web-session bundles, typed storyline
  uploads/downloads, command-derived HTTP, and direct compatibility generation.
- **Consumers:** Zeek HTTP, proxy access, web access, eCAR/Sysmon FLOW ownership, IDS predicates,
  HTTP multipart/file evidence, referrer policy, request headers, and evaluator correlation.
- **Layer rationale:** emitters can only render the agent already attached to canonical HTTP
  context, while request-level pools lack the process lifetime needed to preserve identity. The
  process/network boundary is the first shared layer that knows image, durable process object,
  source tuple, and every downstream protocol consumer.
- **Sibling risks:** preserve explicit malware/scanner spoofing, source-native missing agents,
  domain-specific system agents, package-manager identity, server non-browser clients, OS
  compatibility, independent profiles for distinct process objects, checkpoint/retry determinism,
  and explicit-proxy two-leg agreement.

## Loop 87 Result

- **Implementation:** bound browser family/version to canonical process identity and stabilized
  command-line HTTP client identity through direct and proxy planning, including compatibility and
  authoritative-caller paths.
- **Verification:** 11,684 routine tests passed; Ruff check/format and all 92 packaged config files
  passed; behavior revision 112 validated at
  `8290756c908c5bade888bc213e7f3a20e9dd348f149dab8d711b207a61e03373`.
- **Hard probe:** 1,815 HTTP source tuples and 30 owned processes produced no process-identity or
  tuple-identity violation.
- **Assessment:** deterministic score 96.8088/PASS across 124,274 records. Initial blind mean 64.0;
  deliberated mean 84.25 with a 3–0 Synthetic majority and one Inconclusive dissent.
- **Surviving priority:** Sysmon Event 8 uses thread-creation APIs as entry functions and derives
  addresses from one global module-name band across hosts and Windows builds.

## Loop 88 Family Contract

### Deployment-bound remote-thread entry identity

- **Classification:** `hard_contradiction` plus `family_level`; Loop 87 found Event 8 records using
  `NtCreateThreadEx` and `AmsiScanBuffer` as created-thread entry functions and placing module
  addresses from unrelated hosts and OS builds inside implausibly tight global bands.
- **Owning abstractions:** canonical `RemoteThreadContext` owns target-side entry identity; the
  Windows deployment/binary model owns host-, boot-, architecture-, and build-specific module
  placement; the Sysmon and eCAR emitters only project those canonical values.
- **Invariant:** `StartModule`, `StartFunction`, and `StartAddress` describe one credible target-side
  thread entry. A creation API cannot stand in for the entry routine. Module bases are stable within
  one host boot and binary build, vary across hosts/boots under deterministic ASLR, and differ by
  module/build rather than collapsing into a global name-only range.
- **Entry paths:** benign baseline Event 8 patterns, causal/process-access expansion, typed
  storyline remote-thread events, compatibility generation, and project overlay extensions.
- **Consumers:** Sysmon Event 8 XML, eCAR thread records, external-parser projections, evaluator
  validation, process/thread lifecycle state, and blind endpoint reconstruction.
- **Layer rationale:** the generator currently chooses source/target-aware start labels but assigns
  one global module-name-derived base. Emitters lack deployment and lifecycle ownership, so the
  canonical event construction boundary is the first layer that can bind entry semantics to an
  exact host boot and target module identity.
- **Sibling risks:** preserve canonical thread creation and termination, target/source PID validity,
  per-process object IDs, OS architecture, Defender platform paths, overlay extensibility, address
  formatting, Sysmon/eCAR agreement, behavior-manifest determinism, and checkpoint replay.

## Loop 88 Result

- **Implementation:** removed thread-creation APIs from entry-function selection and derived the
  canonical start address from a build-specific function RVA plus deterministic host/boot ASLR.
- **Verification:** 11,686 routine tests and 481 focused tests passed; Ruff check/format and all 92
  packaged config files passed; behavior revision 113 validated at
  `680ba6a45a1371c96e0673a3b438489f86b80f7bbdd58b2d71e06e176db39fa8`.
- **Hard probe:** 13 Event 8 records on eight hosts had no creation-API entry, within-boot address
  drift, cross-host address reuse, address-range failure, or Sysmon/eCAR mismatch.
- **Assessment:** deterministic score 96.8088/PASS across 124,274 records. Initial blind mean 54.0;
  deliberated mean 62.75 with two Synthetic and two Inconclusive final verdicts.
- **Surviving priority:** one Type 9 SMB sequence gives Marcus Chen's outbound credential to a
  PowerShell process but assigns the Marcus-authenticated transport and file effects to an older
  Explorer process in Aisha Johnson's RDP session.

## Loop 89 Family Contract

### Type 9 credential-to-SMB ownership

- **Classification:** `hard_contradiction` plus `family_level`; Loop 88 joined a Type 9 LUID and
  PowerShell process to Marcus Chen's outbound identity, while the SMB transport and local file
  effects were owned by Explorer under Aisha Johnson's older desktop LUID and targets authenticated
  Marcus.
- **Owning abstractions:** the Type 9 session owns the immutable local caller and outbound
  credential; the canonical SMB action bundle owns client-process selection, channel affinity,
  transport attribution, target authentication, and file effects. The storyline adapter must pass
  the exact session/process relationship rather than only substituting an SMB principal.
- **Invariant:** credentialed SMB uses one live client process whose LogonID is the exact Type 9
  session. That process retains the local caller principal, owns every client-side FLOW and file
  effect, and authenticates the outbound principal on the target. No older desktop process may
  inherit the alternate credential merely because it is the default Windows-native SMB client.
- **Entry paths:** typed Type 9 logon followed by SMB browse/read/copy/move, batched persistent SMB,
  Windows-native and command-line clients, storyline file collection/staging, and compatibility
  paths that supply an explicit preferred process.
- **Consumers:** Security 4624/4688/5156, Sysmon 1/3/11, eCAR process/FLOW/file, Zeek conn/SMB/files,
  target 4624/5140/5145, persistent SMB channel state, truth manifests, and evaluator pivots.
- **Layer rationale:** emitters cannot repair a credential/process split after channel affinity and
  canonical transport ownership are fixed. The storyline-to-bundle request and SMB preparation are
  the earliest shared boundary holding the Type 9 LUID, live process identity, local principal,
  outbound principal, transport, and every downstream consumer.
- **Sibling risks:** preserve immutable local token ownership, outbound target principal, ordinary
  desktop SMB without Type 9, Linux clients, explicit credential mappings, operation batching,
  persistent channel/session reuse, exact retry/checkpoint behavior, process lifetimes, and
  multi-source timestamp ordering.

## Loop 89 Result

- **Implementation:** passed the exact Type 9 LogonID and live credential-process identity into
  canonical SMB preparation so the local caller owns client flows/file effects while targets use
  the outbound credential.
- **Verification:** 11,686 routine tests and 697 focused tests passed; Ruff check/format and all 92
  packaged config files passed; behavior revision 114 validated at
  `61f46daa4610d50eee44f15c4c985693271f9f7ef8dae53ebfe07e1d808f06a4`.
- **Hard probe:** the split-token chain used one PowerShell process under the exact Type 9 LUID for
  all five SMB flows and six VaultCache file effects, while target authentication used Marcus Chen.
- **Assessment:** deterministic score 96.8088/PASS across 124,276 records. The unanimous Synthetic
  panel scored 86, 78, 68, and 66 (mean 74.5); no deliberation trigger fired.
- **Surviving priority:** the corrected PowerShell owner visibly runs only a directory-creation
  command yet is credited with creating nine populated business documents.

## Loop 90 Family Contract

### Operation-semantic SMB staging lineage

- **Classification:** `hard_contradiction` plus `family_level`; Loop 89 tied SMB and file effects to
  the correct Type 9 process but exposed that its visible command only creates three directories and
  cannot create or copy the nine populated documents attributed to it.
- **Owning abstractions:** authored/storyline operation intent owns what the process was asked to do;
  the canonical SMB action bundle owns remote read, local write, channel, artifact, and process
  relationships; command rendering must express the same transfer semantics without inventing an
  emitter-local explanation.
- **Invariant:** every staged content file has one source-visible operation capable of producing it.
  Directory creation may emit directory effects only. Remote documents copied through SMB must be
  owned by a live process whose command expresses the source share/path and local destination, while
  the exact Type 9 LUID, local token principal, outbound target credential, artifact identity, and
  transfer timing remain consistent.
- **Entry paths:** typed storyline SMB browse/read/copy/move, batched persistent SMB staging,
  Windows-native PowerShell/robocopy/cmd clients, command-derived transfers, compatibility requests
  with explicit process identity, and ordinary non-Type-9 desktop SMB.
- **Consumers:** Security 4688/5156/5140/5145, Sysmon 1/3/11, eCAR process/FLOW/file, Zeek
  conn/SMB/files, target authentication, ground-truth operation summaries, and evaluator pivots.
- **Layer rationale:** emitters know neither the authored operation nor the artifact lifecycle, and
  the SMB bundle cannot infer a credible command after a directory-only process has already been
  selected. The storyline-to-bundle intent boundary is the first shared layer that knows source
  share, destination tree, operation, credential session, client process, and all effects.
- **Sibling risks:** preserve the Loop 89 Type 9 ownership fix, persistent SMB channel reuse,
  batched artifact order and hashes, source/target file semantics, Linux clients, ordinary Explorer
  browsing, command quoting, PowerShell process lifetime, causal timing, observation grouping,
  checkpoint determinism, and authored raw-command escape hatches.

## Loop 90 Result

- **Implementation:** expressed every staged SMB copy as a source-visible PowerShell operation and
  carried its exact Type 9 process/LUID authority through persistent and Samba-backed SMB paths.
- **Verification:** 11,690 routine tests passed; Ruff check/format and all 92 packaged config files
  passed; behavior revision 122 validated at
  `0cf38af7e1a7e3cb60febadc93260b59ac42ba83864878dc6a3f03cad9e66115`.
- **Hard probe:** nine VaultCache files were owned by three compatible copy commands under the exact
  Type 9 LUID; ten Marcus Chen target reads covered all nine staged object identities with no
  command/effect, identity, timing, or artifact violation.
- **Assessment:** deterministic score 96.8090/PASS across 124,311 records. The initial panel split
  two Synthetic/two Inconclusive at mean 63.5 and spread 40; deliberation converged 4–0 Synthetic
  with mean 70.75 and a unified synthetic-confidence score of 71.
- **Surviving priority:** a visible non-`-Pn` Nmap command produces five service attempts against
  every usable address after its immediately preceding discovery run found only nine responders.

## Loop 91 Family Contract

### Command-semantic network scan materialization

- **Classification:** `hard_contradiction` plus `family_level`; Loop 90 joined the recorded command
  `nmap -sT -p 22,80,443,445,3306 10.10.2.0/24` to exactly 1,270 TCP attempts—five ports on every
  usable address—even though its immediately preceding discovery run received only nine replies
  and the command does not bypass discovery with `-Pn`.
- **Owning abstractions:** the canonical scanner action bundle owns target expansion, discovery
  policy, discovered-host state, service-probe enumeration, timing, and process lifecycle; command
  rendering must project that same plan rather than describe a different invocation.
- **Invariant:** a source-visible scanner command and its network effects describe one executable
  plan. A service scan without `-Pn` may probe only hosts discoverable by that invocation's modeled
  discovery behavior. If every usable address is intentionally service-scanned, the command must
  include `-Pn` or an equivalent visible bypass. Ports, target range, scan type, and TCP outcomes
  must remain compatible with the command.
- **Entry paths:** typed storyline scan events, compound discovery-plus-service scans, baseline and
  red-herring scanners, compatibility scan helpers, authored raw commands with modeled effects, and
  future tool-specific scanner adapters.
- **Consumers:** eCAR/Sysmon/Security process evidence, Zeek conn and ICMP evidence, endpoint FLOW,
  firewall records, IDS scan alerts, process lifetimes, ground-truth summaries, and evaluator
  command/effect pivots.
- **Layer rationale:** emitters cannot infer omitted scanner flags or safely delete already-planned
  connections. The scanner action boundary is the first shared layer that knows the command,
  discovery results, target/port expansion, timing, process identity, and every downstream network
  consumer.
- **Sibling risks:** preserve deterministic host ordering, existing discovery evidence, realistic
  closed/filtered/open TCP state texture, timing bursts, source-port allocation, process lifetime,
  endpoint/network/IDS correlation, IPv4 range bounds, authored raw-command escape hatches, and
  checkpoint/retry determinism.

## Loop 91 Result

- **Implementation:** compiled Nmap commands into one discovery/service plan; ordinary scans probe
  discovered or explicit hosts, while the authored all-address scan now visibly declares `-Pn`.
- **Verification:** 11,691 routine tests passed; Ruff check/format and all 92 packaged config files
  passed; behavior revision 123 validated at
  `4e00bb0d855f5867b0fd6312776520442220c4188e036244086ac207c61e7b1e`.
- **Hard probe:** the visible `-Pn` scan covered exactly 1,270 target/port pairs across all 254
  usable addresses, with no hidden discovery and with mixed native TCP outcomes.
- **Assessment:** deterministic score 96.9982/PASS across 120,040 records. Initial scores 34, 48,
  25, and 78 triggered deliberation; the panel converged on Synthetic at mean 66.75 and unified
  synthetic-confidence 67.
- **Surviving priority:** Exchange transport and IMAP services accumulate overlapping
  singleton-style instances across Security, Sysmon, and eCAR.

## Loop 92 Family Contract

### Canonical Windows service cardinality

- **Classification:** `hard_contradiction` plus `family_level`; Loop 91 emitted multiple concurrent
  `EdgeTransport.exe -service` and `Microsoft.Exchange.Imap4.exe` instances under SCM ownership,
  reaching implausible in-window concurrency that three endpoint sources independently reproduce.
- **Owning abstractions:** the data-driven system-service catalog declares service identity and
  singleton versus bounded-worker cardinality; canonical process/service lifecycle authority owns
  live-instance selection, restart, closure, and publication before any endpoint renderer runs.
- **Invariant:** a cataloged singleton service has at most one canonical live process per host and
  service identity at any instant. A later request reuses that process until its close, then may
  start a replacement. Multi-instance services require an explicit worker-pool policy rather than
  inheriting duplicate starts from baseline frequency.
- **Entry paths:** hourly baseline service noise, profiled service workers, role-specific server
  services, seeded boot processes, compatibility process helpers, terminal-pass generation, and
  out-of-order deterministic visits.
- **Consumers:** Security 4688/4689, Sysmon 1/5, eCAR PROCESS create/terminate, process-owned FLOW and
  file/registry effects, service/process registry bindings, truth manifests, and evaluator pivots.
- **Layer rationale:** emitters faithfully repeat the canonical overlap and cannot infer service
  cardinality. The service catalog plus lifecycle authority is the earliest shared boundary that
  knows service identity, policy, live state, process ownership, and every rendered consumer.
- **Sibling risks:** preserve legitimate WMI and worker-pool concurrency, distinct named
  `svchost -s` services, exact image-path matching, future/out-of-order canonical reuse, process
  lifetime and terminal closure, role/service eligibility, observation grouping, checkpoint/retry
  determinism, and source-native timestamps.

## Loop 92 Result

- **Implementation:** declared Exchange transport and IMAP as per-host singleton services in the
  data-driven catalog, routing every request through the existing canonical reuse authority.
- **Verification:** 11,692 routine tests passed; Ruff check/format and all 92 packaged config files
  passed; behavior revision 124 validated at
  `64abff378ac7bd7c2449c93433ca2e42c16c938ff5f40f77870925e9179e656a`.
- **Hard probe:** 13 eCAR flows, 13 Security 5156 rows, and 15 Sysmon rows for Exchange transport
  all used PID 2724, with no second candidate in any source.
- **Assessment:** deterministic score 95.8521 across 122,483 records, but acceptance failed on
  pivot linkability 77.3 and temporal integrity 83.7; the failure was investigated as a distinct
  scheduling/source-ordering family. Initial blind mean 35.5 triggered deliberation on verdict
  disagreement; the chair returned Inconclusive at mean 40.75 and unified score 41.
- **Surviving priority:** fresh interactive processes continue under disconnected RDP LUIDs without
  a reconnect or alternate visible controller; RDP terminal outcomes also lack policy texture.

## Loop 93 Family Contract

### State-aware RDP interaction and terminal outcomes

- **Classification:** `contract_gap`, `distribution_texture`, and `family_level`; Loop 92 emitted
  Security 4779 for an RDP LUID, then attributed multiple new Explorer-launched interactive
  processes to that disconnected session without Security 4778 or another controller. Across the
  corpus, every visible RDP session disconnected before logoff, none reconnected, and cleanup
  delays were independently sampled rather than host/policy-shaped.
- **Owning abstractions:** the RDP action bundle and `RdpReconnectStateManager` own exact connected,
  disconnected, reconnected, and logged-out states; a data-driven RDP outcome policy owns ordinary
  direct-logoff, retained-disconnect, timeout-retirement, and reconnect selection. Process planning
  must consult that state before assigning fresh interactive ownership.
- **Invariant:** a disconnected RDP session may retain and execute already-running background work,
  but it cannot own a fresh UI-driven process after 4779 until an exact later transport generation
  commits and Security 4778 becomes visible. Otherwise the process must use another active
  controller/session. Terminal outcomes are stable per explicit intent or host policy, not one
  fleet-wide disconnect shape with an independent random cleanup delay.
- **Entry paths:** typed `rdp_session`, compatibility Type 10 logon, baseline remote administration,
  reconnect admission, storyline process selection, nested RDP clients, hourly lifecycle
  watermarks, explicit logoff, hard-deadline closure, and checkpoint-restored continuations.
- **Consumers:** Security 4624/4634/4778/4779/4688, Sysmon 1/5, eCAR USER_SESSION/PROCESS/FLOW,
  Zeek/endpoint RDP transport, process-parent/session identities, truth manifests, and evaluator
  timing/linkability pivots.
- **Layer rationale:** emitters accurately render the disconnected state and cannot decide whether
  later interaction is legal. The RDP bundle/state manager is the first shared owner of logical
  session identity, immutable transport generations, reconnect deadlines, process/session binding,
  and terminal lifecycle publication; outcome diversity belongs in data configuration consumed by
  that owner.
- **Sibling risks:** preserve disconnected process survival, exact LUID/session identity across
  reconnect, new source ports and channel IDs per generation, transport-before-4778 ordering,
  source `mstsc.exe` lifecycle, direct explicit logoff semantics, nested-session ordering,
  collection-boundary retention, observation grouping, atomic recovery, and checkpoint/retry
  determinism.

## Loop 93 Result

- **Implementation:** gated fresh RDP interactive ownership on canonical connected state and
  extended the same lifecycle frontier through proxy, SMB, and SSH-adjacent process selection.
- **Verification:** the routine suite reached 11,695 passed and 48 skipped before the final narrow
  refinements; every subsequent focused lifecycle gate passed. Behavior revision 135 validated at
  `b9793c1d50ff60e700de7bb1b6d48963739521801bff46d49e55c0a0c9ad411d`.
- **Hard probe:** all 102 interactive creates respected 12 visible disconnects, with no fresh
  process under a disconnected LUID and no skipped storyline event.
- **Assessment:** deterministic score 96.0296/PASS across 117,967 records. Initial verdicts split
  two Synthetic/two Realistic; deliberation converged on Synthetic at 82% confidence and 72
  synthetic-confidence.
- **Surviving priority:** canonical execution/session lifecycle permits implausible Windows
  parent/token/session ownership and advances a Linux shell command before its predecessor ends.

## Loop 94 Family Contract

### Canonical execution/session lifecycle truth

- **Classification:** `hard_contradiction`, `contract_gap`, and `family_level`; Loop 93 recorded a
  `DB-PROD-01` shell-history command in the same second as its still-running predecessor began,
  while Windows staging/exfiltration exposed user processes under incompatible service parents and
  widespread zero Sysmon `LogonGuid` values.
- **Owning abstractions:** canonical process/session state owns immutable parent, actor, token,
  logon identity, start, and completion; action bundles own sequential versus concurrent execution
  intent; source timing and observation may delay evidence but may not invent a different process
  tree, session identity, or command order.
- **Invariant:** a sequential shell command starts only after its predecessor completes. Every
  Windows process projects one compatible canonical parent, token principal, LogonID, and stable
  nonzero session GUID across Security, Sysmon, and eCAR. Remote/service execution must expose its
  actual controller boundary rather than borrowing an unrelated interactive user or service tree.
- **Entry paths:** typed process events, SSH command execution, bash-history rendering, RDP-owned
  interactive work, Type 9 staging, proxy upload clients, WMI/service/task execution, baseline
  process spawning, compatibility helpers, and terminal lifecycle finalization.
- **Consumers:** Security 4688/4689, Sysmon 1/3/5/11, eCAR PROCESS/FLOW/FILE, bash history,
  SSH/PAM/syslog, process and session registries, action continuations, truth manifests, and
  evaluator temporal/pivot checks.
- **Layer rationale:** an emitter can hide one bad parent or move one timestamp, but only canonical
  process/session state plus bundle timing knows the shared actor, controller, dependency, and
  lifecycle interval consumed by every source.
- **Sibling risks:** preserve legitimate pipelines and background jobs, concurrent shells, durable
  SSH sessions, service and SYSTEM execution, Type 9 local/outbound identity split, disconnected
  RDP process survival, remote-controller ownership, source-native clock/observation delay,
  bounded-window processes, checkpoint/retry determinism, and terminal cleanup.

## Loop 94 Result

- **Implementation:** added a long-lived Type 9 controller and stable nonzero session LogonGuid,
  serialized Linux foreground shell commands, rendered parentless Sysmon roots source-natively,
  and stopped the shared process lookup from labeling PID 0 as Explorer.
- **Verification:** 11,701 routine tests passed before the two bounded generation-discovered
  follow-ups; all 64 final focused regressions, repository-wide Ruff check/format, all 92 packaged
  config files, and behavior revision 138 at
  `286044103e9de50f17f726ffd793da8727b2c694935139522289d0270ab18594` passed.
- **Hard probe:** all eight Type 9 creates shared one nonzero GUID and controller ancestry, ordinary
  interactive users had no null Sysmon GUID, `mysqldump`/`gzip`/`scp` had positive 1.9-second gaps,
  and no truth event was unemitted.
- **Assessment:** deterministic score 96.0293/PASS across 117,928 records. Initial verdicts were
  two Realistic, one Inconclusive, and one Synthetic at mean 78.5; deliberation converged on
  Synthetic at 87% confidence, 68 synthetic-confidence, and mean recalibrated realism 75.75.
- **Surviving priority:** the new Type 9 `cmd.exe` controller is itself visibly created by Windows
  PID 0 across Security, Sysmon, and eCAR, and its bootstrap omits the expected 4648 companion.

## Loop 95 Family Contract

### Canonical Type 9/NewCredentials execution-session bootstrap

- **Classification:** `hard_contradiction`, `contract_gap`, and `family_level`; Loop 94 made the
  Type 9 descendants internally consistent but materialized their user-mode controller with
  Windows PID 0 and emitted no adjacent 4648 explicit-credential event.
- **Owning abstractions:** the Windows explicit-credential/NewCredentials action bundle owns the
  live local caller, caller session, 4648 use, 4624 Type 9 clone, outbound identity, controller
  process, and its durable lifecycle; canonical process/session state owns the cross-token parent
  edge and stable identities consumed by renderers.
- **Invariant:** every modeled Type 9 session begins with one live, source-visible caller in an
  active local interactive session. The same action emits a caller-bound 4648 and a 4624 Type 9,
  then creates the long-lived controller under a valid parent PID/GUID/image. Descendants use the
  cloned Type 9 token while retaining the correct local principal and outbound credential; no
  user-mode process may be created by PID 0.
- **Entry paths:** typed `logon_type: 9`, typed `explicit_credentials`, `runas /netonly`, storyline
  SMB staging, remote-admin helpers, compatibility explicit-credential calls, and future tools
  that create NewCredentials tokens.
- **Consumers:** Security 4648/4624/4688/4689, Sysmon 1/5 and dependent events, eCAR
  USER_SESSION/PROCESS/FLOW/FILE, SMB and proxy action bundles, process/session state, truth
  manifests, and evaluator pivots.
- **Layer rationale:** emitters cannot invent a missing caller, 4648, or legal process/session edge.
  The NewCredentials action family is the first shared boundary that knows the interactive caller,
  outbound credential, cloned session, controller, and all downstream activity.
- **Sibling risks:** preserve the immutable local-versus-outbound identity split, exact Type 9 LUID
  and GUID, ordinary explicit-credential events that do not create Type 9, short-lived `runas`
  actions, long-lived storyline controllers, process termination/logoff order, disconnected RDP
  admission, SMB channel affinity, source timing, observation grouping, and checkpoint determinism.

## Loop 95 Result

- **Implementation:** moved Type 9 bootstrap into the canonical NewCredentials action family with
  a live interactive caller, source-visible `runas` and 4648, ordered 4624 admission, valid
  cross-token ancestry, and a durable child lifecycle independent of the short-lived caller.
- **Verification:** 11,705 routine tests passed with 48 skipped; Ruff check/format and all 92
  packaged config files passed; behavior revision 142 validated at
  `42a680d425650fb17ff18f573b1ce49c7f710e145f8e533dbc888ada22122349`.
- **Hard probe:** both Type 9 sessions ordered `runas -> 4648 -> 4624 -> child`, retained matching
  caller/outbound identities across Security, Sysmon, and eCAR, and had no PID-0 or ancestry
  violation.
- **Assessment:** deterministic score 96.0293/PASS across 117,976 records. Initial realism scores
  84, 88, 81, and 76 triggered deliberation on verdict disagreement; the chair converged on
  Realistic at 79% confidence, 39 synthetic-confidence, and mean recalibrated realism 79.0.
- **Surviving priority:** syslog `omfwd` diagnostics name an undeclared/self receiver that no
  outbound eCAR flow uses, while all 321 sender-side syslog flows omit forwarding-process
  ownership.

## Loop 96 Family Contract

### Canonical syslog transport route and forwarding-process ownership

- **Classification:** `hard_contradiction`, `contract_gap`, and `family_level`; Loop 95 emitted nine
  `omfwd` diagnostics on six hosts naming `10.10.2.30` even though that address belongs to
  `APP-INT-01`, including a self-target claim, while all 321 outbound eCAR UDP/514 flows went only
  to the declared receivers `10.10.2.40` and `10.10.2.21` and carried no process identity.
- **Owning abstractions:** the source-routing planner resolves the eligible receiver and route once;
  the canonical network-connection contract owns the sender/receiver transport and live forwarding
  process context; syslog health vocabulary and all rendered observations consume that retained
  route truth.
- **Invariant:** every modeled syslog forwarding action uses one canonical sender, explicitly
  syslog-capable receiver host/IP, transport/port, and live forwarder process. `omfwd` diagnostics,
  sender/receiver eCAR FLOW rows, Zeek transport evidence, and queue/health labels agree on that
  identity. Accidental self-targets and undeclared receiver roles fail closed; observable senders
  carry actor/PID/principal/image ownership.
- **Entry paths:** periodic baseline forwarding, rsyslog queue/checkpoint health, sender and receiver
  flow projection, Linux and Windows forwarding agents, alias-based routes, direct IP routes,
  observation-loss paths, compatibility network helpers, and collection-boundary carry-in.
- **Consumers:** RFC 5424 syslog, eCAR FLOW and PROCESS identities, Zeek conn records, environment
  service roles, source visibility/routing, queue diagnostics, receiver-side telemetry, truth
  manifests, and evaluator cross-source agreement.
- **Layer rationale:** emitters cannot independently infer which health-message target, flow tuple,
  and forwarding process refer to the same route. Source routing plus the network-connection
  contract is the earliest shared owner with receiver capability, canonical tuple, process
  lifetime, and every downstream projection.
- **Sibling risks:** preserve both declared receivers, UDP and TCP/TLS syslog variants, aliases,
  legitimate relays, explicit self-logging, pre-window agent processes, receiver-only observation,
  source-local drop/delay grouping, process-lifetime bounds, port allocation, checkpoint/retry
  determinism, and realistic health-message diversity.

## Loop 96 Result

- **Implementation:** introduced a stable source-routing plan for every system, restricted routes
  to explicitly syslog-capable receivers, attached the live Linux or Windows forwarder process to
  canonical connections, and made every `omfwd` health row own a matching transport occurrence.
  Event-local RNG isolation prevents this family from perturbing unrelated baseline schedules.
- **Verification:** 11,709 routine tests passed with 48 skipped; Ruff check/format and all 92
  packaged config files passed; behavior revision 146 validated at
  `0a16bb0b1dceac986677d3428590d1d2786c739af2cd57022212d43362fcc0d8`.
- **Hard probe:** 29 health messages, 271 process-attributed eCAR flows across all 21 senders, and
  286 Zeek flows used only the two declared receivers, with no self-targets, no missing eCAR
  process identity, one stable route per sender, and 254 exact eCAR/Zeek tuple matches.
- **Assessment:** deterministic score 96.8804/PASS across 122,049 records and 22 sources. Initial
  realism scores 84, 82, 78, and 70 triggered deliberation on verdict disagreement; the chair
  converged on Synthetic at 87% confidence, 64 synthetic-confidence, and mean recalibrated
  realism 76.25.
- **Surviving priority:** canonical process-lifecycle authority permits six eCAR module loads under
  the exact `runas.exe` process identity 45.3 seconds after its visible termination. A future loop
  should enforce every dependent endpoint event between create and terminate at the canonical
  state/timing and source-observation layer.

## Post-Loop 96 Slow-Gate Follow-Up

- **Finding:** the first complete `uv run pytest -m slow --no-cov` run reported one failure in the
  direct continuous-RNG inventory guard because the new rsyslog health transport used a local
  `Random.uniform()` duration draw. The remaining 1,793 tests passed and five platform-specific
  durability tests skipped.
- **Correction:** moved that duration draw onto the engine-owned, event-keyed timing runtime,
  retained the independent event-local RNG for byte texture, and recorded generation behavior
  revision 147 at
  `cf83458286ce8c6732971e96af3dc8971babcb69b1e831d86f5250615d1fc367`.
- **Focused verification:** all 96 Phase 5 system-traffic tests, all three temporal-RNG policy tests,
  all 23 generation-behavior manifest tests, and both fresh-process iteration targets passed.
- **Final extended gate:** `uv run pytest -m slow --no-cov` passed with 1,794 tests, five expected
  skips, and 11,988 deselections in 25 minutes 55 seconds. Ruff check and format validation also
  passed across all 896 files.
