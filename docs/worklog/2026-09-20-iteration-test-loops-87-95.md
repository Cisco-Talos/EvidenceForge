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
