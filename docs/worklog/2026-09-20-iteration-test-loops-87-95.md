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
