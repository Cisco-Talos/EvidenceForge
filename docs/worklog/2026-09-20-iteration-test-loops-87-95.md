# Iteration-Test Assessment Loops 87–95

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
