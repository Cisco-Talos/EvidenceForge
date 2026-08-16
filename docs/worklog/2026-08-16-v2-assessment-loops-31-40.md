# EvidenceForge V2 assessment loops 31–40

This worklog continues the explicit `eforge-assess` run after Loops 21–30. The user requested ten
additional loops, so this effort covers Loops 31 through 40 using the same deterministic scenario,
strict six-hour blind window, family-level contract/fix/probe workflow, fresh four-person panels,
and standalone-score dashboard policy.

## Starting state

- Loop 30 automated evaluation: 97.2016 over 86,077 records.
- Loop 30 standalone blind scores: 52/48/43/78 (average 55.25).
- Loop 30 deliberated result: likely synthetic, 69.5.
- Next accepted family: scanner endpoint FLOW observations preceding their owning nmap process
  CREATE. Subsequent ranked families include RDP post-logout dependents, cross-build Windows binary
  identity, RDP bootstrap/session-ID consistency, proxy DNS precision, and failed-SSH process close.

## Loop 31 family contract — process-owned scanner source ordering

- **Finding/classification:** Loop 30's repeated eCAR `nmap` FLOW-before-CREATE inversion is a
  `sibling_defect` in the endpoint/eCAR process-and-flow ownership family. The Loop 30 CIDR change
  correctly expanded address-space effects, but exposed the pre-existing mismatch between the scan
  bundle's canonical start anchor and the owning process's independently delayed eCAR CREATE.
- **Owning abstraction/layer:** `NmapCommandProbeActionBundle` owns the process-to-probe lifecycle;
  `SourceTimingPlanner` owns eCAR CREATE/FLOW observation ordering. The activity-generator adapter
  must obtain one source-visible readiness anchor from the timing owner and give that anchor to both
  discovery and connect-scan siblings before they request canonical network connections.
- **Family invariant:** Every eCAR FLOW emitted for an explicit process-owned nmap probe must be
  strictly later than that exact process instance's eCAR CREATE. The full probe set keeps its
  deterministic concurrent offset distribution and process hold through the latest transport close.
  If another connection family has no admissible process-visible FLOW interval, the generic network
  contract continues to omit unsafe actor identity rather than invent or move an unrelated process.
- **Entry paths:** Linux and Windows user-process creation through `generate_process`; command-derived
  `-sn`/legacy `-sP` discovery; TCP connect scans with separated or attached `-p`; explicit IP,
  full-CIDR, and bounded large-CIDR targets. Storyline `port_scan`, web scan, scheduled benign scan,
  raw network events, and inferred background owners do not use this process-command adapter.
- **Consumers:** canonical network state and process holds; eCAR outbound FLOW and PROCESS/CREATE;
  Zeek conn; firewall/IDS visibility; workload estimation; generated-output scan probes and eval.
- **Layer rationale:** The nmap bundle alone knows that the entire dense probe family is causally
  owned by one already-created process. An emitter-only clamp would either place short FLOWs outside
  their canonical intervals or hide the contradiction by stripping identity, while a global network
  shift would alter unrelated transports. Source timing remains authoritative for the process-visible
  anchor; the action bundle adapts both scan modes to it once.
- **Sibling risks:** Covered siblings are discovery/connect mode, modeled/silent targets, explicit/CIDR
  operands, and Linux/Windows owners. Out of scope are external scanner storylines without endpoint
  processes and the generic short-flow identity-omission policy. Tests must prove strict eCAR order,
  retained PID attribution, concurrent scan-window width, and process hold coverage.

### Loop 31 implementation and verification handoff

- Added one deterministic process-source-ready anchor to the nmap command adapter and reused it for
  every discovery/connect probe before applying the existing dense concurrent offsets. The generic
  connection timing and unsafe-identity omission contracts were not changed.
- Added Windows `nmap.exe` recognition as an OS sibling of Linux `nmap`; target parsing, bounded CIDR
  planning, service outcomes, and workload admission remain shared.
- Focused rendered-plan probes cover all 1,270 TCP `/24` effects, all 254 ICMP `/24` effects, and an
  explicit Windows TCP target. Every endpoint event retains a safe exact-process identity and has a
  dispatcher-finalized outbound eCAR FLOW time strictly after CREATE; relative scan windows and
  process holds remain bounded.
- Verification: 709 relevant activity/source-timing/eCAR/process-lifetime/bulk-event tests passed;
  full suite passed with 6,074 tests and 22 skips; Ruff check and format check passed. Generation,
  commit, and loop artifacts remain for the parent loop owner as requested.
