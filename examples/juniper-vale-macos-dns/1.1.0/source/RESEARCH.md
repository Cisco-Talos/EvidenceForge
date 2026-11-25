# Kestrel Ridge Engineering - macOS Persistence and DNS: design and research

Reviewed 2026-11-16. These are fictional organizations and invented incident details. Public technique descriptions inform the design; no real incident or exact malware-family reproduction is claimed. Scenario commands are synthetic evidence inputs and must not be executed as an authoring step.

## Technique basis

- [T1543.004 — Launch Daemon](https://attack.mitre.org/techniques/T1543/004/): A root/system job retains a definition and launches an installed interpreter. Registration, explicit activation, file removal and unload remain distinct.
- [T1071.004 — DNS](https://attack.mitre.org/techniques/T1071/004/): A bounded synthetic channel uses encoded labels and TXT responses. The authoring model demonstrates DNS abuse without claiming a specific tool's protocol.

## Composition

- package:evidenceforge:industry:technology@1.0.0; digest `11e90fb8aa02c2a97d55b6a90fb9b7c192470215174f10f2832da6c253c62928`.

## Deliberate boundaries

This is a fictional Python agent, not a claim to reproduce a named malware family or supply a runnable payload. The script is represented by pre-existing modeled storage and exact invocation; DNS wire behavior is authored through dns_tunnel. RunAtLoad is false, activation is explicit, and no reboot, KeepAlive or timer behavior is asserted. Native plist artifacts and launchd Unified Log messages are unavailable; use eCAR file evidence and native process evidence for their respective observations. Complete native process-start coverage is requested; an unsupported launch must fail rather than silently omit its start. Unload does not fabricate a known successful exit result. The shared DNS event cannot explicitly bind a payload process; any inferred resolver transport owner must not be treated as proof of origin. Missing direct linkage is the accepted collection boundary and a separate P1 engine backlog item.

## Deterministic execution

The engine renders the authored event plan without LLM calls. Corpora, seed files and metadata are authored inputs. Generation owns causal prerequisites, correlated sibling evidence, lifecycle closure, run manifests and run ground truth. This release contains no generated logs or checkpoints and needs no live callback service.

## Version 1.0.1 deployment repair

Retain standard machine software and restrict only per-user application assignments. The original machine-wide whitelist excluded /bin/sh, which the pre-existing root foothold requires. No collection window, user/host count or attack sequence changed.

## Version 1.0.2 organization rename

Renamed the fictional organization and its host prefixes, email domains, sensor and updater artifacts consistently. Pack selection, collection scope, timing and learning objectives are unchanged. The stable scenario identifier preserves the existing Studio version family.
