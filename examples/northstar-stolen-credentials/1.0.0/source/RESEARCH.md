# Northstar Health - Stolen Credentials: design and research

Reviewed 2026-11-16. These are fictional organizations and invented incident details. Public technique descriptions inform the design; no real incident or exact malware-family reproduction is claimed. Scenario commands are synthetic evidence inputs and must not be executed as an authoring step.

## Technique basis

- [T1021.001 — Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001/): Stolen operator credentials are used for interactive access from a clinical workstation to a file server. The RDP bundle owns transport, client/session identity and closure.

## Composition

- package:evidenceforge:industry:healthcare@1.0.0; digest `91f369c55113c940a9a907282b53fcc5629c54d3b91b79a869814cbcb7b82220`.
- package:evidenceforge:organization:northstar-health@1.1.0; digest `2b5c2142e4eae824e8a4463c914c6916661ed92817e3c9d7fd1be4d2cf891db1`.

## Deliberate boundaries

The service binary is an invented staged artifact; service registration does not prove successful service execution, and no such execution is asserted. The Windows administrative-share and clinical-share operations use separate permissions and purposes. No data destruction or external exfiltration is modeled. The scenario intentionally overrides the pack's firewall default to permit the modeled routed traffic while retaining its host/user roster.

## Deterministic execution

The engine renders the authored event plan without LLM calls. Corpora, seed files and metadata are authored inputs. Generation owns causal prerequisites, correlated sibling evidence, lifecycle closure, run manifests and run ground truth. This release contains no generated logs or checkpoints and needs no live callback service.
