# Lantern Works Software - Web Server Compromise: design and research

Reviewed 2026-11-16. These are fictional organizations and invented incident details. Public technique descriptions inform the design; no real incident or exact malware-family reproduction is claimed. Scenario commands are synthetic evidence inputs and must not be executed as an authoring step.

## Technique basis

- [T1505.003 — Web Shell](https://attack.mitre.org/techniques/T1505/003/): An uploaded server-side script enables commands under the web service principal. Follow the web and endpoint sequence rather than treating all scanner requests as successful exploitation.

## Composition

- package:evidenceforge:industry:technology@1.0.0; digest `11e90fb8aa02c2a97d55b6a90fb9b7c192470215174f10f2832da6c253c62928`.

## Deliberate boundaries

The public portal uses HTTPS and a static NAT address. Web access collection is intended to carry the request and response evidence. Passive sensors supply connection and TLS metadata, and the plaintext upload signature is omitted on the encrypted leg. The upload is modeled with synthetic size and MIME metadata. The fictional helper transfer uses the permitted outbound HTTP path, followed by TLS callbacks whose content remains encrypted.

## Deterministic execution

The engine renders the authored event plan without LLM calls. Corpora, seed files and metadata are authored inputs. Generation owns causal prerequisites, correlated sibling evidence, lifecycle closure, run manifests and run ground truth. This release contains no generated logs or checkpoints and needs no live callback service.
