# Alderbrook Lending - Insider Data Theft: design and research

Reviewed 2026-11-16. These are fictional organizations and invented incident details. Public technique descriptions inform the design; no real incident or exact malware-family reproduction is claimed. Scenario commands are synthetic evidence inputs and must not be executed as an authoring step.

## Technique basis

- [T1567.002 — Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002/): A valid employee account sends staged review data to a personal file-transfer workspace. The exercise's authorization premise is supplied to instructors rather than inferred from a TLS session alone.

## Composition

- package:evidenceforge:industry:finance@1.0.0; digest `6ac9a23a29d34d44181260f0445542dd3340c6dafab12c7a129f6c3aa03e8971`.

## Deliberate boundaries

There is no stolen account, exploit or malware in this storyline. Permission to read a share does not establish permission to export its data. The intended upload is file-backed multipart, but TLS keeps its form fields and archive contents out of network HTTP/file inspection. Use endpoint command/file evidence with connection bytes, destination and timing. The exact archive bytes and any generated transfer evidence are owned by generation, not a prewritten ZIP shipped here.

## Deterministic execution

The engine renders the authored event plan without LLM calls. Corpora, seed files and metadata are authored inputs. Generation owns causal prerequisites, correlated sibling evidence, lifecycle closure, run manifests and run ground truth. This release contains no generated logs or checkpoints and needs no live callback service.
