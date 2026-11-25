# Cedar Vale Advisory - Invoice Phishing: design and research

Reviewed 2026-11-16. These are fictional organizations and invented incident details. Public technique descriptions inform the design; no real incident or exact malware-family reproduction is claimed. Scenario commands are synthetic evidence inputs and must not be executed as an authoring step.

## Technique basis

- [T1566.002 — Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/): A supplier-themed link leads to the offered reconciliation helper. Message delivery, user action and process execution remain separate stages.

## Composition

- package:evidenceforge:industry:finance@1.0.0; digest `6ac9a23a29d34d44181260f0445542dd3340c6dafab12c7a129f6c3aa03e8971`.

## Deliberate boundaries

SMTP STARTTLS and IMAPS protect message contents on the wire. Use the generated email artifacts for message content; a mailbox-access session does not prove which message a person read. External web/mail systems have no defender endpoint logs. Scheduled-task creation is modeled; this exercise does not claim a later reboot or task-triggered re-execution. Cleartext HTTP is deliberate for the document-delivery and tasking portions of this introductory example.

## Deterministic execution

The engine renders the authored event plan without LLM calls. Corpora, seed files and metadata are authored inputs. Generation owns causal prerequisites, correlated sibling evidence, lifecycle closure, run manifests and run ground truth. This release contains no generated logs or checkpoints and needs no live callback service.
