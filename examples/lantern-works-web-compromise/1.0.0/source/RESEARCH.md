# Lantern Works Software - Web Server Compromise: design and research

Reviewed 2026-11-16. These are fictional organizations and invented incident details. Public technique descriptions inform the design; no real incident or exact malware-family reproduction is claimed. Scenario commands are synthetic evidence inputs and must not be executed as an authoring step.

## Technique basis

- [T1505.003 — Web Shell](https://attack.mitre.org/techniques/T1505/003/): An uploaded server-side script enables commands under the web service principal. Follow the web and endpoint sequence rather than treating all scanner requests as successful exploitation.

## Composition

- package:evidenceforge:industry:technology@1.0.0; digest `11e90fb8aa02c2a97d55b6a90fb9b7c192470215174f10f2832da6c253c62928`.

## Deliberate boundaries

HTTP upload and command-request evidence are visible on port 80; the later TLS callback content is opaque. The upload represents script bytes by size and MIME, not an executable web-shell file distributed with the example. The secondary helper is fictional. Two canonical-path advisories are retained intentionally: Ubuntu PHP-FPM uses /usr/sbin/php-fpm8.3, and a newly staged helper belongs in /tmp rather than the generic /usr/bin fallback. Neither is an accidental path typo. An attached IDS SID asserts a configured match; the engine does not execute a Snort predicate or prove exploit success from that alert.

## Deterministic execution

The engine renders the authored event plan without LLM calls. Corpora, seed files and metadata are authored inputs. Generation owns causal prerequisites, correlated sibling evidence, lifecycle closure, run manifests and run ground truth. This release contains no generated logs or checkpoints and needs no live callback service.
