# Lantern Works Software - Web Server Compromise

Identify successful server-side execution among noisy probes and scanner alerts.

Planned size: **4 users · 6 hosts · 6 collection hours**, plus one hour of warmup.

- ENVIRONMENT.md is the analyst handout.
- INSTRUCTOR_GUIDE.md contains the questions, intended timeline, answers and limits.
- RESEARCH.md records the technique basis and composition.
- scenario.yaml is the deterministic authored input and contains the solution.

The shipping folder is an immutable Schema 3 release. Copy the entire version directory to a writable location to inspect it; retain release.json, dependencies and configuration. Use the normal scenario draft operation for edits. Keep generated bundles outside this source directory.

From an EvidenceForge checkout, for example:

```sh
uv run eforge validate /path/to/lantern-works-web-compromise/1.0.0/source/scenario.yaml --json
uv run eforge generate /path/to/lantern-works-web-compromise/1.0.0/source/scenario.yaml --output /path/to/runs/lantern-works-web-compromise
```

An installed CLI uses `eforge` instead of `uv run eforge`. The default rendering target is appropriate; SOF-ELK and Splunk targets can be chosen through the ordinary generate options. Inputs work offline. Generated logs and a reviewed evidence-quality report are not included in this release.
