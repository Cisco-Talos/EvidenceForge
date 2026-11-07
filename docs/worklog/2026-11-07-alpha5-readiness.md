# Alpha 5 preparation and automated readiness

The user explicitly requested the next alpha version bump and items 1–2 of the
remaining readiness plan: full automated release validation and a bounded longer
Mac/mixed-fleet resource measurement. Studio interactive acceptance remains for
the user. This authorizes preparation/testing, not tagging or publication.

Current source is `codex/macos-workstation-support`, HEAD `42d6440a`, with the
previously authorized implementation/documentation changes still uncommitted.
Remote tags confirm alpha 4 is the latest alpha; alpha 5 is unused. Target product
version is 2.2.0a5, with derived Studio version 2.2.0-alpha.5. The explicit request
authorizes preparing version files here; the normal release commit/integration on
dev remains separate from this working-tree preparation and the Studio hold.

CI needs a committed exact snapshot. Prepare an isolated validation branch with
read-only test/build workflows, retaining the original workspace and excluding
generated blind-review artifacts from the validation snapshot. Do not open a PR
into dev, move main/dev or create/push a release tag. Record exact source hashes,
workflow differences and validation commit/run IDs. Native platform CI/installer
success cannot be claimed from local Mac-only checks.

Planned checks: version/behavior/config/lint checks; known timing inventory and
older Mac extended regressions; routine pytest and enforced 70% Linux coverage;
all four slow shards without coverage; Python portability; Studio/frontend/Rust/
state recovery on supported native platforms; verified preview DMG and both Linux
AppImages. Do not weaken independent assertions or increase timing inventory caps
to hide failures. No soak campaign is part of this request.

Use one bounded longer Mac-inclusive workload with checkpointing on an otherwise
idle reference host. Record wall runtime, peak process-tree RSS, sampled working
disk, committed checkpoint size and completion/coverage. Measurement is not a
general scalability guarantee or Studio acceptance. Work remains pending.
