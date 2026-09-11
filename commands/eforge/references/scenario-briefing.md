---
description: "Attack-free ENVIRONMENT.md construction from the effective scenario"
---

# ENVIRONMENT.md Briefing

Create `ENVIRONMENT.md` beside the authored scenario only when requested or when the authoring
workflow calls for the analyst briefing. It describes the effective environment and available
evidence, never the attack solution.

For pack-backed input, validate and resolve first, then derive the briefing from the resolved
effective environment. Do not infer pack-provided users, systems, topology, storage, or baseline
from manifests alone. For monolithic input, use the validated authored environment.

Use the opt-in, non-writing model payload only for this effective-model task:

```bash
eforge resolve <scenario> --explain-composition --json \
  --include-effective-scenario
```

Read the stable `effective_scenario` object and do not create a temporary resolved artifact.

Include:

- organization overview, timezone, UTC offset at scenario time, UTC data window, and approximate
  user/system counts;
- representative legitimate user directory and system inventory;
- subnets, topology, sensor placement, and factual collection boundaries;
- selected canonical data sources and relevant source-native limitations;
- modeled email, proxy, storage, or Sysmon policy context when it helps analysts interpret absence.

Exclude storyline, red-herring, suspicious-activity, attacker, technique, indicator, detection,
ground-truth, and answer-key information. Exclude attacker-created accounts and artifacts. Include
compromised legitimate users only as ordinary directory entries.

Sort stable inventories predictably. Use natural job titles rather than persona codes. State that
emitted timestamps are UTC and convert business hours to UTC for the scenario date. Describe blind
spots factually without editorializing about the hunt.

After an authored, pack, or project-config change, treat the briefing and adjacent generated bundle
as stale until they are regenerated from the new effective scenario.
