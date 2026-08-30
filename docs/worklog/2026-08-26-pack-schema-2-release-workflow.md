# Pack Schema 2.0 release workflow

## Objective

Complete the breaking pre-release pack workflow: authoritative publisher identity,
publisher-qualified references and repositories, manifest constraints plus exact locks,
immutable release consent/discovery/hydration, and distinct Northstar/MetroLink scale consumers.

## Decisions

- Schema 1.0 and unqualified CLI/YAML references are rejected without compatibility aliases.
- Publisher configuration is explicit at user or project scope; project wins and no identity is derived.
- Manifest dependencies own source/publisher/type/name/constraint. Locks alone own exact versions/digests.
- Immutable releases never resolve implicitly. Hydration explicitly copies a complete locked closure.
- Publisher consent is repeated on every import and acknowledges namespace only, not authenticity.

## Completed implementation

- Core models, repository paths, catalog namespaces, selected provenance, and package indexes are
  publisher-qualified.
- Publisher show/set/clear and lock preview/apply commands are implemented.
- Manifest constraints and exact locks have one-to-one validation; runtime composition uses the
  locked version and digest as authority.
- Import validates the complete bounded archive graph before requiring fresh per-publisher consent.
- Project and user release libraries are immutable and non-resolving; resilient inventory reports
  corrupt entries without hiding valid releases, and hydration atomically copies a full closure.
- Shipped packs and Meridian are migrated to Schema 2.0; Northstar is small and MetroLink medium.
- Pack-management, pack-release, scenario, industry-pack, and organization-pack skills document the
  qualified identity, lock, consent, discovery, and hydration workflows.

## Verification

- `uv run ruff check .` and `uv run ruff format --check .` pass.
- Routine gate: 8,176 passed, 5 skipped, 2,058 deselected.
- Focused publisher CLI regression after the routine gate: 2 passed.
- Focused archive/immutable-library hardening regression after the routine gate: 10 passed.
- MetroLink slow gate: 8 passed, 1 deselected in 218.74 seconds.
- Meridian pack validation and `scenarios/iteration-test/scenario.yaml` validation pass.
- Freshly installed pack, pack-release, scenario, industry-pack, and organization-pack skills pass
  the skill validator.
- No soak test was added; the medium run demonstrated no distinct capacity failure.
