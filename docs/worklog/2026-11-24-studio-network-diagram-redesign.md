# Studio network diagram redesign

Branch: `feat/studio-network-diagram-redesign`, based on `codex/studio-routing-topology` @ `e2864953`.
Design and prioritized recommendations: [network diagram review](../design/network-diagram-review/README.md).

## Milestones

- **A (P0 + chrome):** server-side projection enrichment, new layout engine (zones, sites, level
  of detail, inferred legacy links), new rendering, canvas-first chrome. Pause for review.
- **B (P1):** search and jump, drill-in with breadcrumb and large-subnet table, findings in place.
- **C (P2/P3):** engine-computed coverage lens, firewall/NAT inspector, export, path trace,
  revision diff.

## Constraints and decisions

- The new `RoutedTopologyGraph` fields all have defaults. Chat records in database version 8 embed
  this model, and v8 is not released yet (it arrived with the routing branch), so the v8 record
  contract is extended in place. If v8 ships before this branch merges, add a v9 record version
  instead.
- Sensor evidence comes from `DEFAULT_SOURCE_CATALOG` and `FORMAT_FAMILIES`. Unknown format names
  pass through unchanged.
- Hosts belong to one primary zone (longest prefix). Public addresses are per host only (static
  NAT `real_ip` or a globally routable IP). Dynamic PAT marks nothing.
- Legacy firewalls attach through `interfaces` (inferred) or `monitoring_segments` (observes).
  The Internet is inferred only when a firewall exists to attach it to.

## Progress

### Milestone A (implemented, awaiting review, uncommitted)

- `studio/topology.py` projects host `type`, `primary_segment_id`, `public_address(_source)` via
  `NetworkVisibilityEngine.get_public_inbound_address`, segment `parent_id`, per-sensor `evidence`,
  firewall `nat_rules`/`policy`/`default_action`, and graph `public_cidrs`. TS types regenerated.
- `networkDiagramLayout.ts` was rewritten as model plus layout:
  - Root rule: Internet-facing, then inter-site (WAN/VPN), then firewall, then most connected.
  - Zones go to the declared gateway, else the attached device nearest the root.
  - A zoneless leaf device sits beside its parent.
  - Sites are split at WAN/VPN links, with more than four collapsing.
  - The column count and the host/overview level of detail are chosen to fit the viewport.
  - Legacy inferred and observes links, and an inferred Internet only when a firewall exists.
- `NetworkDiagram.tsx` was rewritten:
  - Zone cards, evidence chips with cross-zone highlighting, and a details panel that overlays
    the map.
  - A Layers menu, a floating zoom and key, the legacy notice in the toolbar, and an sr-only
    heading.
  - `sensor_key` is sent empty (no letter marks).
- Checks:
  - `npx vitest run`: 48 files, 465 tests pass.
  - `npm run build` and `npm run types:check` pass.
  - Studio, routing and migration pytest: 131 pass.
  - Ruff check and format are clean.
- Renders across Talos, iteration-test, Metrolink, medium-dataset, routed-two-site and the
  warmup fixture are in `docs/design/network-diagram-review/images/milestone-a-*.jpg`.
- Known follow-ups for review: the floating key can cover the lower canvas in shorter windows
  (it is collapsible). Multiple zoneless leaf children only place the first beside the parent.

### Milestone A review changes (2026-11-24)

- Chips name the tool only ("Zeek", "Snort"). The hover text lists the Zeek logs a sensor writes.
  The evidence `depth` stays in the projection for the coverage lens.
- The Firewalls layer was removed: forwarding devices are always drawn. Layers has info tooltips.
- **Show on map** expands a summarized subnet or collapsed site first. Reveal avoids the key and
  the details panel.
- Site names are derived, not authored: the common subnet-name prefix (shared by at least two
  subnets and half the site), else the root device name. An optional authored site label would
  need a routing-schema addition; it is not implemented.
- Multi-row subnet grids: the first bus now reaches the row gutter, and buses are split at their
  drops. Every segment lights for exactly the subnets whose path runs through it. The gutter sits
  `GUTTER_GAP` (26 px) clear of the cards. A connectivity test parses the rendered wires and fails
  on either earlier behavior.
- Committed as milestone A. Frontend: 48 files, 471 tests pass.
