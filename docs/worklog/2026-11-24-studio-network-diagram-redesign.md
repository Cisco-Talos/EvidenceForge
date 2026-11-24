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
- Renders were checked on Talos, iteration-test, Metrolink, medium-dataset, routed-two-site and the
  warmup fixture. Review images were not kept in the repository.
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

### Milestone B (implemented, awaiting review, uncommitted)

- `networkSearch.ts`: matches hostnames, IP and public-address prefixes, subnet names and CIDRs,
  sensors and devices. A complete IPv4 or IPv6 address also finds its most specific containing
  subnet, using BigInt prefix math. Unit tests: `tests/networkSearch.test.ts`.
- Search box: `/` shortcut (ignored while typing and in hidden tabs), arrow keys and Enter.
  Choosing a result runs a staged reveal: hidden layer → collapsed site → subnet host detail →
  center. Sensors and links reveal through something they connect to.
- Drill-in: double-click or **Focus subnet** fits the subnet at host detail, with a
  breadcrumb (Escape or **Overview** to return). A minimap appears when focused or zoomed in.
- The details host list is filterable, and lists over 60 rows render only the rows in view.
  Choosing a row reveals the host; this replaces the 12-per-page pager.
- Findings mark their subnet, device, sensor or host. Accessible names gain ", N findings". The
  list below the map links to findings it can show.

### Milestone B review changes (2026-11-24)

- Review images were removed from the milestone A commit (amended to `4b11a673`) and from disk.
- The "Mfg ×" popup came from macOS text suggestions in WebKit. Search and filter fields now set
  `autocomplete`, `autocorrect`, `autocapitalize` off and `spellcheck` false.
- The site crumb is selectable, and double-clicking a site label also focuses the site. Sites have
  `site:<id>` bounds in the scene. A collapsed site expands before the fit.
- The host filter appears for any subnet with more than one host. Rows are two lines (name, then
  address and OS).
- The details header has the title and close button on one row, with compact actions below.
- The minimap view box can be dragged.
- No repository or workspace environment yields diagram findings: resolution and pack validation
  reject those conditions first (checked with a dangling `segment.systems` reference). Badges are a
  safety net, covered by tests.
- Collapsed sites: devices inside are tracked as hidden. Links internal to the site, its Internet
  boundary, interface labels and TAP chips are skipped; cross-site links end at the card, which is
  drawn above the links. Cards size to their summary and carry no frame padding.
- Scene size comes from every drawn element (wire points, labels, chips, cards, devices, clouds,
  sites), so Fit shows everything; covered by an extent test. `.diagram-viewport` gets
  `transform: translateZ(0)` against WebKit repaint trails while panning (to confirm in the app).
- Internet boundaries are drawn in a band above every site, outside the device trees, centered over
  the devices they serve, and spread `CLOUD_SPACING` apart. Uplinks end at a collapsed site's card.
  Internet-facing components share the top row. An inferred boundary fans out to every NAT firewall.
- Sites wrap only when one row would exceed the canvas width. Stacked sites link through the gap
  between them.
- Labeled links have a minimum length: label width plus `LABEL_PAD` on each side.
  - Gaps between neighbouring sites widen to fit their links' labels, with the jog near the right site.
  - Side links fit their name, end labels and chips.
  - Blocks reserve width for gutter link labels.
- An invariant test checks that link labels never overlap subnets, devices or collapsed cards, and
  that cross-site labels never overlap sites.

### Milestone C (implemented, awaiting review, uncommitted)

- `project_coverage` (topology.py) asks `NetworkVisibilityEngine.get_observing_sensors` and
  `routed_connection` about every ordered pair of subnets plus the Internet, using one
  representative address each (a real host, else an address near the range start; Internet from
  documentation ranges outside every segment). Talos: 396 paths, about 150 KB, 1.3 s. It is stored
  as `RoutedTopologyGraph.coverage` and left out of chat contexts.
- `networkCoverage.ts`:
  - Tiers: full, protocol, alerts, connection, firewall, none.
  - A subnet's weakest inbound tier drives the lens outline.
  - Rows are grouped by tier, with path tracing through links, forwarders, endpoints and sensors.
- Firewall details list NAT and policy.
- Export: a split button saves a PNG of exactly the current view; the menu copies it instead.
  Desktop saving uses a new narrow Tauri command, `save_diagram_image` (`src-tauri/src/diagram_export.rs`):
  - It takes the PNG as the raw IPC body and checks the signature, IHDR and a 64 MB limit.
  - The native save dialog starts in the remembered export folder.
  - The write is atomic, through a temporary sibling and a rename.
  - It adds no service route and does not change the `save_studio_export` allowlist.
  - Rust tests cover the PNG check, name sanitizing and header decoding.
- The lens outline uses inbound traffic from other subnets and the Internet only. Traffic within a
  subnet shows separately as "Unobserved within". Transit-link segments are excluded from peers.
- The toolbar order is Layers, lens, search, name, Ask, Refresh, Export, Expand.
- `networkDiff.ts`: a session-scoped "last shown revision" per item (`historyKey`). It is read
  purely during render and recorded in an effect, so it is StrictMode safe.
- Tests found a real duplicate-key bug: the coverage section and host list shared a key.

### Milestone C review follow-ups

- The toolbar stays on one row: the search box shrinks to 200px and the name truncates first. It
  wraps only below an 820px container. **Ask** shows an icon and a short label, and **Layers**
  shows its count only when a layer is hidden. Export feedback floats under the toolbar, and the
  segment-based notice sits below it.
- Links between stacked sites no longer cross subnet cards. Each end leaves its site straight
  down or up when the run is clear. Otherwise it runs along the device's row to the frame's inner
  padding and down that edge (`crosses`, `orthogonalPath` in `networkDiagramLayout.ts`).
- The Coverage lens is renamed **Visibility**, matching the industry term and
  `NetworkVisibilityEngine`. Internal identifiers still say coverage.
- Firewall rule filter (6+ rules), `firewallRuleFilter` in `networkSearch.ts`:
  - A full IP address matches the rules that apply to it, as `firewall_policy.py` evaluates them.
  - A port number matches listed ports exactly; other input matches text.
  - Filtered rules keep their policy numbers.

