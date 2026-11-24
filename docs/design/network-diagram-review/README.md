# Studio network diagram: UX review and proposal (revised)

Reviewed: `codex/studio-routing-topology` @ `e2864953` (`NetworkDiagram.tsx`, `networkDiagramLayout.ts`,
`studio/topology.py`).

The first draft was built around Talos Enterprises. This revision checks every proposal against
all **47 distinct topologies** found in the repository and the local Studio workspace (scenarios,
fixtures, examples, sample packs, and pack drafts), projected with the same `project_topology` code
Studio uses. Mockups 1–3 use Talos, mockup 4 a legacy segment-model scenario, and mockup 5 a flat
single-subnet scenario, all from real data.

## What the 47 topologies look like

| Shape | Count | Consequence for the design |
|---|---|---|
| Legacy segment model (no `routing`) | **44** | The diagram must be good without routers, links or gateways. Routed-only ideas can't be P0. |
| Authored routing | 3 (two are Talos drafts) | Routed features matter, but they serve a minority today. |
| More than one site (WAN/VPN partition) | 1 | Site grouping is a conditional bonus, not the layout's backbone. |
| A single segment | ~22 | Many diagrams are "one subnet + hosts + a sensor". They should open straight at host detail. |
| Firewall drawn unconnected (legacy) | ~20 | The most widespread visible defect. |
| Hosts without `roles` | common: 67/78, 19/19, 14/14, 11/11… | Role icons need a fallback. `system.type` (workstation / server / domain_controller) is required on every host, so it is always available. |
| A sensor monitoring several segments | most legacy scenarios | The same sensor must read as one identity across zones. |
| Granular log formats (`zeek_conn`, `zeek_dns`, `zeek_http`…) | several | Sensor labels must be derived from the format catalog, not hard-coded. |
| Nested CIDRs (Metrolink `offices` /16 ⊃ `services` /24, 3 hosts in both) | 1 | Hosts need one primary zone (longest prefix, as routing does) and zones need nesting. |
| No network sensors | 1 | Coverage features must degrade cleanly. |
| Static NAT / public IPs | 9 | Internet reachability can be computed. The `exposure` field cannot stand in for it; it only controls the web-client IP mix. |
| Largest subnet | 54 hosts (fixture); Talos 20 | Host views must scale past one screen. |

The model also supports shapes absent from the corpus but legal: IPv6 and dual Internet boundaries,
shared subnets with two devices, switch devices, firewalls in series, and hub-and-spoke WANs.
The proposals below avoid assuming any of them away.

## Generality check of the first draft

| First-draft proposal | Verdict | Change |
|---|---|---|
| Site-aware edge → core → access layout | **Generalized** | The layered layout is ranked by hop distance from an Internet boundary, or from the most-connected device when there is none. A grid of zones fills the canvas aspect. Sites appear only when WAN/VPN links partition the graph, and become collapsible summaries when there are many. |
| Sensors named by evidence | **Kept, made generic** | Labels are derived from `log_formats` through the format catalog (family plus which logs). One sensor keeps one identity across all zones it covers. |
| Zone cards with role icons | **Kept, with fallback** | Icon comes from role, then `type`. Placement uses longest prefix, with nested zones. Small zones list host names when space allows (a space rule, not a fixed count). |
| Tint zones by `exposure` / "DMZ" | **Dropped** | `exposure` means web-client mix, not reachability, and DMZ-ness can't be inferred from names. Zones stay neutral; no subnet is ever tinted for reachability. A public address (static NAT VIP or public IP) is a badge on that host only. |
| Legacy inferred links (was P1) | **Promoted to P0** | This affects about 20 of 47 diagrams. Inference now prefers the firewall's `interfaces` map and falls back to `monitoring_segments` ("observes"). Unattached zones are grouped and labeled. The Internet appears when declared or implied by NAT, `public_cidrs` or public host IPs, and is labeled *inferred*. |
| Coverage lens, one row per origin | **Restructured** | Rows are grouped by outcome, so the list stays short with 50 segments. There is always a "within this subnet" row (flat-network lateral movement) and an Internet row. Disabled with a reason when there are no sensors. Computed by the engine for both legacy and routed models. |
| Search, semantic zoom, chrome, export, firewall/NAT, diff | **Kept** | Already topology-independent. Drill-in gains role-grouped sections and a virtualized table for large subnets. |
| Path trace | **Kept at P3** | Only meaningful with routing; legacy gets segment-level answers from the coverage lens. |

## Revised recommendations, in implementation order

### P0

**1. Draw every relationship the model implies, in the current renderer.**
This is a quick fix that ships before the layout rewrite.
- No device floats. In the legacy model, a firewall's `interfaces` map draws a dashed *inferred
  attachment*. Segments only in `monitoring_segments` get a dotted *observes* link.
- Segments with neither are grouped under "Not attached to a modeled device".
- An *inferred* Internet node appears when NAT, `public_cidrs` or public host IPs exist. If the
  boundary is declared, draw it normally.
- A one-line canvas notice explains the inference and links to routing authoring.

*Function:* every legacy scenario (44/47) gets a connected, honest picture. Nothing is invented
beyond what policy scope, NAT and monitoring already say. See mockup 4.

**2. Enrich the topology projection once, server-side.**
Extend `TopologyGraph` (`studio/topology.py`) with:
- host `type`;
- each host's primary segment (longest prefix) and each segment's parent (nesting);
- each host's public address, if any (a static NAT VIP or a non-RFC1918 IP), from the same rules
  generation uses. Dynamic PAT is outbound-only and segment-wide, so it marks no host;
- per-sensor evidence descriptors from the format catalog;
- firewall interface IPs, NAT and policy summaries;
- provenance flags for inferred links.

*Function:* every later item renders facts instead of re-deriving them in TypeScript. This follows
the compute-once rule, and the diagram can't disagree with generation.

**3. Rewrite the layout and rendering.**
- **Zones:** subnets become zone cards (name, CIDR, sensor chips, then host names or icon counts
  with an OS split), nested where CIDRs nest.
- **Public addresses:** marked per host, never per subnet. At host detail the host card carries a
  `public 203.x.x.x` badge. When a zone is summarized as counts, hosts with a public address are
  listed by name in the card, so they are never hidden inside a count. The badge means the host
  *has a public address*, not that policy permits any inbound flow. Allowed ports come from the
  firewall inspector (item 9) and the coverage lens (item 8).
- **Layering:** devices are layered by distance from the boundary; zones are placed under their
  attachment device and packed to the canvas aspect.
- **Detail:** the level of detail is chosen automatically. If all hosts fit, open at host detail
  (mockup 5); otherwise open at the zone overview (mockups 1 and 4).
- **Sites:** when WAN/VPN links partition the graph, draw site containers. With more than a few
  sites, render them as collapsed summary nodes that expand in place.
- **Links:** point-to-point transits are drawn as labeled links, with `name .octet` at each end
  (just `.1` when the interface is named after the segment).
- **Sensors and hosts:** sensor chips are labeled by evidence, and hovering or selecting one
  highlights every zone it covers. Host icons come from role, then `type`, with an OS badge.
  Hostnames are never truncated mid-string.

*Function:* readable at the default zoom for one subnet through two-plus sites. The layout must
stay deterministic; `elkjs` (layered + orthogonal routing) is worth evaluating against extending
the bespoke engine.

Mockups: `mockup-1-topology.html` (routed, multi-site Talos), `mockup-4-legacy.html` (a firewall
and four segments, iteration-test) and `mockup-5-single-subnet.html` (one flat subnet with no roles,
opening at host detail).

### P1

**4. Canvas-first chrome.**
- Drop the "Network diagram" heading; the tab already says Visualize.
- One toolbar: search, the Topology/Coverage lens, and a single Layers popover. Then Refresh,
  Ask, and an icon-only Expand.
- Zoom floats bottom-right. A collapsible key floats bottom-left and shows only the symbols
  present.
- The inspector overlays the canvas and never moves the camera.

*Function:* about 90 px more canvas, and one place for each control, in every environment.

**5. Search and jump.**
Press `/` to search by hostname, IP prefix, IP-in-CIDR ("which subnet would this address land
in?"), segment or sensor. Enter flies to and selects the result.
*Function:* finding a host without guessing its subnet. Value grows with size, and the
IP-in-CIDR lookup helps authors of any environment.

**6. Semantic zoom and drill-in that scales.**
Double-click a zone to open its host view, with a breadcrumb. Hosts are grouped by role or type.
Above a threshold (about 60 hosts), the group becomes a filterable, virtualized table. Show a
minimap only past the overview zoom. This replaces both existing pagers.
*Function:* inspecting large subnets (54+ hosts today, more in user packs) without paging 12 at
a time. See mockup 3.

**7. Show findings in place.**
Put `graph.findings` (duplicate names, hosts absent from segments, ambiguous references) as
warning badges on the affected entities instead of a list below the canvas.
*Function:* pack authors see where their data is wrong while they fix it.

### P2

**8. Coverage lens, computed by the engine.**
- Zones and links are outlined by the network evidence that observes them: full protocol logs
  and IDS, full protocol logs, connection-only, or nothing.
- Selecting a host answers "which logs see traffic to this host?". Rows are grouped by outcome
  and always include *within this subnet* and *Internet*.
- Hovering a row highlights the path.
- Legacy models use segment monitoring; routed models use forwarding paths. Both come from
  `NetworkVisibilityEngine` and routing on the server.
- When no network sensors exist, the lens is disabled with an explanation.

*Function:* the core hunting question, "will this activity leave network evidence, and of
what kind?" It also exposes blind spots such as conn-only server subnets or uncovered lateral
paths in any environment. See mockup 2.

**9. Firewall and NAT details in the inspector.**
Show interfaces with IPs, policy rules and NAT mappings, using the data from item 2.
*Function:* explains denied flows and public addresses seen in logs. Applies wherever a firewall
is declared, including the 9 corpus environments with NAT.

**10. Export the full diagram (PNG/SVG).**
*Function:* add the network map to an attack-free `ENVIRONMENT.md` trainee briefing. Reuses
`captureNetworkView`.

### P3

**11. A→B path trace** (routed models): hops, firewall interfaces and decisions, NAT, and the
sensors on the path. *Function:* check that a storyline step will be visible, or deliberately
invisible, before generating.

**12. Revision diff overlay.** After an Author chat edit, highlight added, removed and changed
segments, hosts and sensors against the previous revision digest. *Function:* verify that the
agent changed only what you asked, for packs and scenarios alike.

### Deliberately not recommended

- **Tinting zones by `exposure` or inferring "DMZ" from names:** ambiguous and often wrong.
- **Free-form node dragging and saved layouts:** persistence and merge burden.
- **Force-directed layouts:** non-deterministic, and they don't look like network diagrams.
- **An always-on minimap at overview zoom:** the overview already fits.

## Data questions surfaced while testing (Talos, not UI)

- `hq-dmz` is `exposure: internal`, so its web server receives only internal clients. If the
  customer portal should see Internet clients, it needs `both` (or `external`) and a reachable
  address. Item 2's reachability badge would show whether it has one.
- `HQ-EDGE-01` lists every `mfg-*` segment in `monitoring_segments` with policy scope `inside`.
  With routing declared, ASA visibility follows forwarding paths, so confirm whether these
  entries are still intended.
- 17 of 85 hosts have no `roles`. They would show `type` icons rather than "unknown", but roles
  give better icons and summaries.

## Files

- `mockup-1-topology.html`, `mockup-2-coverage.html`, `mockup-3-search-zoom.html`: Talos.
- `mockup-4-legacy.html`: `scenarios/iteration-test`.
- `mockup-5-single-subnet.html`: `tests/fixtures/scenarios/medium-dataset.yaml`.
- `mockup.css`, `symbols.svg.part`: shared styles and icons. Open any mockup at 1440×900.
