# Studio routed topology

Branch `codex/studio-routing-topology` starts from `dev` at `5fea57b4`.

Studio keeps the layout independent of firewall policy scopes. Legacy scenarios display
configured subnet memberships and a default-enabled policy overlay. Scenarios with authored
routing display physical interfaces and start with the overlay off. Link details show the
attached interfaces and TAPs. Ask actions include the linked topology and overlay setting,
and Studio database version 8 accepts existing version 7 drafts and queue records.

The engine resolves connected and longest-prefix static routes in both directions. A missing
route leaves an attempt along the forward prefix and bypasses remote-session and application
success generation. Link TAPs observe authored links and can limit coverage to Internet
traffic. The core-facing TAP in the fixture has this scope. The fixture models linked HQ
and manufacturing sites, a DMZ branch, and NAT on the edge. The legacy INC001 scenario and
its pack serve as read-only references.

## Regression coverage

- The diagram tests replace expectations for firewall-scope wires with assertions about the
  labeled overlay. The DMZ host-expansion fixture uses an authored physical link. Existing
  camera, keyboard, host paging, and sensor badge tests remain in place.
- Routing tests cover IPv4 and IPv6 routes, longest prefix, missing forward and return routes,
  invalid references, asymmetric TAP capture, and aborted SSH and RDP bootstraps. A separate
  bundled test checks emitted Zeek and ASA records against the two-site scenario.
- Pack coverage compares an organization model with the consuming scenario and resolved
  artifact. State migration tests keep the earlier v6-to-v7 transition pinned and exercise
  v7-to-v8 with a draft and queued network attachment.

The targeted Python gate passed 751 tests with one skip. A separate native Snort projection
test passed for the inside and outside TAPs. The extended generation and database recovery gate
passed 146 tests, and all 460 Studio frontend tests passed. The frontend build, generated schema,
behavior manifest, and Ruff checks passed. A fixed-seed legacy smoke run produced seven log
files identical to those generated from `dev`.

The firewall scope overlay now matches colors and outline patterns with the legend, including
when two firewalls classify the same subnet. The color regression covers 13 scopes, palette
reuse, and stable assignment under reordering. All 461 Studio tests and the build passed.

## Routing and visibility edge-case audit

A routed access link now represents the gateway attachment for TAP visibility. Ordinary
same-subnet unicast remains visible to a segment SPAN. A host can reach the gateway's own
interface across the attachment even without a configured default gateway, while an
off-subnet attempt with no gateway reaches no physical link.

Longest-prefix subnet membership now agrees across forwarding, firewall policy, NAT matching,
and sensor visibility. Requests to a static NAT VIP cannot reach the private endpoint along
a path that bypasses the translating firewall. A link TAP uses the actual translation to
choose its tuple, including when an internal client connects to the DMZ VIP. Return-only TAPs
require response packets. Tests exercise routing loops, two enforcing firewalls, addressing
and attachment validation, and local, routed, and Internet-only capture for both IP families.

The bundle regression projects both local and routed HTTP through the configured SPAN and
uplink TAP and verifies the DMZ VIP tuple before and after translation. All 30 selected
generation and composition tests passed. The legacy seed-17 comparison matched all seven
data files from `dev`.

## Dense routed diagram layout

Studio now draws a device's access links in rows next to that device before advancing
along the transit backbone. The Talos Enterprises draft renders all six HQ core subnets
and five manufacturing core subnets with their respective routers. In the same preview
viewport the diagram went from 3,057 to 2,140 layout units high. Each physical attachment
has its own path. Link details are available through an icon on each subnet.

The dense-site regression checks attachment ownership and count, the transit backbone,
and that expanding hosts keeps their subnet rail in place. All 462 Studio tests and the
production frontend build passed. The visual check used the Talos draft read through Studio.

## WAN and VPN link kinds

An omitted `kind` and explicit `network` have the same effective model and serialized
shape. `wan` and `vpn` survive pack composition and resolution. The VPN models routed
reachability, with no encapsulated traffic. Studio draws WAN circuits in blue dash-dot
and VPN tunnels in violet long dashes. The map controls, legend, link inspector, and
diagram chat context identify the kind.

Network and IDS sensors must observe an ordinary link or subnet at the termination.
Validation rejects a WAN or VPN capture named either by `link_tap` or by
`monitoring_segments`. Firewall policy scopes can still name those subnets. The
scenario and organization-pack skills use the same network reference.

The tests cover direct TAP and SPAN rejection, both directions of capture on ordinary
termination links, link kind overrides during composition, and generated records for all
three kinds. All 236 selected Python tests and 463 frontend tests passed. The Studio build,
schema and behavior checks, skill validation, and light and dark diagram previews passed.

## Visualize in the Studio workflow

The scenario workflow now places Visualize between Validate and Generate. Review is
optional and has no completion status. Studio recommends opening the diagram after
successful validation when a generation is due and the diagram has yet to be opened
in that workspace. The organization-pack tab follows Validate & Release.

The routed fixture confirms that the ASA source remains eligible for allowed and denied
traffic it handles even with only the DMZ in its monitored segments. A cross-site path
that bypasses that firewall produces no observation for it. A firewall source cannot
declare a physical link TAP.

All 464 Studio frontend tests and the production build passed.

## Legacy firewall validation

Scenario validation and organization pack reviews warn about firewall sources that
use legacy segment-based visibility. The finding points to `environment.network.routing`
and explains how to bind a firewall device to its sensor. Pack CLI validation and
artifact checks preserve the warning in their structured results. A pack may supply
routing in its own environment or rely on its consuming scenario for the complete model.

The legacy fixture validates with warnings, generates successfully, and emits a native
ASA connection record. The authoring reference directs new firewall models to authored
routing and intentional collection gaps to the standard observation settings.

All 236 selected Python tests and 465 frontend tests passed. The Python checks include
legacy and routed bundle generation, Studio pack reviews, and the pack CLI. The
production build, generated API types, and generation behavior manifest also passed.

## Internet boundary and responsive diagram

Authored Internet boundaries sit above the devices that connect them. Their clouds
replace the empty subnet rails, retain the selectable link and TAP markers, and show
address-family labels when both IPv4 and IPv6 have boundaries.

Dense routed branches reflow between two and four columns as the diagram's available
width changes. The layout preserves manual host expansion choices and zoom. Wheel zoom
anchors on the pointer and requires focus inside the diagram.

The Talos draft preview was checked in a browser at wide and narrow widths. The
regression covers cloud and TAP placement, two Internet boundaries, focus and wheel
handling, and resizing with an open inspector. All 467 frontend tests and the production
build passed.

## Expanded diagram input and subnet details

Expanded view mounts the canvas inside a modal portal. Wheel and resize handlers now
attach to the mounted canvas, and the modal focuses it on entry. Escape returns to
the tab with the selection intact.

The subnet label opens one inspector for subnet facts, hosts, authored interfaces, and
sensor coverage. WAN and VPN labels remain visible on the map. A link TAP's inspector
can navigate back to its subnet or Internet boundary.

All 467 frontend tests and the production build passed. A browser preview using the
saved Talos topology verified wheel zoom in expanded view and the combined transit
subnet inspector.
