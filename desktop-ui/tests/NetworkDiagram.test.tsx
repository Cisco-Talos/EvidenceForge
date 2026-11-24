import "@testing-library/jest-dom/vitest";
import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, test, vi } from "vitest";
import type { CatalogItem, PackTopology, StudioApi, StudioEvent, TopologyGraph } from "../src/api";
import { NetworkDiagram } from "../src/NetworkDiagram";
import * as capture from "../src/captureNetworkView";
import { PackEnvironmentView } from "../src/PackEnvironmentView";
import { chooseInitialBranches, indexDiagramHosts, layoutNetworkDiagram } from "../src/networkDiagramLayout";

const graph: TopologyGraph = {
  segments: [{ id: "segment:office", name: "office", cidr: "10.0.0.0/24", exposure: "internal", description: "" }],
  hosts: [
    ...Array.from({ length: 32 }, (_, index) => ({
      id: `host:${index + 1}`, hostname: `WS-${index + 1}`, ip: `10.0.0.${index + 1}`,
      os: "Windows 11", os_family: "windows", segment_ids: ["segment:office"],
      primary_users: index === 0 ? ["alex"] : [], roles: index === 0 ? ["workstation", "developer"] : [],
    })),
    { id: "host:standalone", hostname: "standalone", ip: "2001:db8::1", os: "macOS 27", os_family: "macos", segment_ids: [] },
  ],
  devices: [
    { id: "device:span", name: "core", hostname: "CORE", kind: "network", placement: "span", direction: "bidirectional", description: "", log_formats: ["zeek"], default_interface: null, associations: [{ segment_id: "segment:office", monitored: true, interface_name: null }] },
    { id: "device:fw", name: "edge", hostname: "FW-01", kind: "firewall", placement: "tap", direction: "inbound", description: "", log_formats: ["cisco_asa"], default_interface: null, associations: [{ segment_id: "segment:office", monitored: true, interface_name: "inside" }] },
  ],
  findings: [{ entity_id: "device:fw", message: "FW-01 refers to a segment absent from this environment." }],
};

afterEach(cleanup);

test("both diagram questions capture the viewport and retain the full topology", async () => {
  const shot = "data:image/png;base64,viewport";
  const captureView = vi.spyOn(capture, "captureNetworkView").mockResolvedValue(shot);
  const onAsk = vi.fn(async () => undefined);
  const user = userEvent.setup();
  try {
    render(<NetworkDiagram graph={graph} revision="resolved" onAsk={onAsk} />);
    await user.click(screen.getByRole("button", { name: "Sensors" }));
    await user.click(screen.getByRole("button", { name: "Ask about this diagram" }));
    expect(onAsk).toHaveBeenLastCalledWith(expect.objectContaining({
      revision: "resolved", topology: graph, image: shot, visible_layers: ["firewalls", "hosts"], selected_id: undefined,
    }));
    await user.click(screen.getByRole("button", { name: /Segment office/ }));
    await user.click(screen.getByRole("button", { name: "Ask about this", exact: true }));
    expect(onAsk).toHaveBeenLastCalledWith(expect.objectContaining({
      selected_id: "segment:office", selection_label: "office", topology: graph, image: shot,
    }));
    expect(captureView).toHaveBeenCalledTimes(2);
    expect(captureView).toHaveBeenCalledWith(screen.getByRole("group", { name: /Network map/ }).querySelector("svg"));
  } finally { captureView.mockRestore(); }
});

test("the diagram separates SPAN markers from firewall scope highlights and preserves selection", async () => {
  const { container } = render(<NetworkDiagram graph={graph} />);
  const user = userEvent.setup();
  const map = screen.getByRole("group", { name: /Network map/ });
  const firewall = screen.getByRole("button", { name: "Firewall FW-01" });
  expect(container.querySelectorAll(".diagram-marker[data-placement='span']")).toHaveLength(1);
  const interfaceCount = container.querySelectorAll("path[data-kind='interface']").length;
  expect(interfaceCount).toBe(0);
  expect(container.querySelectorAll(".diagram-scope-highlight")).toHaveLength(1);
  expect(screen.getByRole("button", { name: "Unassigned hosts" })).toBeVisible();
  expect(screen.queryByRole("complementary")).toBeNull();

  await user.click(firewall);
  const details = screen.getByRole("complementary", { name: "Network diagram details" });
  await user.hover(screen.getByRole("button", { name: "Network sensor CORE, SPAN" }));
  expect(container.querySelectorAll(".diagram-marker[data-active='true']")).toHaveLength(1);
  expect(container.querySelectorAll("path[data-kind='interface']")).toHaveLength(interfaceCount);
  expect(within(details).getByText("Policy scope inside")).toBeVisible();
  expect(firewall).toHaveAttribute("aria-pressed", "true");
  expect(within(details).getByText(/segment absent/)).toBeVisible();
  const scopes = screen.getByRole("button", { name: "Firewall scopes", exact: true });
  expect(scopes).toHaveAttribute("aria-pressed", "true");
  await user.click(scopes);
  expect(container.querySelectorAll(".diagram-scope-highlight")).toHaveLength(0);
  expect(firewall).toHaveAttribute("aria-pressed", "true");

  const transform = () => map.querySelector("g")!.getAttribute("transform");
  const initialTransform = transform();
  await user.click(screen.getByRole("button", { name: "Zoom in" }));
  expect(transform()).not.toBe(initialTransform);
  const zoomedIn = transform();
  fireEvent.keyDown(map, { key: "ArrowRight" });
  expect(transform()).not.toBe(zoomedIn);
  await user.click(screen.getByRole("button", { name: "Fit to view" }));
  expect(transform()).toBe(initialTransform);

  const capture = vi.fn();
  const plot = map.querySelector("svg")!;
  Object.defineProperty(plot, "setPointerCapture", { value: capture });
  fireEvent.pointerDown(plot, { button: 0, pointerId: 1, clientX: 20, clientY: 30 });
  expect(capture).toHaveBeenCalledWith(1);
  fireEvent.pointerMove(plot, { pointerId: 1, clientX: 50, clientY: 45 });
  expect(transform()).not.toBe(initialTransform);
  fireEvent.pointerUp(plot, { pointerId: 1 });
  expect(plot).toHaveAttribute("data-dragging", "false");

  await user.click(screen.getByRole("button", { name: "Sensors" }));
  expect(screen.queryByRole("button", { name: "Network sensor CORE, SPAN" })).not.toBeInTheDocument();
  expect(container.querySelectorAll(".diagram-marker")).toHaveLength(0);
  expect(within(details).getByText("Policy scope inside")).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Firewalls" }));
  expect(screen.queryByRole("button", { name: "Firewall FW-01" })).not.toBeInTheDocument();
  expect(container.querySelectorAll("path[data-kind='interface']")).toHaveLength(0);
});

test("wheel zoom requires diagram focus and keeps the point under the pointer in place", () => {
  render(<NetworkDiagram graph={graph} />);
  const map = screen.getByRole("group", { name: /Network map/ });
  const camera = () => (map.querySelector("svg > g")?.getAttribute("transform")?.match(/-?[\d.]+/g) ?? []).map(Number);
  vi.spyOn(map, "getBoundingClientRect").mockReturnValue(new DOMRect(20, 30, 720, 320));
  const pointer = { clientX: 180, clientY: 120, cancelable: true };
  const original = camera();
  expect(fireEvent.wheel(map, { ...pointer, deltaY: -120 })).toBe(true);
  expect(camera()).toEqual(original);

  act(() => map.focus());
  const worldPoint = ([x, y, scale]: number[]) => [(160 - x) / scale, (90 - y) / scale];
  const before = worldPoint(camera());
  expect(fireEvent.wheel(map, { ...pointer, deltaY: -120 })).toBe(false);
  expect(camera()[2]).toBeGreaterThan(original[2]);
  expect(worldPoint(camera())).toEqual(before.map((value) => expect.closeTo(value, 6)));
  expect(fireEvent.wheel(map, { ...pointer, deltaY: 120 })).toBe(false);
  expect(camera()).toEqual(original.map((value) => expect.closeTo(value, 6)));

  const office = screen.getByRole("button", { name: /Segment office/ });
  act(() => office.focus());
  const focusedScale = camera()[2];
  expect(fireEvent.wheel(office, { ...pointer, deltaY: -3, deltaMode: WheelEvent.DOM_DELTA_LINE })).toBe(false);
  expect(camera()[2]).toBeGreaterThan(focusedScale);
  act(() => screen.getByRole("button", { name: "Fit to view" }).focus());
  const toolbarScale = camera()[2];
  expect(fireEvent.wheel(map, { ...pointer, deltaY: 120 })).toBe(true);
  expect(camera()[2]).toBe(toolbarScale);
});

test("keyboard selection opens bounded host pages and individual host facts", async () => {
  render(<NetworkDiagram graph={graph} />);
  const user = userEvent.setup();
  const office = screen.getByRole("button", { name: /Segment office/ });
  fireEvent.focus(office);
  expect(screen.getAllByText("10.0.0.0/24", { exact: true })[0]).toBeVisible();
  expect(screen.queryByRole("complementary")).toBeNull();
  fireEvent.keyDown(office, { key: "Enter" });
  const details = screen.getByRole("complementary", { name: "Network diagram details" });
  expect(within(details).getByRole("button", { name: "CORE" })).toBeVisible();
  await user.click(within(details).getByRole("button", { name: "WS-1 Windows" }));
  expect(within(details).getByText("Windows 11")).toBeVisible();
  expect(within(details).getByText("10.0.0.1")).toBeVisible();
  expect(within(details).getByText("Primary user")).toBeVisible();
  expect(within(details).getByText("alex")).toBeVisible();
  expect(within(details).getByText("workstation, developer")).toBeVisible();
  expect(within(details).getByText("1–12 of 32")).toBeVisible();
  expect(within(details).queryByRole("button", { name: "WS-13 Windows" })).toBeNull();
  await user.click(within(details).getByRole("button", { name: "Next hosts" }));
  expect(within(details).getByRole("button", { name: "WS-13 Windows" })).toBeVisible();
  expect(within(details).getByText("13–24 of 32")).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Unassigned hosts" }));
  expect(within(details).getByRole("button", { name: "standalone macOS" })).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Hosts" }));
  expect(screen.queryByRole("button", { name: "Unassigned hosts" })).toBeNull();
  expect(screen.queryByRole("button", { name: "standalone macOS" })).toBeNull();
});

test("expanded view starts focused for wheel zoom and preserves layers and the selected subnet", async () => {
  render(<NetworkDiagram graph={graph} context="Branch Office" />);
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: "Sensors" }));
  await user.click(screen.getByRole("button", { name: /Segment office/ }));
  await user.click(screen.getByRole("button", { name: "Expand diagram" }));
  const dialog = screen.getByRole("dialog", { name: "Expanded network diagram" });
  expect(within(dialog).getByText("Branch Office")).toBeVisible();
  expect(within(dialog).getByRole("button", { name: "Sensors" })).toHaveAttribute("aria-pressed", "false");
  expect(within(dialog).getByRole("button", { name: /Segment office/ })).toHaveAttribute("aria-pressed", "true");
  const map = within(dialog).getByRole("group", { name: /Network map/ });
  const plot = map.querySelector("svg")!;
  const transform = () => plot.firstElementChild?.getAttribute("transform");
  expect(map).toHaveFocus();
  const initial = transform();
  fireEvent.wheel(plot, { clientX: 150, clientY: 140, deltaY: -120 });
  expect(transform()).not.toBe(initial);

  act(() => within(dialog).getByRole("button", { name: "WS-1 Windows" }).focus());
  const zoomed = transform();
  fireEvent.wheel(plot, { deltaY: -120 });
  expect(transform()).toBe(zoomed);
  act(() => map.focus());
  await user.keyboard("{Escape}");
  expect(screen.queryByRole("dialog")).toBeNull();
  expect(screen.getByRole("button", { name: /Segment office/ })).toHaveAttribute("aria-pressed", "true");
});

test("dense monitoring keeps sensor badges and firewall scopes separate", async () => {
  const segments: TopologyGraph["segments"] = Array.from({ length: 16 }, (_, index) => ({
    id: `segment:${index}`, name: `subnet-${index}`, cidr: `10.40.${index}.0/24`, description: "",
    exposure: index === 15 ? "external" : "internal",
  }));
  const associations = segments.map(({ id }) => ({ segment_id: id, monitored: true, interface_name: null }));
  const sensors = Array.from({ length: 12 }, (_, index) => ({
    ...graph.devices[0], id: `sensor:${index}`, name: `sensor-${index}`, hostname: `SENSOR-${index}`, associations,
  }));
  const firewall = { ...graph.devices[1], associations: [
    ...associations.slice(0, 6).map((entry) => ({ ...entry, interface_name: "inside" })),
    ...associations.slice(6, 12).map((entry) => ({ ...entry, interface_name: "production" })),
    ...associations.slice(12),
  ] };
  const dense = { segments, devices: [firewall, ...sensors], hosts: [], findings: [] };
  const scene = layoutNetworkDiagram(dense, { sensors: true, firewalls: true, hosts: true }, new Map(), new Set());
  expect(scene.labels).toEqual([]);
  expect(scene.branches.every(({ sensors }) => sensors.some(({ device }) => device.id === "sensor:0"))).toBe(true);
  expect(scene.wires.filter(({ kind, entities }) => kind === "interface" && entities.includes("segment:15"))).toHaveLength(0);
  expect(scene.width).toBeLessThan(1500);
  expect(scene.wires.filter(({ key }) => key.endsWith(":feed"))).toHaveLength(0);
  expect(scene.wires.filter(({ key, kind }) => kind === "interface" && key.startsWith('["segment:'))).toHaveLength(0);
  for (const node of scene.nodes) {
    expect(node.x + node.width).toBeLessThanOrEqual(scene.width);
    expect(node.y + node.height).toBeLessThanOrEqual(scene.height);
  }
  const view = render(<NetworkDiagram graph={dense} />);
  const user = userEvent.setup();
  const markers = () => [...view.container.querySelectorAll(".diagram-marker")];
  expect(markers()).toHaveLength(16 * 7);
  expect(view.container.querySelectorAll(".diagram-scope-highlight")).toHaveLength(12);
  expect(screen.getByRole("button", { name: "Firewall FW-01" })).toBeVisible();
  expect(markers().some((marker) => marker.getAttribute("aria-label")?.includes("FW-01"))).toBe(false);
  await user.click(screen.getByRole("button", { name: /^Segment subnet-15,/ }));
  const details = screen.getByRole("complementary");
  expect(within(details).getByRole("button", { name: "FW-01", exact: true })).toBeVisible();
  expect(within(details).getByText("Monitored by firewall")).toBeVisible();

  await user.click(screen.getByRole("button", { name: /^Segment subnet-0,/ }));
  await user.click(screen.getByRole("button", { name: "Show 5 more sensors on subnet-0" }));
  const extra = screen.getByRole("region", { name: "Additional sensors" });
  expect(within(extra).getAllByRole("button").map((button) => button.textContent))
    .toEqual(sensors.slice(7).map(({ hostname }) => hostname));
  await user.click(within(extra).getByRole("button", { name: "SENSOR-11" }));
  expect(within(details).getByRole("heading", { name: "SENSOR-11" })).toBeVisible();
  const highlighted = markers().filter((marker) => marker.getAttribute("data-active") === "true");
  expect(highlighted).toHaveLength(16);
  expect(new Set(highlighted.map((marker) => marker.textContent))).toHaveLength(1);
});

test.each([6, 8, 9])("a horizontal rail with %i sensors uses overflow only when needed", (count) => {
  const sensors = Array.from({ length: count }, (_, index) => ({
    ...graph.devices[0], id: `sensor:${index}`, name: `sensor-${index}`, hostname: `SENSOR-${index}`,
  }));
  const { container } = render(<NetworkDiagram graph={{ ...graph, devices: sensors }} />);
  const visible = container.querySelectorAll(".diagram-marker");
  expect(visible).toHaveLength(count > 8 ? 7 : count);
  if (count > 8) {
    expect(screen.getByRole("button", { name: "Show 2 more sensors on office" })).toBeVisible();
  } else {
    expect(screen.queryByRole("button", { name: /more sensors on office/ })).toBeNull();
  }
});

test("inline host pages reach all 20 hosts without moving the map", async () => {
  const groups = indexDiagramHosts(graph.hosts);
  expect(chooseInitialBranches(groups, { width: 1000, height: 720 })).toEqual(new Set(["unassigned"]));
  expect(chooseInitialBranches(indexDiagramHosts(graph.hosts.slice(0, 10)), { width: 1000, height: 720 }))
    .toEqual(new Set(["segment:office"]));
  const user = userEvent.setup();
  render(<NetworkDiagram graph={{ ...graph, hosts: graph.hosts.slice(0, 20) }} />);
  expect(screen.queryByRole("button", { name: "WS-1 Windows" })).toBeNull();
  expect(screen.getByRole("button", { name: /Segment office, 10.0.0.0/ })).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Expand office hosts" }));
  expect(screen.getByText("1–12 of 20 hosts")).toBeVisible();
  expect(screen.getByRole("button", { name: "WS-12 Windows" })).toBeVisible();
  expect(screen.queryByRole("button", { name: "WS-13 Windows" })).toBeNull();
  const map = screen.getByRole("group", { name: /Network map/ });
  const firstPage = [...map.querySelectorAll(".diagram-node[data-kind='host']")].map((node) => node.getAttribute("transform")?.split(" ")[1]);
  expect(new Set(firstPage).size).toBe(3);
  const camera = map.querySelector("svg > g")?.getAttribute("transform");
  const next = screen.getByRole("button", { name: "Next hosts on office" });
  const previous = screen.getByRole("button", { name: "Previous hosts on office" });
  expect(previous).toHaveAttribute("aria-disabled", "true");
  await user.click(next);
  expect(screen.getByText("13–20 of 20 hosts")).toBeVisible();
  expect(screen.getByRole("button", { name: "WS-20 Windows" })).toBeVisible();
  expect(next).toHaveAttribute("aria-disabled", "true");
  expect(map.querySelector("svg > g")?.getAttribute("transform")).toBe(camera);
  await user.click(previous);
  await user.click(screen.getByRole("button", { name: "WS-1 Windows" }));
  const details = screen.getByRole("complementary", { name: "Network diagram details" });
  expect(within(details).getByText("alex")).toBeVisible();
  expect(within(details).getByText("workstation, developer")).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Zoom in" }));
  expect(screen.getByRole("button", { name: "Collapse office hosts" })).toHaveAttribute("aria-expanded", "true");
});

test.each([1, 4])("opening a side subnet with %i hosts leaves the map, rail, labels, and sensors in place", async (hostCount) => {
  const dmz = { ...graph.segments[0], id: "segment:dmz", name: "dmz", cidr: "10.3.0.0/24" };
  const dmzMonitoring = { segment_id: dmz.id, monitored: true, interface_name: null };
  render(<NetworkDiagram graph={{
    ...graph,
    segments: [...graph.segments, dmz],
    routing: {
      devices: { edge: { kind: "firewall", firewall: "edge" } },
      links: { dmz: { segment: "dmz", interfaces: { edge: { name: "dmz", ip: "10.3.0.254" } } } },
    },
    hosts: [...graph.hosts, ...Array.from({ length: hostCount }, (_, index) => ({
      ...graph.hosts[0], id: `host:portal-${index + 1}`, hostname: `PORTAL-${index + 1}`, ip: `10.3.0.${index + 1}`,
      os: "Ubuntu", os_family: "linux", segment_ids: [dmz.id],
    }))],
    devices: [
      { ...graph.devices[0], associations: [...graph.devices[0].associations, dmzMonitoring] },
      { ...graph.devices[0], id: "device:tap", name: "DMZ tap", hostname: "DMZ-TAP", placement: "tap", associations: [dmzMonitoring] },
      { ...graph.devices[1], associations: [...graph.devices[1].associations, { ...dmzMonitoring, interface_name: "dmz" }] },
    ],
  }} />);
  const user = userEvent.setup();
  const map = screen.getByRole("group", { name: /Network map/ });
  const dmzLabel = screen.getByRole("button", { name: "Segment dmz, 10.3.0.0/24" });
  const markers = ["CORE SPAN on dmz", "DMZ-TAP TAP on dmz"].map((name) => screen.getByRole("button", { name }));
  const [span, tap] = markers;
  expect(span.querySelector("polygon")).toBeInTheDocument();
  expect(span.querySelector("path")).toHaveAttribute("stroke-dasharray", "4 3");
  expect(tap.querySelector("circle")).toBeInTheDocument();
  expect(tap.querySelector("path")).not.toHaveAttribute("stroke-dasharray");
  const geometry = () => ({
    camera: map.querySelector("svg > g")?.getAttribute("transform"),
    wires: [...map.querySelectorAll(".diagram-edges path:not([data-kind='host'])")].map((wire) => wire.getAttribute("d")),
    interfaceLabels: map.querySelector(".diagram-interface-labels")?.innerHTML,
    subnetLabel: dmzLabel.getAttribute("transform"),
    markers: markers.map((marker) => marker.innerHTML),
  });

  await user.click(screen.getByRole("button", { name: "Collapse dmz hosts" }));
  expect(screen.queryByRole("button", { name: /^PORTAL-\d Linux$/ })).toBeNull();
  await user.click(screen.getByRole("button", { name: "Fit to view" }));
  const collapsed = geometry();
  const hostLinks = () => [...map.querySelectorAll(".diagram-edges path[data-kind='host']")].map((wire) => wire.getAttribute("d"));
  const collapsedLinks = hostLinks();
  await user.click(screen.getByRole("button", { name: "Expand dmz hosts" }));
  expect(screen.getAllByRole("button", { name: /^PORTAL-\d Linux$/ })).toHaveLength(hostCount);
  expect(geometry()).toEqual(collapsed);
  if (hostCount === 1) expect(hostLinks()).toEqual(collapsedLinks);
  await user.click(screen.getByRole("button", { name: "Collapse dmz hosts" }));
  expect(screen.queryByRole("button", { name: /^PORTAL-\d Linux$/ })).toBeNull();
  expect(geometry()).toEqual(collapsed);
});

test("shared policy scopes leave independent subnet rails", () => {
  const scene = layoutNetworkDiagram({
    ...graph,
    segments: [...graph.segments, { id: "segment:lab", name: "lab", cidr: "2001:db8::/64", description: "", exposure: "internal" }],
    devices: [...graph.devices, {
      ...graph.devices[1], id: "device:fw2", name: "second-edge", hostname: "FW-02",
      associations: [{ segment_id: "segment:office", monitored: false, interface_name: "lan" }],
    }],
  }, { sensors: true, firewalls: true, hosts: false }, new Map(), new Set());
  expect(scene.branches.map(({ node }) => node.id)).toEqual(["segment:office", "segment:lab"]);
  expect(scene.labels).toEqual([]);
  const interfaceWires = scene.wires.filter(({ kind }) => kind === "interface");
  expect(interfaceWires).toHaveLength(0);
});

test("named firewall scopes share colors, distinguish overlaps, and extend the palette with outlines", async () => {
  const names = ["inside", "outside", "dmz", "production", "research", "guest", "plant", "wireless", "voice", "storage", "partners", "backup"];
  const segments = [
    ...names.map((name, index) => ({ ...graph.segments[0], id: `segment:${name}`, name, cidr: `10.2.${index}.0/24` })),
    graph.segments[0],
  ];
  const firewall = {
    ...graph.devices[1],
    associations: [
      ...names.map((name) => ({ segment_id: `segment:${name}`, monitored: true, interface_name: name })),
      { segment_id: "segment:office", monitored: true, interface_name: "inside" },
    ],
  };
  const second = {
    ...firewall, id: "device:fw2", name: "edge-2", hostname: "FW-02",
    associations: [{ segment_id: "segment:office", monitored: true, interface_name: "inside" }],
  };
  const topology = { ...graph, segments, hosts: [], devices: [firewall, second] };
  const { container, rerender } = render(<NetworkDiagram graph={topology} />);
  const highlights = (root: ParentNode) => [...root.querySelectorAll<SVGRectElement>(".diagram-scope-highlight")];
  const style = (mark: SVGElement, swatch = false) => [
    (swatch ? mark.parentElement as SVGElement | null : mark)?.style.color,
    mark.getAttribute("stroke-dasharray"),
  ].join(" / ");
  const byScope = () => new Map(highlights(container).map((mark) => [mark.querySelector("title")!.textContent, style(mark)]));
  const initial = byScope();
  expect(new Set(initial.values()).size).toBe(names.length + 1);
  expect(new Set(highlights(container).map((mark) => mark.style.color)).size).toBe(8);
  const shared = highlights(screen.getByRole("button", { name: /^Segment office,/ }));
  expect(shared.map((mark) => style(mark))).toEqual([initial.get("FW-01 · inside"), initial.get("FW-02 · inside")]);
  expect(new Set(shared.map((mark) => mark.getAttribute("x"))).size).toBe(2);

  await userEvent.setup().click(screen.getByText("Firewall scopes (13)"));
  const key = screen.getByRole("list", { name: "Firewall policy scopes" });
  for (const row of within(key).getAllByRole("listitem")) {
    expect(style(row.querySelector(".diagram-scope-swatch")!, true)).toBe(initial.get(row.querySelector("strong")!.textContent));
  }
  rerender(<NetworkDiagram graph={{ ...topology, devices: [second, { ...firewall, associations: [...firewall.associations].reverse() }] }} />);
  expect(byScope()).toEqual(initial);
});

test("declared device membership forms a backbone and keeps the inside network off the core", async () => {
  const transit = { ...graph.segments[0], id: "segment:transit", name: "edge-transit", cidr: "10.2.0.0/30" };
  const dmz = { ...graph.segments[0], id: "segment:dmz", name: "dmz", cidr: "10.3.0.0/24" };
  const edge = { ...graph.hosts[0], id: "host:edge", hostname: "FW-01", ip: "10.2.0.1",
    segment_ids: [transit.id], os: "Cisco ASA", os_family: "unknown", roles: ["firewall"] };
  const core = { ...edge, id: "host:core", hostname: "CORE-01", ip: "10.2.0.2",
    os: "Cisco IOS-XE", roles: ["core_router"] };
  const topology = { ...graph, segments: [...graph.segments, transit, dmz], hosts: [graph.hosts[0], edge, core],
    devices: [graph.devices[0], { ...graph.devices[1], associations: [...graph.devices[1].associations,
      { segment_id: dmz.id, interface_name: "dmz", monitored: false }] }] };
  const groups = indexDiagramHosts(topology.hosts);
  const scene = layoutNetworkDiagram(topology, { sensors: true, firewalls: true, hosts: true }, groups, new Set());
  const firewall = scene.nodesById.get("device:fw")!;
  const router = scene.nodesById.get(core.id)!;
  expect(router.x).toBe(firewall.x);
  expect(router.y).toBeGreaterThan(firewall.y + firewall.height);
  expect(scene.nodesById.has(dmz.id)).toBe(true);
  expect(scene.nodesById.has(edge.id)).toBe(false);
  expect(scene.branches.find(({ node }) => node.id === transit.id)?.vertical).toBe(true);
  const membership = scene.wires.filter(({ kind }) => kind === "membership");
  expect(membership.map(({ entities }) => entities)).toEqual([["device:fw", transit.id], [core.id, transit.id]]);
  expect(scene.wires.some(({ kind, entities }) => kind === "interface" && entities.includes("device:fw") && entities.includes("segment:office"))).toBe(false);
  expect(scene.wires.some(({ entities }) => entities.includes(core.id) && entities.includes("segment:office"))).toBe(false);

  const user = userEvent.setup();
  render(<NetworkDiagram graph={topology} />);
  await user.click(screen.getByRole("button", { name: "Firewall FW-01" }));
  expect(screen.getByRole("complementary")).toHaveTextContent("Cisco ASA");
  await user.click(screen.getByRole("button", { name: "CORE-01 Router" }));
  expect(screen.getByRole("complementary")).toHaveTextContent("core_router");
});

test("empty environments keep the diagram section intelligible", () => {
  render(<NetworkDiagram graph={{ segments: [], devices: [], hosts: [], findings: [] }} />);
  expect(screen.getByText("No network segments are declared.")).toBeVisible();
  expect(screen.queryByRole("button", { name: "Fit to view" })).toBeNull();
});

test("pack requests discard superseded results and allow retry after inspection errors", async () => {
  const item = { id: "office", source_sha256: "old", version: "1.0.0" } as CatalogItem;
  let finishOld: (report: PackTopology) => void = () => undefined;
  const oldRequest = new Promise<PackTopology>((resolve) => { finishOld = resolve; });
  const completed = { source_sha256: "current", reference: "draft:organization:office@current", digest: "digest", topology: graph };
  const request = vi.fn()
    .mockReturnValueOnce(oldRequest)
    .mockRejectedValueOnce(new Error("A locked pack is missing"))
    .mockResolvedValueOnce(completed)
    .mockResolvedValueOnce({ ...completed, topology: { ...graph, segments: [] } });
  const onChanged = vi.fn(async () => undefined);
  let sendEvent: (event: StudioEvent) => void = () => undefined;
  const props = {
    api: { request } as unknown as StudioApi, onChanged,
    subscribeEvents: (listener: typeof sendEvent) => { sendEvent = listener; return () => undefined; },
  };
  const { rerender } = render(<PackEnvironmentView item={item} {...props} />);
  rerender(<PackEnvironmentView item={{ ...item, source_sha256: "current", version: "" }} {...props} />);
  expect(await screen.findByRole("alert")).toHaveTextContent("A locked pack is missing");
  await act(async () => finishOld({ ...completed, source_sha256: "old" }));
  expect(screen.queryByRole("heading", { name: "Network diagram" })).toBeNull();
  await userEvent.setup().click(screen.getByRole("button", { name: "Refresh environment" }));
  expect(await screen.findByRole("heading", { name: "Network diagram" })).toBeVisible();
  expect(onChanged).toHaveBeenCalledOnce();
  expect(screen.getByText("Organization pack fragment · Draft")).toBeVisible();
  act(() => sendEvent({ seq: 1, entity_id: "office", kind: "assets.updated", payload: {} }));
  expect(await screen.findByText("No network segments are declared.")).toBeVisible();
});

test("a routed subnet opens its link and subnet details together and captures the selection for chat", async () => {
  const transit = { ...graph.segments[0], id: "segment:transit", name: "transit", cidr: "10.2.0.0/30" };
  const routed: TopologyGraph = {
    ...graph,
    segments: [...graph.segments, transit],
    routing: {
      devices: { edge: { kind: "firewall", firewall: "edge" }, core: { kind: "router", system: "CORE-01" } },
      links: {
        "edge-core": { segment: "transit", interfaces: { edge: { name: "inside", ip: "10.2.0.1" }, core: { name: "edge", ip: "10.2.0.2" } } },
        office: { segment: "office", interfaces: { core: { name: "office", ip: "10.0.0.254" } } },
      },
      gateways: { office: "core" },
    },
    link_taps: { "device:tap": { link: "edge-core", scope: "internet" } },
    devices: [...graph.devices, { ...graph.devices[0], id: "device:tap", name: "uplink", hostname: "UPLINK", placement: "tap", associations: [] }],
  };
  const scene = layoutNetworkDiagram(routed, { sensors: true, firewalls: true, hosts: true }, new Map(), new Set());
  expect(scene.wires.filter(({ kind, entities }) => kind === "interface" && entities.includes("link:edge-core"))).toHaveLength(2);
  const officeWires = scene.wires.filter(({ kind, entities }) => kind === "interface" && entities.includes("link:office"));
  expect(officeWires).toHaveLength(1);
  expect(officeWires[0].entities).toContain("router:core");
  const onAsk = vi.fn(async () => undefined);
  const { container } = render(<NetworkDiagram graph={routed} revision="routed" onAsk={onAsk} />);
  expect(screen.getByRole("button", { name: "CORE-01 Router" })).toBeVisible();
  const scopes = screen.getByRole("button", { name: "Firewall scopes", exact: true });
  expect(scopes).toHaveAttribute("aria-pressed", "false");
  const user = userEvent.setup();
  const geometry = () => [...container.querySelectorAll(".diagram-edges path")].map((path) => path.getAttribute("d"));
  const wires = geometry();
  await user.click(scopes);
  expect(geometry()).toEqual(wires);
  expect(container.querySelectorAll(".diagram-scope-highlight")).toHaveLength(1);
  expect(screen.queryByRole("button", { name: "Network link edge-core" })).toBeNull();
  await user.click(screen.getByRole("button", { name: /^Segment transit/ }));
  const linkDetails = screen.getByRole("complementary");
  expect(linkDetails).toHaveTextContent("10.2.0.0/30");
  expect(linkDetails).toHaveTextContent("edge-core");
  expect(linkDetails).toHaveTextContent("10.2.0.1");
  expect(linkDetails).toHaveTextContent("10.2.0.2");
  expect(linkDetails).toHaveTextContent("Internet traffic");
  expect(screen.getByRole("button", { name: "UPLINK TAP on transit" })).toBeVisible();
  await user.click(within(linkDetails).getByRole("button", { name: "UPLINK", exact: true }));
  await user.click(within(linkDetails).getByRole("button", { name: "edge-core", exact: true }));
  expect(within(linkDetails).getByRole("heading", { name: "transit", exact: true })).toBeVisible();
  await user.click(within(linkDetails).getByRole("button", { name: "Ask about this", exact: true }));
  expect(onAsk).toHaveBeenCalledWith(expect.objectContaining({
    selected_id: "segment:transit",
    selection_label: "transit",
    topology: routed,
    firewall_scopes_visible: true,
  }));
});

test("WAN and VPN links show their types in the map, legend, details, and diagram questions", async () => {
  const makeSegment = (name: string, cidr: string) => ({ ...graph.segments[0], id: `segment:${name}`, name, cidr });
  const routed: TopologyGraph = {
    ...graph,
    devices: [],
    hosts: [],
    segments: [graph.segments[0], makeSegment("leased", "10.1.0.0/30"), makeSegment("tunnel", "10.2.0.0/30")],
    routing: {
      devices: { hq: { kind: "router" }, hub: { kind: "router" }, branch: { kind: "router" } },
      links: {
        office: { segment: "office", interfaces: { hq: { name: "inside", ip: "10.0.0.1" } } },
        leased: {
          kind: "wan", segment: "leased",
          interfaces: { hq: { name: "wan", ip: "10.1.0.1" }, hub: { name: "wan", ip: "10.1.0.2" } },
        },
        tunnel: {
          kind: "vpn", segment: "tunnel",
          interfaces: { hub: { name: "vpn", ip: "10.2.0.1" }, branch: { name: "vpn", ip: "10.2.0.2" } },
        },
      },
    },
  };
  const onAsk = vi.fn(async () => undefined);
  const { container } = render(<NetworkDiagram graph={routed} revision="typed-links" onAsk={onAsk} />);
  const user = userEvent.setup();
  const key = screen.getByLabelText("Diagram key");
  const wires = (kind: string) => container.querySelectorAll(`.diagram-edges [data-kind="interface"][data-link-kind="${kind}"]`);
  expect(wires("network")).toHaveLength(1);
  expect(within(key).getByText("Network link").querySelector("path")).toHaveAttribute("data-link-kind", "network");
  for (const [kind, name] of [["wan", "leased"], ["vpn", "tunnel"]]) {
    const label = kind.toUpperCase();
    expect(wires(kind)).toHaveLength(2);
    expect(within(key).getByText(`${label} link`).querySelector("path")).toHaveAttribute("data-link-kind", kind);
    const control = screen.getByRole("button", { name: new RegExp(`^Segment ${name},`) });
    expect(control).toHaveTextContent(label);
    await user.click(control);
    expect(screen.getByRole("complementary")).toHaveTextContent(`${label} link`);
    expect([...wires(kind)].every((wire) => wire.getAttribute("data-highlighted") === "true")).toBe(true);
  }
  await user.click(within(screen.getByRole("complementary")).getByRole("button", { name: "Ask about this" }));
  expect(onAsk).toHaveBeenCalledWith(expect.objectContaining({ topology: routed, selected_id: "segment:tunnel" }));
});

test("an authored Internet boundary is a cloud above its firewall with a selectable link and TAP", async () => {
  const secondary = { ...graph.devices[1], id: "device:secondary", name: "secondary", hostname: "FW-02" };
  const tap = { ...graph.devices[0], id: "device:internet-tap", hostname: "UPLINK", placement: "tap" as const, associations: [] };
  const routed: TopologyGraph = {
    ...graph,
    hosts: [],
    devices: [secondary, graph.devices[1], tap],
    routing: {
      devices: { edge: { kind: "firewall", firewall: "edge" }, branch: { kind: "firewall", firewall: "secondary" } },
      links: {
        upstream: { internet: true, interfaces: { edge: { name: "outside", ip: "192.0.2.1" } } },
        office: { segment: "office", interfaces: { edge: { name: "inside", ip: "10.0.0.1" }, branch: { name: "office", ip: "10.0.0.2" } } },
      },
    },
    link_taps: { [tap.id]: { link: "upstream", scope: "all" } },
  };
  const layers = { sensors: true, firewalls: true, hosts: true };
  const scene = layoutNetworkDiagram(routed, layers, new Map(), new Set());
  const cloud = scene.branches.find(({ node }) => node.id === "internet:upstream")!;
  const edge = scene.nodesById.get("device:fw")!;
  expect(cloud.node.x + cloud.node.width / 2).toBe(edge.x + edge.width / 2);
  expect(cloud.node.y + cloud.node.height).toBeLessThan(edge.y);
  expect(edge.y).toBeLessThan(scene.nodesById.get(secondary.id)!.y);
  const uplink = scene.wires.filter(({ entities }) => entities.includes("link:upstream"));
  expect(uplink.map(({ kind, entities }) => [kind, entities])).toEqual([
    ["interface", ["device:fw", "internet:upstream", "link:upstream"]],
  ]);

  const { rerender } = render(<NetworkDiagram graph={routed} />);
  expect(screen.getByRole("button", { name: "Internet", exact: true }).querySelector(".lucide-cloud")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "UPLINK TAP on Internet" })).toBeVisible();
  await userEvent.setup().click(screen.getByRole("button", { name: "Internet", exact: true }));
  expect(screen.getByRole("complementary")).toHaveTextContent("upstream");
  expect(screen.getByRole("complementary")).toHaveTextContent("All traffic");
  expect(screen.getByRole("complementary")).toHaveTextContent("192.0.2.1");

  const dual = {
    ...routed, routing: { ...routed.routing!, links: { ...routed.routing!.links,
      upstream6: { internet: true, interfaces: { branch: { name: "outside6", ip: "2001:db8::1" } } },
    } },
  };
  rerender(<NetworkDiagram graph={dual} />);
  expect(screen.getByRole("button", { name: "Internet (IPv4)", exact: true })).toBeVisible();
  expect(screen.getByRole("button", { name: "Internet (IPv6)", exact: true })).toBeVisible();
  const secondEdge = layoutNetworkDiagram(dual, layers, new Map(), new Set());
  const ipv6 = secondEdge.nodesById.get("internet:upstream6")!;
  expect(ipv6.y + ipv6.height).toBeLessThan(secondEdge.nodesById.get(secondary.id)!.y);
  expect(secondEdge.wires.find(({ entities }) => entities.includes("link:upstream6"))?.entities).toContain(secondary.id);
});

test("dense routed sites keep their links and host choices when the diagram changes width", async () => {
  const hq = Array.from({ length: 6 }, (_, index) => `hq-lan-${index + 1}`);
  const plant = Array.from({ length: 5 }, (_, index) => `plant-lan-${index + 1}`);
  const backbone = [
    ["edge-uplink", "edge", "hq"],
    ["hq-uplink", "hq", "vpn"],
    ["site-transit", "vpn", "plant"],
    ["plant-uplink", "plant", "remote"],
  ];
  const declared = [...backbone, ...hq.map((name) => [name, "hq"]), ...plant.map((name) => [name, "plant"])];
  const routed: TopologyGraph = {
    ...graph,
    devices: [graph.devices[1]],
    hosts: graph.hosts.slice(0, 10).map((host) => ({ ...host, segment_ids: [`segment:${hq[0]}`] })),
    segments: declared.map(([name, , peer], index) => ({
      ...graph.segments[0], id: `segment:${name}`, name, cidr: `10.0.${index}.0/${peer ? 30 : 24}`,
    })),
    routing: {
      devices: {
        edge: { kind: "firewall", firewall: "edge" },
        hq: { kind: "router" },
        vpn: { kind: "router" },
        plant: { kind: "router" },
        remote: { kind: "router" },
      },
      links: Object.fromEntries(declared.map(([name, ...devices], index) => [name, {
        segment: name,
        interfaces: Object.fromEntries(devices.map((device, port) =>
          [device, { name, ip: `10.0.${index}.${port + 1}` }])),
      }])),
      gateways: Object.fromEntries([...hq.map((name) => [name, "hq"]), ...plant.map((name) => [name, "plant"])]),
    },
  };
  const layers = { firewalls: true, sensors: true, hosts: true };
  const hosts = indexDiagramHosts(routed.hosts);
  const collapsed = layoutNetworkDiagram(routed, layers, hosts, new Set());
  const expanded = layoutNetworkDiagram(routed, layers, hosts, new Set([`segment:${hq[0]}`]));
  const compact = layoutNetworkDiagram(routed, layers, hosts, new Set(), {}, 680);
  expect(compact.width).toBeLessThan(collapsed.width);
  expect(compact.height).toBeGreaterThan(collapsed.height);
  const accessBranch = (scene: typeof collapsed, name: string) =>
    scene.branches.find(({ node }) => node.id === `segment:${name}`)!;
  const firstRail = ({ railY, railX }: ReturnType<typeof accessBranch>) => [railX, railY];

  expect(firstRail(accessBranch(expanded, hq[0]))).toEqual(firstRail(accessBranch(collapsed, hq[0])));
  expect(expanded.nodesById.get("router:vpn")!.y).toBeGreaterThan(collapsed.nodesById.get("router:vpn")!.y);
  for (const scene of [collapsed, expanded, compact]) {
    const attachments = scene.wires.filter(({ kind }) => kind === "interface");
    expect(attachments).toHaveLength(2 * backbone.length + hq.length + plant.length);
    for (const [name, from, to] of backbone) {
      expect(accessBranch(scene, name).vertical).toBe(true);
      const connections = attachments.filter(({ entities }) => entities.includes(`link:${name}`));
      expect(connections.flatMap(({ entities }) => entities).filter((id) => id.startsWith("router:") || id === "device:fw"))
        .toEqual([from === "edge" ? "device:fw" : `router:${from}`, `router:${to}`]);
    }
    for (const [subnets, owner, next] of [[hq, "hq", "vpn"], [plant, "plant", "remote"]] as const) {
      const device = scene.nodesById.get(`router:${owner}`)!;
      const nextDevice = scene.nodesById.get(`router:${next}`)!;
      const rails = subnets.map((name) => {
        const branch = accessBranch(scene, name);
        expect(branch.railY).toBeGreaterThan(device.y);
        expect(branch.railY).toBeLessThan(nextDevice.y);
        const paths = attachments.filter(({ entities }) => entities.includes(`link:${name}`));
        expect(paths.map(({ entities }) => entities)).toEqual([[
          device.id, `segment:${name}`, `link:${name}`,
        ]]);
        return branch.railX;
      });
      expect(new Set(rails).size).toBe(scene === compact ? 2 : 4);
    }
  }

  let measure!: ResizeObserverCallback;
  vi.stubGlobal("ResizeObserver", class {
    constructor(callback: ResizeObserverCallback) { measure = callback; }
    observe() {}
    disconnect() {}
  });
  try {
    const { container } = render(<NetworkDiagram graph={routed} />);
    let bodyWidth = 1200;
    Object.defineProperty(container.querySelector(".diagram-body"), "clientWidth", { get: () => bodyWidth });
    const resize = (width: number, height: number, available = width) => {
      bodyWidth = available;
      const entry = { contentRect: new DOMRect(0, 0, width, height) } as ResizeObserverEntry;
      act(() => measure([entry], {} as ResizeObserver));
    };
    const horizontalPositions = () => screen.getAllByRole("button", { name: /^Segment hq-lan-/ })
      .map((node) => node.getAttribute("transform")?.split(" ")[0]);
    const cameraScale = () => screen.getByRole("group", { name: /Network map/ }).querySelector("svg > g")
      ?.getAttribute("transform")?.match(/scale\(([^)]+)\)/)?.[1];
    resize(1200, 650);
    const widePositions = horizontalPositions();
    expect(new Set(widePositions).size).toBe(4);
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "Collapse hq-lan-1 hosts" }));
    await user.click(screen.getByRole("button", { name: "Zoom in" }));
    const zoom = cameraScale();
    resize(720, 650, 1200); // The details inspector narrows the drawing, while space for layout stays stable.
    expect(horizontalPositions()).toEqual(widePositions);
    resize(690, 650);
    expect(new Set(horizontalPositions()).size).toBe(2);
    expect(cameraScale()).toBe(zoom);
    resize(1200, 650);
    expect(horizontalPositions()).toEqual(widePositions);
    expect(screen.getByRole("button", { name: "Expand hq-lan-1 hosts" })).toBeVisible();
  } finally {
    vi.unstubAllGlobals();
  }
});
