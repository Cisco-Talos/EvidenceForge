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
    expect(captureView).toHaveBeenCalledWith(screen.getByRole("group", { name: /Network map/ }));
  } finally { captureView.mockRestore(); }
});

test("the diagram separates SPAN markers from modeled interface links and preserves selection", async () => {
  const { container } = render(<NetworkDiagram graph={graph} />);
  const user = userEvent.setup();
  const map = screen.getByRole("group", { name: /Network map/ });
  const firewall = screen.getByRole("button", { name: "Firewall FW-01" });
  expect(container.querySelectorAll(".diagram-marker[data-placement='span']")).toHaveLength(1);
  const interfaceCount = container.querySelectorAll("path[data-kind='interface']").length;
  expect(interfaceCount).toBeGreaterThan(0);
  expect(screen.getByRole("button", { name: "Unassigned hosts" })).toBeVisible();
  expect(screen.queryByRole("complementary")).toBeNull();
  await user.hover(firewall);
  expect(container.querySelector("path[data-kind='interface']")).toHaveAttribute("data-highlighted", "true");
  await user.click(firewall);
  const details = screen.getByRole("complementary", { name: "Network diagram details" });
  await user.hover(screen.getByRole("button", { name: "Network sensor CORE, SPAN" }));
  expect(container.querySelectorAll(".diagram-marker[data-active='true']")).toHaveLength(1);
  expect(container.querySelectorAll("path[data-kind='interface']")).toHaveLength(interfaceCount);
  expect(within(details).getByText("Interface inside")).toBeVisible();
  expect(firewall).toHaveAttribute("aria-pressed", "true");
  expect(within(details).getByText(/segment absent/)).toBeVisible();

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
  Object.defineProperty(map, "setPointerCapture", { value: capture });
  fireEvent.pointerDown(map, { button: 0, pointerId: 1, clientX: 20, clientY: 30 });
  expect(capture).toHaveBeenCalledWith(1);
  fireEvent.pointerMove(map, { pointerId: 1, clientX: 50, clientY: 45 });
  expect(transform()).not.toBe(initialTransform);
  fireEvent.pointerUp(map, { pointerId: 1 });
  expect(map).toHaveAttribute("data-dragging", "false");

  await user.click(screen.getByRole("button", { name: "Sensors" }));
  expect(screen.queryByRole("button", { name: "Network sensor CORE, SPAN" })).not.toBeInTheDocument();
  expect(container.querySelectorAll(".diagram-marker")).toHaveLength(0);
  expect(within(details).getByText("Interface inside")).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Firewalls" }));
  expect(screen.queryByRole("button", { name: "Firewall FW-01" })).not.toBeInTheDocument();
  expect(container.querySelectorAll("path[data-kind='interface']")).toHaveLength(0);
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

test("expanding fills the app view and preserves layers and the selected subnet", async () => {
  render(<NetworkDiagram graph={graph} context="Branch Office" />);
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: "Sensors" }));
  await user.click(screen.getByRole("button", { name: /Segment office/ }));
  await user.click(screen.getByRole("button", { name: "Expand diagram" }));
  const dialog = screen.getByRole("dialog", { name: "Expanded network diagram" });
  expect(within(dialog).getByText("Branch Office")).toBeVisible();
  expect(within(dialog).getByRole("button", { name: "Sensors" })).toHaveAttribute("aria-pressed", "false");
  expect(within(dialog).getByRole("button", { name: /Segment office/ })).toHaveAttribute("aria-pressed", "true");
  await user.keyboard("{Escape}");
  expect(screen.queryByRole("dialog")).toBeNull();
  expect(screen.getByRole("button", { name: /Segment office/ })).toHaveAttribute("aria-pressed", "true");
});

test("dense monitoring uses bounded repeated badges and rails use only authored interfaces", async () => {
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
  expect(scene.labels.map(({ text }) => text)).toEqual(["FW-01 · inside", "FW-01 · production"]);
  expect(scene.branches.every(({ sensors }) => sensors.some(({ device }) => device.id === "sensor:0"))).toBe(true);
  expect(scene.wires.filter(({ kind, entities }) => kind === "interface" && entities.includes("segment:15"))).toHaveLength(0);
  expect(scene.width).toBeLessThan(1500);
  // Each interface group has one feed; a later leaf must not sprout another device link.
  expect(scene.wires.filter(({ key }) => key.endsWith(":feed"))).toHaveLength(2);
  expect(scene.wires.filter(({ key, kind }) => kind === "interface" && key.startsWith('["segment:'))).toHaveLength(0);
  for (const node of scene.nodes) {
    expect(node.x + node.width).toBeLessThanOrEqual(scene.width);
    expect(node.y + node.height).toBeLessThanOrEqual(scene.height);
  }
  const view = render(<NetworkDiagram graph={dense} />);
  const user = userEvent.setup();
  const markers = () => [...view.container.querySelectorAll(".diagram-marker")];
  expect(markers()).toHaveLength(16 * 7);
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
  const camera = map.firstElementChild?.getAttribute("transform");
  const next = screen.getByRole("button", { name: "Next hosts on office" });
  const previous = screen.getByRole("button", { name: "Previous hosts on office" });
  expect(previous).toHaveAttribute("aria-disabled", "true");
  await user.click(next);
  expect(screen.getByText("13–20 of 20 hosts")).toBeVisible();
  expect(screen.getByRole("button", { name: "WS-20 Windows" })).toBeVisible();
  expect(next).toHaveAttribute("aria-disabled", "true");
  expect(map.firstElementChild?.getAttribute("transform")).toBe(camera);
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
    camera: map.firstElementChild?.getAttribute("transform"),
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

test("shared subnets retain both declared firewall attachments and isolated segments keep their own rails", () => {
  const scene = layoutNetworkDiagram({
    ...graph,
    segments: [...graph.segments, { id: "segment:lab", name: "lab", cidr: "2001:db8::/64", description: "", exposure: "internal" }],
    devices: [...graph.devices, {
      ...graph.devices[1], id: "device:fw2", name: "second-edge", hostname: "FW-02",
      associations: [{ segment_id: "segment:office", monitored: false, interface_name: "lan" }],
    }],
  }, { sensors: true, firewalls: true, hosts: false }, new Map(), new Set());
  expect(scene.branches.map(({ node }) => node.id)).toEqual(["segment:office", "segment:lab"]);
  expect(scene.labels.map(({ text }) => text)).toEqual(["inside", "lan"]);
  const interfaceWires = scene.wires.filter(({ kind }) => kind === "interface");
  expect(interfaceWires.some(({ entities }) => entities.includes("device:fw") && entities.includes("segment:office"))).toBe(true);
  expect(interfaceWires.some(({ entities }) => entities.includes("device:fw2") && entities.includes("segment:office"))).toBe(true);
  expect(interfaceWires.some(({ entities }) => entities.includes("segment:lab"))).toBe(false);
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
  expect(scene.nodesById.get(dmz.id)!.x).toBeLessThan(firewall.x);
  expect(scene.nodesById.has(edge.id)).toBe(false);
  expect(scene.branches.find(({ node }) => node.id === transit.id)?.vertical).toBe(true);
  const membership = scene.wires.filter(({ kind }) => kind === "membership");
  expect(membership.map(({ entities }) => entities)).toEqual([["device:fw", transit.id], [core.id, transit.id]]);
  expect(scene.wires.some(({ kind, entities }) => kind === "interface" && entities.includes("device:fw") && entities.includes("segment:office"))).toBe(true);
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
