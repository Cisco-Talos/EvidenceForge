import "@testing-library/jest-dom/vitest";
import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, test, vi } from "vitest";
import type { CatalogItem, PackTopology, StudioApi, StudioEvent, TopologyGraph } from "../src/api";
import { NetworkDiagram } from "../src/NetworkDiagram";
import * as capture from "../src/captureNetworkView";
import { PackEnvironmentView } from "../src/PackEnvironmentView";
import { buildDiagramModel, GUTTER_GAP, hostCategory, interfaceSuffix, layoutNetworkDiagram, type DiagramScene } from "../src/networkDiagramLayout";

type Host = TopologyGraph["hosts"][number];
type Device = TopologyGraph["devices"][number];
type Segment = TopologyGraph["segments"][number];

const LAYERS = { sensors: true, hosts: true };
const WIDE = { width: 1400, height: 760 };

const segment = (name: string, cidr: string, extra: Partial<Segment> = {}): Segment =>
  ({ id: `segment:${name}`, name, cidr, exposure: "internal", description: "", ...extra });
const host = (hostname: string, ip: string, segments: string[], extra: Partial<Host> = {}): Host => ({
  id: `host:${hostname}`, hostname, ip, os: "Windows 11", os_family: "windows", type: "workstation",
  segment_ids: segments.map((name) => `segment:${name}`), ...extra,
});
const sensor = (hostname: string, segments: string[], extra: Partial<Device> = {}): Device => ({
  id: `device:${hostname}`, name: hostname.toLowerCase(), hostname, kind: "network", placement: "span", direction: "bidirectional",
  description: "", log_formats: ["zeek"], default_interface: null,
  evidence: [{ family: "zeek", label: "Zeek", depth: "protocol", formats: ["zeek_conn", "zeek_dns"] }],
  associations: segments.map((name) => ({ segment_id: `segment:${name}`, monitored: true, interface_name: null })), ...extra,
});
const firewall = (hostname: string, interfaces: Record<string, string | null>, extra: Partial<Device> = {}): Device => ({
  ...sensor(hostname, []), kind: "firewall", placement: "tap", log_formats: ["cisco_asa"],
  evidence: [{ family: "asa", label: "Cisco ASA", depth: "firewall", formats: ["cisco_asa"] }],
  associations: Object.entries(interfaces).map(([name, iface]) => ({ segment_id: `segment:${name}`, monitored: true, interface_name: iface })),
  ...extra,
});

// A legacy (segment-based) office: one large subnet, a SPAN sensor, a firewall policy interface, and an unplaced host.
const graph: TopologyGraph = {
  segments: [segment("office", "10.0.0.0/24")],
  hosts: [
    ...Array.from({ length: 32 }, (_, index) => host(`WS-${index + 1}`, `10.0.0.${index + 1}`, ["office"], {
      primary_users: index === 0 ? ["alex"] : [], roles: index === 0 ? ["workstation", "developer"] : [],
    })),
    host("standalone", "2001:db8::1", [], { os: "macOS 27", os_family: "macos" }),
  ],
  devices: [sensor("CORE", ["office"]), firewall("FW-01", { office: "inside" }, { direction: "inbound" })],
  findings: [{ entity_id: "device:FW-01", message: "FW-01 refers to a segment absent from this environment." }],
};

const zoneIds = (scene: DiagramScene) => scene.zones.flatMap(function ids(zone): string[] { return [zone.zone.id, ...zone.children.flatMap(ids)]; });

async function toggleLayer(user: ReturnType<typeof userEvent.setup>, name: string, scope: HTMLElement | typeof screen = screen) {
  await user.click(scope.getByRole("button", { name: /^Layers/ }));
  await user.click(scope.getByRole("checkbox", { name }));
  await user.click(scope.getByRole("button", { name: /^Layers/ }));
}

afterEach(cleanup);

test("both diagram questions capture the viewport and retain the full topology", async () => {
  const shot = "data:image/png;base64,viewport";
  const captureView = vi.spyOn(capture, "captureNetworkView").mockResolvedValue(shot);
  const onAsk = vi.fn(async () => undefined);
  const user = userEvent.setup();
  try {
    render(<NetworkDiagram graph={graph} revision="resolved" onAsk={onAsk} />);
    await toggleLayer(user, "Sensors");
    await user.click(screen.getByRole("button", { name: "Ask about this diagram" }));
    expect(onAsk).toHaveBeenLastCalledWith(expect.objectContaining({
      revision: "resolved", topology: graph, image: shot, visible_layers: ["firewalls", "hosts"], selected_id: undefined, sensor_key: {},
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

test("a segment-based firewall connects through inferred and monitored links instead of floating", async () => {
  const legacy: TopologyGraph = {
    segments: [segment("lan", "10.1.0.0/24"), segment("dmz", "10.2.0.0/24"), segment("observed", "10.3.0.0/24"), segment("lab", "10.4.0.0/24")],
    hosts: [host("WS", "10.1.0.5", ["lan"]), host("WEB", "10.2.0.10", ["dmz"], { public_address: "203.0.113.10", public_address_source: "static_nat" }),
      host("PROBE", "10.3.0.4", ["observed"]), host("BENCH", "10.4.0.2", ["lab"])],
    devices: [firewall("FW", { lan: "inside", dmz: "dmz", observed: null }, {
      nat_rules: [{ type: "static", src: [], real_ip: "10.2.0.10", mapped_ip: "203.0.113.10" }],
    })],
    findings: [],
  };
  const scene = layoutNetworkDiagram(legacy, LAYERS, { viewport: WIDE });
  const styles = Object.fromEntries(scene.model.attachments.map(({ targetId, style }) => [targetId, style]));
  expect(styles).toEqual({ "segment:lan": "inferred", "segment:dmz": "inferred", "segment:observed": "observes", "internet:inferred": "inferred" });
  expect(scene.internets.map(({ internet }) => [internet.name, internet.inferred])).toEqual([["Internet", true]]);
  expect(scene.labels.some(({ key, text }) => key.includes("segment:lab") || text === "NOT ATTACHED TO A MODELED DEVICE")).toBe(true);
  for (const id of ["segment:lan", "segment:dmz", "segment:observed", "internet:inferred"]) {
    expect(scene.wires.some(({ entities }) => entities.includes("device:FW") && entities.includes(id))).toBe(true);
  }

  const { container } = render(<NetworkDiagram graph={legacy} />);
  expect(screen.getByText(/dashed links are inferred from firewall interfaces/)).toBeVisible();
  expect(container.querySelectorAll(".diagram-edges [data-style='inferred']").length).toBeGreaterThan(0);
  expect(container.querySelectorAll(".diagram-edges [data-style='observes']").length).toBeGreaterThan(0);
  await userEvent.setup().click(screen.getByRole("button", { name: "Internet (inferred)" }));
  const details = screen.getByRole("complementary", { name: "Network diagram details" });
  expect(details).toHaveTextContent("No Internet boundary is declared");
  expect(within(details).getByRole("button", { name: "WEB" })).toBeVisible();
});

test("a sensor is one identity across every subnet it covers", async () => {
  const spread: TopologyGraph = {
    segments: [segment("a", "10.1.0.0/24"), segment("b", "10.2.0.0/24"), segment("c", "10.3.0.0/24")],
    hosts: [host("A1", "10.1.0.1", ["a"]), host("B1", "10.2.0.1", ["b"]), host("C1", "10.3.0.1", ["c"])],
    devices: [sensor("CORE", ["a", "b"]), sensor("EDGE-IDS", ["c"], { kind: "ids", placement: "tap", log_formats: ["snort_alert"],
      evidence: [{ family: "ids", label: "Snort", depth: "alert", formats: ["snort_alert"] }] })],
    findings: [],
  };
  const { container } = render(<NetworkDiagram graph={spread} />);
  const user = userEvent.setup();
  const chips = screen.getAllByRole("button", { name: "Sensor CORE, Zeek, SPAN" });
  expect(chips).toHaveLength(2);
  expect(screen.getByRole("button", { name: "Sensor EDGE-IDS, Snort, TAP" }).closest("[data-family]")).toHaveAttribute("data-family", "ids");
  await user.hover(chips[0]);
  const covered = [...container.querySelectorAll(".diagram-zone[data-covered]")].map((zone) => zone.getAttribute("aria-label"));
  expect(covered).toEqual(["Segment a, 10.1.0.0/24", "Segment b, 10.2.0.0/24"]);
  expect(container.querySelectorAll(".diagram-chip[data-related='true']")).toHaveLength(2);
  await user.click(chips[1]);
  const details = screen.getByRole("complementary");
  expect(details).toHaveTextContent("SPAN sees traffic within each monitored subnet");
  expect(within(details).getByRole("button", { name: "a" })).toBeVisible();
  expect(within(details).getByRole("button", { name: "b" })).toBeVisible();
  const key = screen.getByLabelText("Diagram key");
  expect(within(key).getByText("TAP")).toBeVisible();
  expect(within(key).getByText("SPAN")).toBeVisible();
  expect(within(key).getByText("Snort IDS alerts")).toBeVisible();
  expect(within(key).getByText("Zeek network logs")).toBeVisible();
});

test("every Zeek sensor shares one badge and its hover lists the logs it writes", async () => {
  const connOnly = sensor("BRANCH-ZEEK", ["b"], { log_formats: ["zeek_conn"],
    evidence: [{ family: "zeek", label: "Zeek", depth: "connection", formats: ["zeek_conn", "zeek_weird"] }] });
  const mixed: TopologyGraph = {
    segments: [segment("a", "10.1.0.0/24"), segment("b", "10.2.0.0/24")],
    hosts: [host("A1", "10.1.0.1", ["a"]), host("B1", "10.2.0.1", ["b"])],
    devices: [sensor("CORE", ["a"]), connOnly], findings: [],
  };
  const { container } = render(<NetworkDiagram graph={mixed} />);
  const chips = [...container.querySelectorAll(".diagram-chip")];
  expect(chips.map((chip) => chip.getAttribute("data-family"))).toEqual(["zeek", "zeek"]);
  expect(screen.getByRole("button", { name: "Sensor BRANCH-ZEEK, Zeek, SPAN" }).querySelector("title")).toHaveTextContent("Zeek logs: conn, weird");
  expect(within(screen.getByLabelText("Diagram key")).queryByText(/Connections only/)).toBeNull();
  await userEvent.setup().hover(screen.getByRole("button", { name: "Sensor CORE, Zeek, SPAN" }));
  expect(container.querySelector(".diagram-preview")).toHaveTextContent("Zeek logs: conn, dns");
});

test("the Layers menu explains each layer and always keeps firewalls", async () => {
  render(<NetworkDiagram graph={graph} />);
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: /^Layers/ }));
  const menu = screen.getByRole("group", { name: "Diagram layers" });
  expect(within(menu).getAllByRole("checkbox").map((box) => box.closest("label")!.textContent)).toEqual(["Sensors", "Hosts", "Firewall policy scopes"]);
  expect(within(menu).getByRole("img", { name: /^About Sensors: / })).toBeVisible();
  expect(within(menu).getByRole("img", { name: /^About Hosts: / })).toBeVisible();
  expect(within(menu).getByRole("img", { name: /^About Firewall policy scopes: / })).toBeVisible();
  await user.click(within(menu).getByRole("checkbox", { name: "Sensors" }));
  await user.click(within(menu).getByRole("checkbox", { name: "Hosts" }));
  expect(screen.getByRole("button", { name: "Firewall FW-01" })).toBeVisible();
});

test("Show on map expands a summarized subnet and selects the host there", async () => {
  const { container } = render(<NetworkDiagram graph={graph} />);
  const user = userEvent.setup();
  expect(container.querySelector(".diagram-host-card[aria-label='WS-5 Windows']")).toBeNull();
  await user.click(screen.getByRole("button", { name: /Segment office/ }));
  const details = screen.getByRole("complementary");
  await user.click(within(details).getByRole("button", { name: "WS-5 Windows" }));
  await user.click(within(details).getByRole("button", { name: "Show on map" }));
  const card = container.querySelector(".diagram-host-card[aria-label='WS-5 Windows']");
  expect(card).not.toBeNull();
  expect(card).toHaveAttribute("aria-pressed", "true");
  expect(screen.getByRole("button", { name: "Collapse office hosts" })).toBeVisible();
  expect(screen.getByRole("complementary")).toHaveTextContent("In office");
});

test("Show on map expands a collapsed site before revealing its host", async () => {
  const sites = ["hq", "a", "b", "c", "d", "e"];
  const routed: TopologyGraph = {
    segments: [...sites.map((name, index) => segment(`${name}-lan`, `10.${index}.1.0/24`)),
      ...sites.slice(1).map((name, index) => segment(`${name}-wan`, `10.100.${index}.0/30`))],
    devices: [], findings: [],
    hosts: sites.map((name, index) => host(`${name.toUpperCase()}-WS`, `10.${index}.1.10`, [`${name}-lan`])),
    routing: {
      devices: Object.fromEntries(sites.map((name) => [name, { kind: "router" as const }])),
      links: {
        ...Object.fromEntries(sites.map((name, index) => [`${name}-lan`, { segment: `${name}-lan`, interfaces: { [name]: { name: "lan", ip: `10.${index}.1.1` } } }])),
        ...Object.fromEntries(sites.slice(1).map((name, index) => [`${name}-wan`, { kind: "wan" as const, segment: `${name}-wan`,
          interfaces: { hq: { name: `to-${name}`, ip: `10.100.${index}.1` }, [name]: { name: "wan", ip: `10.100.${index}.2` } } }])),
      },
    },
  };
  const { container } = render(<NetworkDiagram graph={routed} />);
  const user = userEvent.setup();
  expect(container.querySelector(".diagram-host-card[aria-label='C-WS Windows']")).toBeNull();
  await user.click(screen.getByRole("button", { name: "hq Router" }));
  await user.click(within(screen.getByRole("complementary")).getByRole("button", { name: "c-wan" }));
  await user.click(within(screen.getByRole("complementary")).getByRole("button", { name: "c" }));
  expect(container.querySelector(".diagram-device[aria-label='c Router']")).toHaveAttribute("aria-pressed", "true");
  expect(container.querySelectorAll(".diagram-site-card")).toHaveLength(4);
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
  act(() => screen.getByRole("button", { name: "Expand diagram" }).focus());
  const toolbarScale = camera()[2];
  expect(fireEvent.wheel(map, { ...pointer, deltaY: 120 })).toBe(true);
  expect(camera()[2]).toBe(toolbarScale);
});

test("pan, zoom, fit, and selection work together without moving the map for details", async () => {
  render(<NetworkDiagram graph={graph} />);
  const user = userEvent.setup();
  const map = screen.getByRole("group", { name: /Network map/ });
  const transform = () => map.querySelector("g")!.getAttribute("transform");
  const initial = transform();
  await user.click(screen.getByRole("button", { name: "Firewall FW-01" }));
  expect(transform()).toBe(initial);
  const details = screen.getByRole("complementary", { name: "Network diagram details" });
  expect(details).toHaveTextContent("Policy scope inside");
  expect(within(details).getByText(/segment absent/)).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Zoom in" }));
  expect(transform()).not.toBe(initial);
  fireEvent.keyDown(map, { key: "ArrowRight" });
  const panned = transform();
  await user.click(screen.getByRole("button", { name: "Fit to view" }));
  expect(transform()).not.toBe(panned);
  const plot = map.querySelector("svg")!;
  const pointerCapture = vi.fn();
  Object.defineProperty(plot, "setPointerCapture", { value: pointerCapture });
  fireEvent.pointerDown(plot, { button: 0, pointerId: 1, clientX: 20, clientY: 30 });
  expect(pointerCapture).toHaveBeenCalledWith(1);
  const fitted = transform();
  fireEvent.pointerMove(plot, { pointerId: 1, clientX: 50, clientY: 45 });
  expect(transform()).not.toBe(fitted);
  fireEvent.pointerUp(plot, { pointerId: 1 });
  expect(plot).toHaveAttribute("data-dragging", "false");
  fireEvent.keyDown(map, { key: "Escape" });
  expect(screen.queryByRole("complementary")).toBeNull();
});

test("keyboard selection opens bounded host pages and individual host facts", async () => {
  render(<NetworkDiagram graph={graph} />);
  const user = userEvent.setup();
  const office = screen.getByRole("button", { name: /Segment office/ });
  fireEvent.focus(office);
  expect(screen.queryByRole("complementary")).toBeNull();
  fireEvent.keyDown(office, { key: "Enter" });
  const details = screen.getByRole("complementary", { name: "Network diagram details" });
  expect(within(details).getByRole("button", { name: "CORE" })).toBeVisible();
  await user.click(within(details).getByRole("button", { name: "WS-1 Windows" }));
  expect(within(details).getByText("Windows 11")).toBeVisible();
  expect(within(details).getByText("10.0.0.1")).toBeVisible();
  expect(within(details).getByText("alex")).toBeVisible();
  expect(within(details).getByText("workstation, developer")).toBeVisible();
  expect(within(details).getByText("1–12 of 32")).toBeVisible();
  await user.click(within(details).getByRole("button", { name: "Next hosts" }));
  expect(within(details).getByRole("button", { name: "WS-13 Windows" })).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Unassigned hosts" }));
  expect(within(details).getByRole("button", { name: "standalone macOS" })).toBeVisible();
  await toggleLayer(user, "Hosts");
  expect(screen.queryByRole("button", { name: "Unassigned hosts" })).toBeNull();
});

test("large subnets summarize by role and expand to host cards on request", async () => {
  render(<NetworkDiagram graph={graph} />);
  const user = userEvent.setup();
  expect(screen.queryByRole("button", { name: "WS-1 Windows" })).toBeNull();
  const expand = screen.getByRole("button", { name: "Expand office hosts" });
  expect(expand).toHaveAttribute("aria-expanded", "false");
  await user.click(expand);
  expect(screen.getAllByRole("button", { name: /^WS-\d+ Windows$/ })).toHaveLength(32);
  await user.click(screen.getByRole("button", { name: "Collapse office hosts" }));
  expect(screen.queryByRole("button", { name: "WS-1 Windows" })).toBeNull();
});

test("small environments open at host detail and larger ones at the subnet overview", () => {
  const small: TopologyGraph = { segments: [segment("corp", "10.0.0.0/16")], devices: [sensor("ZEEK", ["corp"])], findings: [],
    hosts: [host("DC-01", "10.0.3.10", ["corp"], { type: "domain_controller", os: "Windows Server 2019" }),
      host("SRV-01", "10.0.2.1", ["corp"], { type: "server", os: "Ubuntu 22.04", os_family: "linux" }),
      ...Array.from({ length: 6 }, (_, index) => host(`WS-0${index + 1}`, `10.0.1.${index + 1}`, ["corp"]))] };
  const opened = layoutNetworkDiagram(small, LAYERS, { viewport: WIDE });
  expect(opened.detail).toBe("hosts");
  expect(opened.zones[0].groupLabels.map(({ text }) => text)).toEqual(["DOMAIN CONTROLLER  1", "SERVER  1", "WORKSTATIONS  6"]);
  const overview = layoutNetworkDiagram(graph, LAYERS, { viewport: { width: 720, height: 320 } });
  expect(overview.detail).toBe("overview");
  expect(overview.zones.find(({ zone }) => zone.id === "segment:office")!.summary).toEqual([{ category: "workstation", count: 32 }]);
  const chosen = layoutNetworkDiagram(graph, LAYERS, { viewport: { width: 720, height: 320 }, zoneDetail: { "segment:office": "hosts" } });
  expect(chosen.zones.find(({ zone }) => zone.id === "segment:office")!.hostCards).toHaveLength(32);
});

test("hosts belong to their most specific subnet and nested subnets draw inside their parent", () => {
  const nested: TopologyGraph = {
    segments: [segment("offices", "10.61.0.0/16"), segment("services", "10.61.60.0/24", { parent_id: "segment:offices" })],
    hosts: [host("WS", "10.61.1.5", ["offices"]), host("DC", "10.61.60.10", ["offices", "services"], { primary_segment_id: "segment:services", roles: ["domain_controller"] })],
    devices: [], findings: [],
  };
  const scene = layoutNetworkDiagram(nested, LAYERS, { viewport: WIDE });
  expect(scene.zones.map(({ zone }) => zone.id)).toEqual(["segment:offices"]);
  const [offices] = scene.zones;
  expect(offices.children.map(({ zone }) => zone.id)).toEqual(["segment:services"]);
  expect(offices.zone.hosts.map(({ hostname }) => hostname)).toEqual(["WS"]);
  expect(offices.children[0].zone.hosts.map(({ hostname }) => hostname)).toEqual(["DC"]);
  const child = offices.children[0];
  expect(child.x).toBeGreaterThan(offices.x);
  expect(child.y + child.height).toBeLessThanOrEqual(offices.y + offices.height);
});

test("public addresses are marked per host, and summarized subnets name those hosts", async () => {
  const servers: TopologyGraph = {
    segments: [segment("servers", "10.2.0.0/24")], devices: [], findings: [],
    hosts: Array.from({ length: 9 }, (_, index) => host(`SRV-${index}`, `10.2.0.${index + 10}`, ["servers"], {
      type: "server", ...(index === 3 ? { public_address: "203.0.113.11", public_address_source: "static_nat" as const } : {}),
    })),
  };
  const scene = layoutNetworkDiagram(servers, LAYERS, { viewport: WIDE, zoneDetail: { "segment:servers": "overview" } });
  const [zone] = scene.zones;
  expect(zone.summary).toEqual([{ category: "server", count: 9 }]);
  expect(zone.publicHosts.map(({ hostname }) => hostname)).toEqual(["SRV-3"]);
  const { container } = render(<NetworkDiagram graph={servers} />);
  // Nine hosts fit, so the subnet opens at host detail; only the reachable host is marked.
  expect(container.querySelectorAll(".diagram-host-card[data-public]")).toHaveLength(1);
  expect(screen.getByRole("button", { name: "SRV-3 Windows" })).toHaveAttribute("data-public", "true");
  expect(container.querySelector(".diagram-zone")).not.toHaveAttribute("data-public");
  await userEvent.setup().click(screen.getByRole("button", { name: "Collapse servers hosts" }));
  expect(screen.getByRole("button", { name: "SRV-3 public address 203.0.113.11" })).toBeVisible();
});

test("host categories prefer roles and fall back to the declared system type", () => {
  expect(hostCategory(host("A", "10.0.0.1", [], { roles: ["file_server"], type: "server" }))).toBe("file_server");
  expect(hostCategory(host("B", "10.0.0.2", [], { roles: [], type: "domain_controller" }))).toBe("domain_controller");
  expect(hostCategory(host("C", "10.0.0.3", [], { roles: ["forward_proxy"], type: "server" }))).toBe("server");
  expect(hostCategory(host("D", "10.0.0.4", [], { roles: [], type: "" }))).toBe("other");
  expect(interfaceSuffix("10.40.10.1", "10.40.10.0/24")).toBe(".1");
  expect(interfaceSuffix("10.40.254.2", "10.40.0.0/16")).toBe(".254.2");
  expect(interfaceSuffix("2001:db8::1", "2001:db8::/64")).toBe("2001:db8::1");
});

test("expanded view starts focused for wheel zoom and preserves layers and the selected subnet", async () => {
  render(<NetworkDiagram graph={graph} context="Branch Office" />);
  const user = userEvent.setup();
  await toggleLayer(user, "Sensors");
  await user.click(screen.getByRole("button", { name: /Segment office/ }));
  await user.click(screen.getByRole("button", { name: "Expand diagram" }));
  const dialog = screen.getByRole("dialog", { name: "Expanded network diagram" });
  expect(within(dialog).getByText("Branch Office")).toBeVisible();
  expect(within(dialog).queryByRole("button", { name: /^Sensor CORE/ })).toBeNull();
  expect(within(dialog).getByRole("button", { name: /Segment office/ })).toHaveAttribute("aria-pressed", "true");
  const map = within(dialog).getByRole("group", { name: /Network map/ });
  const plot = map.querySelector("svg")!;
  const transform = () => plot.firstElementChild?.getAttribute("transform");
  expect(map).toHaveFocus();
  const initial = transform();
  fireEvent.wheel(plot, { clientX: 150, clientY: 140, deltaY: -120 });
  expect(transform()).not.toBe(initial);
  act(() => within(dialog).getByRole("button", { name: "Close details" }).focus());
  const zoomed = transform();
  fireEvent.wheel(plot, { deltaY: -120 });
  expect(transform()).toBe(zoomed);
  act(() => map.focus());
  await user.keyboard("{Escape}");
  expect(screen.queryByRole("dialog")).toBeNull();
  expect(screen.getByRole("button", { name: /Segment office/ })).toHaveAttribute("aria-pressed", "true");
});

test("firewall policy scopes are an optional overlay that never moves links", async () => {
  const scoped: TopologyGraph = {
    segments: [segment("lan", "10.1.0.0/24"), segment("servers", "10.2.0.0/24"), segment("dmz", "10.3.0.0/24")],
    hosts: [host("A", "10.1.0.2", ["lan"]), host("B", "10.2.0.2", ["servers"]), host("C", "10.3.0.2", ["dmz"])],
    devices: [firewall("FW", { lan: "inside", servers: "inside", dmz: "dmz" })], findings: [],
  };
  const { container } = render(<NetworkDiagram graph={scoped} />);
  const user = userEvent.setup();
  const geometry = () => [...container.querySelectorAll(".diagram-edges path")].map((path) => path.getAttribute("d"));
  const wires = geometry();
  expect(container.querySelectorAll(".diagram-scope-highlight")).toHaveLength(0);
  await toggleLayer(user, "Firewall policy scopes");
  expect(geometry()).toEqual(wires);
  expect(container.querySelectorAll(".diagram-scope-highlight")).toHaveLength(3);
  expect(within(screen.getByLabelText("Diagram key")).getByText("FW · inside")).toBeVisible();
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

test("routed transits are links between devices, and leaf devices sit beside their parent", async () => {
  const routed: TopologyGraph = {
    segments: [segment("office", "10.0.0.0/24"), segment("transit", "10.2.0.0/30"), segment("vpn-lan", "10.3.0.0/30")],
    hosts: [host("WS-1", "10.0.0.5", ["office"]), host("CORE-01", "10.2.0.2", ["transit"], { os: "Cisco IOS XE" })],
    devices: [firewall("FW-01", {}, { name: "edge" }), sensor("UPLINK", [], { placement: "tap" })],
    findings: [],
    routing: {
      devices: { edge: { kind: "firewall", firewall: "edge" }, core: { kind: "router", system: "CORE-01" }, vpn: { kind: "router" } },
      links: {
        "edge-core": { segment: "transit", interfaces: { edge: { name: "inside", ip: "10.2.0.1" }, core: { name: "edge", ip: "10.2.0.2" } } },
        "core-vpn": { segment: "vpn-lan", interfaces: { core: { name: "vpn", ip: "10.3.0.1" }, vpn: { name: "lan", ip: "10.3.0.2" } } },
        office: { segment: "office", interfaces: { core: { name: "office", ip: "10.0.0.1" } } },
      },
      gateways: { office: "core" },
    },
    link_taps: { "device:UPLINK": { link: "edge-core", scope: "internet" } },
  };
  const scene = layoutNetworkDiagram(routed, LAYERS, { viewport: WIDE });
  expect(zoneIds(scene)).toEqual(["segment:office"]);
  expect([...scene.model.transits.keys()]).toEqual(["link:edge-core", "link:core-vpn"]);
  const glyph = (id: string) => scene.equipment.find(({ equipment }) => equipment.id === id)!;
  expect(glyph("device:FW-01").y).toBeLessThan(glyph("router:core").y);
  expect(glyph("router:vpn").y).toBe(glyph("router:core").y);
  expect(glyph("router:vpn").labelSide).toBe("above");
  expect(scene.labels.some(({ text }) => text === ".1")).toBe(true);
  expect(scene.taps.map(({ chip }) => chip.device.id)).toEqual(["device:UPLINK"]);
  expect(scene.model.equipment.get("router:core")!.host?.hostname).toBe("CORE-01");

  const onAsk = vi.fn(async () => undefined);
  render(<NetworkDiagram graph={routed} revision="routed" onAsk={onAsk} />);
  const user = userEvent.setup();
  expect(screen.queryByRole("button", { name: /^Segment transit/ })).toBeNull();
  await user.click(screen.getByRole("button", { name: "CORE-01 Router" }));
  const details = screen.getByRole("complementary");
  expect(details).toHaveTextContent("10.2.0.2");
  await user.click(within(details).getByRole("button", { name: "edge-core" }));
  expect(within(details).getByRole("heading", { name: "edge-core" })).toBeVisible();
  expect(details).toHaveTextContent("10.2.0.0/30");
  expect(details).toHaveTextContent("Internet traffic");
  await user.click(within(details).getByRole("button", { name: "Ask about this", exact: true }));
  expect(onAsk).toHaveBeenCalledWith(expect.objectContaining({ selected_id: "link:edge-core", selection_label: "edge-core", topology: routed }));
});

test("WAN and VPN links separate sites, and many sites start collapsed", async () => {
  const sites = ["hq", "a", "b", "c", "d", "e"];
  const segments = sites.map((name, index) => segment(`${name}-lan`, `10.${index}.1.0/24`));
  const wans = sites.slice(1).map((name, index) => segment(`${name}-wan`, `10.100.${index}.0/30`));
  const routed: TopologyGraph = {
    segments: [...segments, ...wans], devices: [], findings: [],
    hosts: sites.map((name, index) => host(`${name.toUpperCase()}-WS`, `10.${index}.1.10`, [`${name}-lan`])),
    routing: {
      devices: Object.fromEntries(sites.map((name) => [name, { kind: "router" as const }])),
      links: {
        ...Object.fromEntries(sites.map((name, index) => [`${name}-lan`, { segment: `${name}-lan`, interfaces: { [name]: { name: "lan", ip: `10.${index}.1.1` } } }])),
        ...Object.fromEntries(sites.slice(1).map((name, index) => [`${name}-wan`, {
          kind: (index % 2 ? "vpn" : "wan") as "vpn" | "wan", segment: `${name}-wan`,
          interfaces: { hq: { name: `to-${name}`, ip: `10.100.${index}.1` }, [name]: { name: "wan", ip: `10.100.${index}.2` } },
        }])),
      },
    },
  };
  const scene = layoutNetworkDiagram(routed, LAYERS, { viewport: WIDE });
  expect(scene.sites).toHaveLength(6);
  expect(scene.sites.filter(({ collapsed }) => collapsed)).toHaveLength(5);
  expect(scene.wires.filter(({ linkKind }) => linkKind === "wan")).toHaveLength(3);
  expect(scene.wires.filter(({ linkKind }) => linkKind === "vpn")).toHaveLength(2);
  const { container } = render(<NetworkDiagram graph={routed} />);
  const user = userEvent.setup();
  expect(container.querySelectorAll(".diagram-site-card")).toHaveLength(5);
  expect(screen.queryByRole("button", { name: "Expand site hq" })).toBeNull();
  await user.click(screen.getByRole("button", { name: "Expand site a" }));
  expect(screen.getByRole("button", { name: "Segment a-lan, 10.1.1.0/24" })).toBeVisible();
  expect(container.querySelectorAll(".diagram-site-card")).toHaveLength(4);
  const key = screen.getByLabelText("Diagram key");
  expect(within(key).getByText("WAN link")).toBeVisible();
  expect(within(key).getByText("VPN link")).toBeVisible();
});

test("an authored Internet boundary sits above its device, with IPv4 and IPv6 boundaries named apart", async () => {
  const tap = sensor("UPLINK", [], { placement: "tap" });
  const routed: TopologyGraph = {
    segments: [segment("office", "10.0.0.0/24")], hosts: [host("WS", "10.0.0.5", ["office"])], findings: [],
    devices: [firewall("FW-01", {}, { name: "edge" }), firewall("FW-02", {}, { name: "secondary" }), tap],
    routing: {
      devices: { edge: { kind: "firewall", firewall: "edge" }, branch: { kind: "firewall", firewall: "secondary" } },
      links: {
        upstream: { internet: true, interfaces: { edge: { name: "outside", ip: "192.0.2.1" } } },
        office: { segment: "office", interfaces: { edge: { name: "inside", ip: "10.0.0.1" }, branch: { name: "office", ip: "10.0.0.2" } } },
      },
    },
    link_taps: { [tap.id]: { link: "upstream", scope: "all" } },
  };
  const scene = layoutNetworkDiagram(routed, LAYERS, { viewport: WIDE });
  const cloud = scene.internets.find(({ internet }) => internet.id === "internet:upstream")!;
  const edge = scene.equipment.find(({ equipment }) => equipment.id === "device:FW-01")!;
  expect(cloud.x).toBe(edge.x);
  expect(cloud.y).toBeLessThan(edge.y);
  expect(scene.zones.find(({ zone }) => zone.id === "segment:office")!.zone.attachments.map(({ equipmentId }) => equipmentId).sort())
    .toEqual(["device:FW-01", "device:FW-02"]);
  expect(scene.wires.filter(({ entities }) => entities.includes("device:FW-02") && entities.includes("segment:office"))).toHaveLength(1);

  const { rerender } = render(<NetworkDiagram graph={routed} />);
  expect(screen.getByRole("button", { name: "Internet", exact: true }).querySelector(".lucide-cloud")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Sensor UPLINK, Zeek, TAP" })).toBeVisible();
  await userEvent.setup().click(screen.getByRole("button", { name: "Internet", exact: true }));
  expect(screen.getByRole("complementary")).toHaveTextContent("192.0.2.1");

  const dual = { ...routed, routing: { ...routed.routing!, links: { ...routed.routing!.links,
    upstream6: { internet: true, interfaces: { branch: { name: "outside6", ip: "2001:db8::1" } } } } } };
  rerender(<NetworkDiagram graph={dual} />);
  expect(screen.getByRole("button", { name: "Internet (IPv4)", exact: true })).toBeVisible();
  expect(screen.getByRole("button", { name: "Internet (IPv6)", exact: true })).toBeVisible();
  const second = layoutNetworkDiagram(dual, LAYERS, { viewport: WIDE });
  expect(second.wires.some(({ entities }) => entities.includes("internet:upstream6") && entities.includes("device:FW-02"))).toBe(true);
});

test("the model never invents an Internet boundary without a firewall to attach it to", () => {
  const cloudHost: TopologyGraph = { segments: [segment("cloud", "45.83.221.0/24")], devices: [], findings: [], public_cidrs: ["45.83.220.0/28"],
    hosts: [host("VM", "45.83.221.5", ["cloud"], { public_address: "45.83.221.5", public_address_source: "public_ip" })] };
  expect(buildDiagramModel(cloudHost, LAYERS).internets.size).toBe(0);
});

/** Split orthogonal SVG paths into segments and report which wires touch one another. */
function connectedWires(scene: DiagramScene, keys: string[]): Set<string>[] {
  type Segment = { key: string; x1: number; y1: number; x2: number; y2: number };
  const segments: Segment[] = [];
  for (const wire of scene.wires.filter(({ key }) => keys.includes(key))) {
    const tokens = wire.path.trim().split(/\s+/);
    let x = 0; let y = 0;
    for (let index = 0; index < tokens.length; index += 2) {
      const command = tokens[index];
      if (command === "M") { x = Number(tokens[index + 1]); y = Number(tokens[index + 2]); index += 1; continue; }
      const value = Number(tokens[index + 1]);
      const next = command === "H" ? { x: value, y } : { x, y: value };
      segments.push({ key: wire.key, x1: x, y1: y, x2: next.x, y2: next.y });
      ({ x, y } = next);
    }
  }
  const onSegment = (px: number, py: number, s: Segment) =>
    px >= Math.min(s.x1, s.x2) - 0.5 && px <= Math.max(s.x1, s.x2) + 0.5 && py >= Math.min(s.y1, s.y2) - 0.5 && py <= Math.max(s.y1, s.y2) + 0.5;
  const touches = (a: Segment, b: Segment) => [[a.x1, a.y1], [a.x2, a.y2]].some(([px, py]) => onSegment(px, py, b))
    || [[b.x1, b.y1], [b.x2, b.y2]].some(([px, py]) => onSegment(px, py, a));
  const groups: Set<string>[] = [];
  for (const key of new Set(segments.map(({ key }) => key))) groups.push(new Set([key]));
  let merged = true;
  while (merged) {
    merged = false;
    outer: for (let i = 0; i < groups.length; i++) {
      for (let j = i + 1; j < groups.length; j++) {
        const a = segments.filter(({ key }) => groups[i].has(key));
        const b = segments.filter(({ key }) => groups[j].has(key));
        if (a.some((first) => b.some((second) => touches(first, second)))) {
          for (const key of groups[j]) groups[i].add(key);
          groups.splice(j, 1);
          merged = true;
          break outer;
        }
      }
    }
  }
  return groups;
}

function accessWires(scene: DiagramScene, equipmentId: string): string[] {
  return [
    ...scene.wires.filter(({ key }) => [":trunk", ":bus:", ":gutter:"].some((part) => key.startsWith(equipmentId + part))).map(({ key }) => key),
    ...scene.model.attachments.filter((attachment) => attachment.equipmentId === equipmentId && scene.model.zones.has(attachment.targetId)).map(({ key }) => key),
  ];
}

test.each([
  ["routed", true],
  ["segment-based", false],
])("every row of a %s subnet grid stays connected to its device", (_kind, routed) => {
  const names = Array.from({ length: 7 }, (_, index) => `lan-${index + 1}`);
  const many: TopologyGraph = {
    segments: names.map((name, index) => segment(name, `10.${index}.0.0/24`)),
    hosts: names.map((name, index) => host(`HOST-${index + 1}`, `10.${index}.0.10`, [name])),
    devices: routed ? [] : [firewall("FW", Object.fromEntries(names.map((name) => [name, "inside"])))],
    findings: [],
    ...(routed ? { routing: {
      devices: { core: { kind: "router" as const } },
      links: Object.fromEntries(names.map((name, index) => [name, { segment: name, interfaces: { core: { name, ip: `10.${index}.0.1` } } }])),
    } } : {}),
  };
  // A tall, narrow canvas forces the grid onto several rows.
  const scene = layoutNetworkDiagram(many, LAYERS, { viewport: { width: 640, height: 1600 }, zoneDetail: Object.fromEntries(names.map((name) => [`segment:${name}`, "overview" as const])) });
  expect(new Set(scene.zones.map(({ y }) => y)).size).toBeGreaterThan(1);
  const device = routed ? "router:core" : "device:FW";
  const keys = accessWires(scene, device);
  expect(keys.filter((key) => key.includes(":bus:")).length).toBeGreaterThan(1);
  expect(connectedWires(scene, keys)).toHaveLength(1);
  const glyph = scene.equipment.find(({ equipment }) => equipment.id === device)!;
  expect(scene.wires.find(({ key }) => key === device + ":trunk")!.path).toMatch(new RegExp(`^M ${glyph.x} ${glyph.y + 24} `));
  // The gutter keeps clear of the cards it feeds.
  const gutterX = Math.min(...scene.wires.filter(({ key }) => key.startsWith(device + ":gutter:")).map(({ path }) => Number(path.split(" ")[1])));
  expect(Math.min(...scene.zones.map(({ x }) => x)) - gutterX).toBeGreaterThanOrEqual(GUTTER_GAP);
  expect(gutterX).toBeGreaterThan(0);
  // Selecting any subnet lights one unbroken path from its drop back to the device trunk.
  for (const name of names) {
    const id = `segment:${name}`;
    const lit = scene.wires.filter(({ key, entities }) => keys.includes(key) && entities.includes(id)).map(({ key }) => key);
    const drop = scene.model.attachments.find(({ equipmentId, targetId }) => equipmentId === device && targetId === id)!.key;
    expect(lit).toContain(device + ":trunk");
    expect(lit).toContain(drop);
    expect(connectedWires(scene, lit)).toHaveLength(1);
  }
});
