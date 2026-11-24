import "@testing-library/jest-dom/vitest";
import { StrictMode } from "react";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import type { TopologyGraph } from "../src/api";
import * as capture from "../src/captureNetworkView";
import { NetworkDiagram } from "../src/NetworkDiagram";
import { groupRows, indexCoverage, tierOf } from "../src/networkCoverage";
import { diffTopology, resetShownRevisions } from "../src/networkDiff";

type Device = TopologyGraph["devices"][number];
const zeek = (hostname: string, segments: string[], depth: "protocol" | "connection" = "protocol"): Device => ({
  id: `device:${hostname}`, name: hostname.toLowerCase(), hostname, kind: "network", placement: "tap", direction: "bidirectional",
  description: "", log_formats: ["zeek"], default_interface: null,
  evidence: [{ family: "zeek", label: "Zeek", depth, formats: depth === "protocol" ? ["zeek_conn", "zeek_dns"] : ["zeek_conn"] }],
  associations: segments.map((name) => ({ segment_id: `segment:${name}`, monitored: true, interface_name: null })),
});
const snort = (hostname: string, segments: string[]): Device => ({
  ...zeek(hostname, segments), kind: "ids", log_formats: ["snort_alert"],
  evidence: [{ family: "ids", label: "Snort", depth: "alert", formats: ["snort_alert"] }],
});

// Two routed subnets behind a core router and an edge firewall that publishes the web server.
export const graphForProbe: TopologyGraph = {
  segments: [
    { id: "segment:users", name: "users", cidr: "10.1.0.0/24", exposure: "internal", description: "" },
    { id: "segment:servers", name: "servers", cidr: "10.2.0.0/24", exposure: "internal", description: "" },
    { id: "segment:edge", name: "edge", cidr: "10.9.0.0/30", exposure: "internal", description: "" },
  ],
  hosts: [
    { id: "host:WS", hostname: "WS", ip: "10.1.0.10", os: "Windows 11", os_family: "windows", type: "workstation", segment_ids: ["segment:users"], primary_segment_id: "segment:users" },
    { id: "host:WEB", hostname: "WEB", ip: "10.2.0.10", os: "Ubuntu 24.04", os_family: "linux", type: "server", segment_ids: ["segment:servers"], primary_segment_id: "segment:servers" },
  ],
  devices: [
    { ...zeek("FW", []), kind: "firewall", log_formats: ["cisco_asa"], evidence: [{ family: "asa", label: "Cisco ASA", depth: "firewall", formats: ["cisco_asa"] }],
      nat_rules: [{ type: "static", src: [], real_ip: "10.2.0.10", mapped_ip: "203.0.113.10" }, { type: "dynamic_pat", src: ["users"], mapped_ip: "203.0.113.1", real_ip: "" }],
      policy: [{ src: "external", dst: "servers", ports: ["443"], action: "permit" }, { src: "any", dst: "any", ports: ["22"], action: "deny" }],
      default_action: "deny" },
    zeek("ZEEK-USERS", ["users"], "connection"), zeek("ZEEK-SERVERS", ["servers"]), snort("IDS-SERVERS", ["servers"]),
  ],
  findings: [],
  routing: {
    devices: { edge: { kind: "firewall", firewall: "fw" }, core: { kind: "router" } },
    links: {
      upstream: { internet: true, interfaces: { edge: { name: "outside", ip: "192.0.2.1" } } },
      edge: { segment: "edge", interfaces: { edge: { name: "inside", ip: "10.9.0.1" }, core: { name: "edge", ip: "10.9.0.2" } } },
      users: { segment: "users", interfaces: { core: { name: "users", ip: "10.1.0.1" } } },
      servers: { segment: "servers", interfaces: { core: { name: "servers", ip: "10.2.0.1" } } },
    },
  },
  coverage: {
    endpoints: { "segment:users": "10.1.0.10", "segment:servers": "10.2.0.10", internet: "198.51.100.200" },
    paths: [
      { source: "segment:users", destination: "segment:servers", sensors: ["device:IDS-SERVERS", "device:ZEEK-SERVERS", "device:ZEEK-USERS"], delivered: true, reason: "",
        hops: [{ link: "users" }, { link: "servers", forwarder: "core" }] },
      { source: "internet", destination: "segment:servers", sensors: ["device:FW", "device:ZEEK-SERVERS"], delivered: true, reason: "",
        hops: [{ link: "upstream" }, { link: "edge", forwarder: "edge" }, { link: "servers", forwarder: "core" }] },
      { source: "segment:servers", destination: "segment:servers", sensors: [], delivered: true, reason: "", hops: [] },
      { source: "segment:users", destination: "segment:users", sensors: [], delivered: true, reason: "", hops: [] },
      { source: "segment:servers", destination: "segment:users", sensors: ["device:ZEEK-USERS"], delivered: true, reason: "",
        hops: [{ link: "servers" }, { link: "users", forwarder: "core" }] },
      { source: "segment:users", destination: "internet", sensors: ["device:FW"], delivered: false, reason: "FW denied traffic", hops: [{ link: "users" }] },
    ],
  },
};

const graph = graphForProbe;
beforeEach(resetShownRevisions);
afterEach(cleanup);

test("evidence tiers rank what the observing sensors actually write", () => {
  const devices = new Map(graph.devices.map((device) => [device.id, device]));
  expect(tierOf(["device:IDS-SERVERS", "device:ZEEK-SERVERS"], devices)).toBe("full");
  expect(tierOf(["device:ZEEK-SERVERS"], devices)).toBe("protocol");
  expect(tierOf(["device:IDS-SERVERS", "device:ZEEK-USERS"], devices)).toBe("alerts");
  expect(tierOf(["device:ZEEK-USERS"], devices)).toBe("connection");
  expect(tierOf(["device:FW"], devices)).toBe("firewall");
  expect(tierOf([], devices)).toBe("none");
  const index = indexCoverage(graph)!;
  // The outline compares traffic from elsewhere; traffic inside a subnet is reported on its own.
  expect(index.weakest("segment:servers")).toBe("protocol");
  expect(index.within("segment:servers")).toBe("none");
  expect(groupRows(index.rows("segment:servers", "to"), "segment:servers").map(({ tier, rows }) => [tier, rows.map(({ peer }) => peer)])).toEqual([
    ["full", ["segment:users"]], ["protocol", ["internet"]], ["none", ["segment:servers"]],
  ]);
  expect(indexCoverage({ ...graph, coverage: null })).toBeUndefined();
});

test("the visibility lens outlines subnets and explains when it is unavailable", async () => {
  const { container, rerender } = render(<NetworkDiagram graph={graph} />);
  const user = userEvent.setup();
  const lens = screen.getByRole("button", { name: "Visibility" });
  expect(lens).toBeEnabled();
  await user.click(lens);
  const servers = container.querySelector(".diagram-zone[aria-label^='Segment servers']")!;
  expect(servers).toHaveAttribute("data-coverage", "protocol");
  expect(servers.getAttribute("aria-label")).toMatch(/traffic within it is not observed$/);
  expect(servers.querySelector(".diagram-within-blind")).toHaveTextContent("Unobserved within");
  expect(within(screen.getByLabelText("Diagram key")).getByText("Not observed by any network sensor")).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Topology" }));
  expect(container.querySelector(".diagram-zone[data-coverage]")).toBeNull();
  rerender(<NetworkDiagram graph={{ ...graph, coverage: null }} />);
  expect(screen.getByRole("button", { name: "Visibility" })).toBeDisabled();
  expect(screen.getByRole("button", { name: "Visibility" })).toHaveAttribute("title", expect.stringMatching(/needs network sensors/));
});

test("a subnet's details group its traffic by evidence, and a row traces the path", async () => {
  const { container } = render(<NetworkDiagram graph={graph} />);
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: /Segment servers/ }));
  const evidence = within(screen.getByRole("complementary")).getByRole("region", { name: "Network evidence" });
  const groups = [...evidence.querySelectorAll(".diagram-coverage-group")].map((group) => [group.getAttribute("data-tier"), group.textContent]);
  expect(groups.map(([tier]) => tier)).toEqual(["full", "protocol", "none"]);
  expect(groups[2][1]).toContain("Within this subnet");
  expect(groups[1][1]).toContain("From the Internet");
  await user.hover(within(evidence).getByRole("button", { name: "From users" }));
  const lit = [...container.querySelectorAll(".diagram-edges path[data-highlighted='true']")];
  expect(lit.length).toBeGreaterThan(0);
  expect(container.querySelector(".diagram-zone[aria-label^='Segment users']")).toHaveAttribute("data-traced", "true");
  expect(container.querySelector(".diagram-device[aria-label='core Router']")).toHaveAttribute("data-traced", "true");
  await user.unhover(within(evidence).getByRole("button", { name: "From users" }));
  await user.click(within(evidence).getByRole("button", { name: "From this subnet" }));
  expect(evidence).toHaveTextContent("To users");
  await user.click(screen.getByRole("button", { name: /Segment users/ }));
  const outbound = within(screen.getByRole("complementary")).getByRole("region", { name: "Network evidence" });
  await user.click(within(outbound).getByRole("button", { name: "From this subnet" }));
  expect(outbound).toHaveTextContent("Not delivered: FW denied traffic");
});

test("a firewall's details list its address translation and ordered policy", async () => {
  render(<NetworkDiagram graph={graph} />);
  await userEvent.setup().click(screen.getByRole("button", { name: "Firewall FW" }));
  const details = screen.getByRole("complementary");
  expect(details).toHaveTextContent("10.2.0.10↔203.0.113.10static NAT");
  expect(details).toHaveTextContent("users→203.0.113.1dynamic PAT");
  const rules = [...details.querySelectorAll(".diagram-policy li")].map((rule) => rule.textContent);
  expect(rules).toEqual(["permit external → servers · ports 443", "deny any → any · ports 22", "deny everything else"]);
});

test("a firewall with many rules can filter them, keeping each rule's place in the policy", async () => {
  const fw = graph.devices[0];
  const policy = [...fw.policy!, ...["users", "servers", "edge", "any"].map((src) => ({ src, dst: "external", ports: ["25"], action: "deny" as const }))];
  render(<NetworkDiagram graph={{ ...graph, devices: [{ ...fw, policy }, ...graph.devices.slice(1)] }} />);
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: "Firewall FW" }));
  const details = screen.getByRole("complementary");
  const filter = within(details).getByRole("searchbox", { name: "Filter firewall rules" });
  expect(filter).toHaveAttribute("placeholder", "Filter 8 rules");
  await user.type(filter, "10.2.0.10");
  const rules = () => [...details.querySelectorAll(".diagram-policy li")].map((rule) => `${(rule as HTMLLIElement).value}. ${rule.textContent}`);
  expect(rules()).toEqual(["1. permit external → servers · ports 443", "2. deny any → any · ports 22", "4. deny servers → external · ports 25",
    "6. deny any → external · ports 25", "7. deny everything else"]);
  expect(details).toHaveTextContent("Policy 4 of 6");
  expect(details).toHaveTextContent("Address translation 1 of 2");
  await user.clear(filter);
  await user.type(filter, "nothing-like-this");
  expect(rules()).toEqual(["7. deny everything else"]);
});

test("a firewall with few rules shows them without a filter", async () => {
  render(<NetworkDiagram graph={graph} />);
  await userEvent.setup().click(screen.getByRole("button", { name: "Firewall FW" }));
  expect(within(screen.getByRole("complementary")).queryByRole("searchbox", { name: "Filter firewall rules" })).toBeNull();
});

test("export saves an image of exactly this view, and the menu can copy it instead", async () => {
  // user-event installs its own clipboard, so set up the user before replacing it.
  const user = userEvent.setup();
  const write = vi.fn(async () => undefined);
  const items: unknown[] = [];
  vi.stubGlobal("ClipboardItem", class { constructor(value: unknown) { items.push(value); } });
  Object.defineProperty(navigator, "clipboard", { value: { write }, configurable: true });
  const image = new Blob(["png"], { type: "image/png" });
  const view = vi.spyOn(capture, "captureViewImage").mockResolvedValue(image);
  const onSaveImage = vi.fn(async () => ({ status: "saved" as const, path: "/tmp/x.png" }));
  try {
    render(<NetworkDiagram graph={graph} exportName="Talos: HQ network" onSaveImage={onSaveImage} />);
    await user.click(screen.getByRole("button", { name: "Save image of this view" }));
    expect(onSaveImage).toHaveBeenCalledWith(image, "Talos- HQ network.png");
    // The capture is of the displayed map element, so it carries the current camera and layout.
    expect(view).toHaveBeenCalledWith(screen.getByRole("group", { name: /Network map/ }).querySelector("svg"));
    expect(await screen.findByText("Image saved")).toBeVisible();
    await user.click(screen.getByRole("button", { name: "More export options" }));
    await user.click(screen.getByRole("menuitem", { name: "Copy image to clipboard" }));
    expect(await screen.findByText("Image copied")).toBeVisible();
    expect(write).toHaveBeenCalledOnce();
    expect(items[0]).toHaveProperty(["image/png"]);
    expect(screen.queryByRole("menu")).toBeNull();
  } finally {
    view.mockRestore();
    vi.unstubAllGlobals();
  }
});

test("the toolbar reads from view controls to actions", () => {
  render(<NetworkDiagram graph={graph} revision="r" description="Organization pack · 1.0.0" onAsk={async () => undefined}
    actions={<button type="button">Refresh environment</button>} />);
  const toolbar = document.querySelector(".diagram-toolbar")!;
  const order = [...toolbar.querySelectorAll("button, input, p")].map((element) =>
    element.getAttribute("aria-label") || element.textContent?.trim());
  const position = (name: string) => order.findIndex((entry) => entry?.startsWith(name));
  const expected = ["Layers", "Topology", "Visibility", "Find in diagram", "Organization pack", "Ask about this diagram",
    "Refresh environment", "Save image of this view", "More export options", "Expand diagram"];
  expect(expected.map(position)).toEqual([...expected.map(position)].sort((a, b) => a - b));
  expect(expected.every((name) => position(name) >= 0)).toBe(true);
});

test("a new revision shows what changed since the item was last shown", async () => {
  const edited: TopologyGraph = {
    ...graph,
    hosts: [...graph.hosts.map((host) => host.id === "host:WEB" ? { ...host, ip: "10.2.0.11" } : host),
      { ...graph.hosts[0], id: "host:WS-2", hostname: "WS-2", ip: "10.1.0.11" }],
    devices: graph.devices.filter(({ id }) => id !== "device:IDS-SERVERS"),
  };
  expect(diffTopology(graph, graph)).toBeNull();
  const changes = diffTopology(graph, edited)!;
  expect([...changes.added]).toEqual(["host:WS-2"]);
  expect([...changes.changed]).toEqual(["host:WEB"]);
  expect(changes.removed).toEqual([{ id: "device:IDS-SERVERS", label: "IDS-SERVERS", kind: "sensor" }]);

  const first = render(<StrictMode><NetworkDiagram graph={graph} revision="r1" historyKey="item" /></StrictMode>);
  expect(screen.queryByText(/Changed since/)).toBeNull();
  first.unmount();
  const { container } = render(<StrictMode><NetworkDiagram graph={edited} revision="r2" historyKey="item" /></StrictMode>);
  const banner = screen.getByText(/Changed since the revision you last viewed/).closest(".diagram-changes")!;
  expect(banner).toHaveTextContent("1 added, 1 changed, 1 removed");
  const user = userEvent.setup();
  await waitFor(() => expect(container.querySelector(".diagram-host-card[aria-label^='WEB']")).toHaveAttribute("data-change", "changed"));
  await user.click(within(banner as HTMLElement).getByRole("button", { name: "Hide changes" }));
  expect(container.querySelector("[data-change]")).toBeNull();
  await user.click(screen.getByRole("button", { name: "Dismiss changes" }));
  expect(screen.queryByText(/Changed since/)).toBeNull();
});

test("diagram questions leave the derived coverage out of the chat topology", async () => {
  const onAsk = vi.fn(async () => undefined);
  const view = vi.spyOn(capture, "captureNetworkView").mockResolvedValue("data:image/png;base64,view");
  try {
    render(<NetworkDiagram graph={graph} revision="r" onAsk={onAsk} />);
    await userEvent.setup().click(screen.getByRole("button", { name: "Ask about this diagram" }));
    const [[context]] = onAsk.mock.calls as unknown as [[{ topology: TopologyGraph }]];
    expect(context.topology.coverage).toBeUndefined();
    expect(context.topology.segments).toEqual(graph.segments);
  } finally { view.mockRestore(); }
});
