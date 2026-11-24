import type { TopologyGraph } from "./api";

export interface DiagramLayers { sensors: boolean; firewalls: boolean; hosts: boolean }
export type DiagramSegment = TopologyGraph["segments"][number];
export type DiagramDevice = TopologyGraph["devices"][number];
export type Routing = NonNullable<TopologyGraph["routing"]>;
type RoutedDevice = Routing["devices"][string];
export type DiagramLink = Routing["links"][string];
export type DiagramLinkKind = NonNullable<DiagramLink["kind"]>;
export type DiagramLinkEntry = { id: string; name: string; link: DiagramLink };
export type DiagramHost = TopologyGraph["hosts"][number];
export type DiagramAssociation = DiagramDevice["associations"][number] & { device: DiagramDevice };

export type DiagramEntity =
  | { kind: "segment"; id: string; segment: DiagramSegment }
  | { kind: "device"; id: string; device: DiagramDevice; host?: DiagramHost }
  | { kind: "host"; id: string; host: DiagramHost }
  | { kind: "router"; id: string; name: string; device: RoutedDevice; host?: DiagramHost }
  | { kind: "unassigned"; id: string };

type EquipmentKind = "firewall" | "router" | "switch" | "network";
type Equipment = Extract<DiagramEntity, { kind: "device" | "host" | "router" }> & { equipment: EquipmentKind };
export type DiagramNode = DiagramEntity & {
  key: string; x: number; y: number; width: number; height: number; equipment?: EquipmentKind;
};
type Wire = {
  key: string; path: string; kind: "interface" | "membership" | "subnet" | "host"; entities: string[];
  linkKind?: DiagramLinkKind;
};
type Attachment = { equipment: Equipment; name: string | null };
type Subnet = Extract<DiagramEntity, { kind: "segment" | "unassigned" }> & { attachments: Attachment[] };
type Group = { subnets: Subnet[]; attachment?: Attachment };
type Station = { equipment: Equipment; transit?: Subnet };
type InterfaceLabel = { key: string; text: string; x: number; y: number; width: number; anchor: "start" | "end" };
export type SensorEntry = { device: DiagramDevice; mark: string };
export type Branch = {
  node: DiagramNode; hosts: DiagramHost[]; expanded: boolean; hostPage: number; railY: number; railX: number;
  railEnd: number; hostToggleY: number; sensors: SensorEntry[]; sensorStart: number; sensorEnd: number;
  vertical: boolean; side?: "left" | "right";
};

export const UNASSIGNED_HOSTS = "unassigned";
export const INLINE_HOST_LIMIT = 12;
export const MIN_READABLE_SCALE = 0.55;
const HOSTS_PER_ROW = 4;
const MARGIN = 44;
const BRANCH_WIDTH = 290;
const BRANCH_GAP = 36;
const SPINE_GAP = 128;
const DEVICE_WIDTH = 182;
const DEVICE_HEIGHT = 72;
const INTERNET_WIDTH = 152;
const INTERNET_HEIGHT = 64;
const GROUP_ROW = 134;
const HOST_HEIGHT = 42;
const HOST_ROW_HEIGHT = 58;
const HORIZONTAL_LABEL_OFFSET = 80;

export function indexDiagramHosts(hosts: DiagramHost[]): Map<string, DiagramHost[]> {
  const groups = new Map<string, DiagramHost[]>();
  for (const host of hosts) {
    for (const id of host.segment_ids.length ? host.segment_ids : [UNASSIGNED_HOSTS]) {
      const members = groups.get(id);
      if (members) members.push(host);
      else groups.set(id, [host]);
    }
  }
  return groups;
}

export function chooseInitialBranches(groups: Map<string, DiagramHost[]>, size: { width: number; height: number }): Set<string> {
  const slots = Math.max(1, Math.floor(size.width / 260)) * Math.max(1, Math.floor((size.height - 88) / 153));
  const congestion = Math.max(1, Math.ceil(groups.size / slots));
  let remaining = Math.max(2, Math.floor(Math.min(20, slots * HOSTS_PER_ROW) / congestion));
  const expanded = new Set<string>();
  const candidates = [...groups].filter(([, hosts]) => hosts.length > 0).sort(([left, a], [right, b]) =>
    Number(left === UNASSIGNED_HOSTS) - Number(right === UNASSIGNED_HOSTS) || a.length - b.length || left.localeCompare(right, "en"));
  for (const [id, hosts] of candidates) {
    if (hosts.length > INLINE_HOST_LIMIT || hosts.length > remaining) continue;
    expanded.add(id);
    remaining -= hosts.length;
  }
  return expanded;
}

function groupBy<T, Key>(items: T[], keyFor: (item: T) => Key): Map<Key, T[]> {
  const groups = new Map<Key, T[]>();
  for (const item of items) {
    const key = keyFor(item);
    const members = groups.get(key);
    if (members) members.push(item);
    else groups.set(key, [item]);
  }
  return groups;
}

function hostEquipment(host: DiagramHost): EquipmentKind | null {
  const roles = new Set((host.roles ?? []).map((role) => role.toLowerCase().replace(/[ -]+/g, "_")));
  if (["router", "core_router", "edge_router", "network_router"].some((role) => roles.has(role))) return "router";
  if (["switch", "core_switch", "network_switch"].some((role) => roles.has(role))) return "switch";
  // These platforms identify network appliances. They can run several different network roles.
  if (/^(?:Cisco (?:IOS|NX-OS|ASA)|Arista EOS|Juniper Junos|MikroTik RouterOS)\b/i.test(host.os)) return "network";
  return null;
}

function equipmentFor(graph: TopologyGraph, layers: DiagramLayers) {
  const equipment: Equipment[] = [];
  const claimedHosts = new Set<string>();
  const firewallNames = new Map<string, number>();
  const hostsByName = groupBy(graph.hosts, ({ hostname }) => hostname.toLowerCase());
  const firewalls = graph.devices.filter(({ kind }) => kind === "firewall");
  for (const { hostname } of firewalls) {
    const name = hostname.toLowerCase();
    firewallNames.set(name, (firewallNames.get(name) ?? 0) + 1);
  }
  for (const device of firewalls) {
    const name = device.hostname.toLowerCase();
    const matches = hostsByName.get(name);
    const host = matches?.length === 1 && firewallNames.get(name) === 1 ? matches[0] : undefined;
    if (host) claimedHosts.add(host.id);
    if (layers.firewalls) equipment.push({ kind: "device", id: device.id, device, host: layers.hosts ? host : undefined, equipment: "firewall" });
  }
  for (const [name, device] of Object.entries(graph.routing?.devices ?? {})) {
    const host = device.system ? hostsByName.get(device.system.toLowerCase())?.[0] : undefined;
    if (host) claimedHosts.add(host.id);
    if (device.kind !== "firewall") equipment.push({
      kind: "router", id: "router:" + name, name, device, host: layers.hosts ? host : undefined,
      equipment: device.kind,
    });
  }
  if (layers.hosts) {
    for (const host of graph.hosts) {
      const kind = hostEquipment(host);
      if (kind && !graph.routing && !claimedHosts.has(host.id) && host.segment_ids.length) {
        equipment.push({ kind: "host", id: host.id, host, equipment: kind });
        claimedHosts.add(host.id);
      }
    }
  }
  return { equipment, claimedHosts };
}

export function indexInlineHosts(graph: TopologyGraph, allHosts: Map<string, DiagramHost[]>) {
  const { claimedHosts } = equipmentFor(graph, { hosts: true, firewalls: true, sensors: true });
  return new Map([...allHosts].flatMap(([id, hosts]) => {
    const inline = hosts.filter((host) => !claimedHosts.has(host.id));
    return inline.length ? [[id, inline] as const] : [];
  }));
}

function indexAssociations(devices: DiagramDevice[]): Map<string, DiagramAssociation[]> {
  const entries = devices.flatMap((device) => device.associations.map((association) => ({ ...association, device })));
  return groupBy(entries, ({ segment_id }) => segment_id);
}

function buildSubnets(graph: TopologyGraph, equipment: Equipment[], unassigned: boolean) {
  const attachments = new Map<string, Attachment[]>();
  const segments = [...graph.segments];
  const linksBySegment = new Map<string, DiagramLinkEntry>();
  const links = Object.entries(graph.routing?.links ?? {});
  const multipleBoundaries = links.filter(([, link]) => link.internet).length > 1;
  for (const [name, link] of links) {
    const segment = graph.segments.find(({ name }) => name === link.segment);
    const id = segment?.id ?? "internet:" + name;
    if (link.internet) {
      const version = Object.values(link.interfaces)[0]?.ip.includes(":") ? "IPv6" : "IPv4";
      segments.push({ id, name: multipleBoundaries ? `Internet (${version})` : "Internet",
        cidr: "", description: "", exposure: "external" });
    }
    if (!segment && !link.internet) continue;
    linksBySegment.set(id, { id: "link:" + name, name, link });
    for (const [deviceId, iface] of Object.entries(link.interfaces)) {
      const device = graph.routing!.devices[deviceId];
      const item = equipment.find((entry) => (entry.kind === "device" && entry.device.name === device?.firewall)
        || (entry.kind === "router" && entry.name === deviceId));
      if (!item) continue;
      const entries = attachments.get(id) ?? [];
      entries.push({ equipment: item, name: iface.name });
      attachments.set(id, entries);
    }
  }
  if (!graph.routing) {
    for (const item of equipment) {
      for (const id of item.host?.segment_ids ?? []) {
        const entries = attachments.get(id) ?? [];
        entries.push({ equipment: item, name: null });
        attachments.set(id, entries);
      }
    }
  }
  const subnets: Subnet[] = segments.map((segment) => ({
    kind: "segment", id: segment.id, segment, attachments: attachments.get(segment.id) ?? [],
  }));
  if (unassigned) subnets.push({ kind: "unassigned", id: UNASSIGNED_HOSTS, attachments: [] });
  return { subnets, linksBySegment };
}

/** Follow a pair of modeled attachments through a shared subnet. Other links remain branches. */
function spineStations(equipment: Equipment[], subnets: Subnet[]): Station[][] {
  const shared = groupBy(
    subnets.filter(({ attachments }) => attachments.length === 2)
      .flatMap((subnet) => subnet.attachments.map(({ equipment }) => ({ id: equipment.id, subnet }))),
    ({ id }) => id,
  );
  const remaining = new Set(equipment.map(({ id }) => id));
  const spines: Station[][] = [];
  for (const root of equipment) {
    if (!remaining.has(root.id)) continue;
    const stations: Station[] = [{ equipment: root }];
    remaining.delete(root.id);
    let current = root;
    while (true) {
      const onward = shared.get(current.id)?.find(({ subnet }) => subnet.attachments.some(({ equipment }) => remaining.has(equipment.id)));
      const next = onward?.subnet.attachments.find(({ equipment }) => equipment.id !== current.id);
      if (!onward || !next) break;
      stations.push({ equipment: next.equipment, transit: onward.subnet });
      current = next.equipment;
      remaining.delete(current.id);
    }
    spines.push(stations);
  }
  return spines;
}

function ownerGroups(subnets: Subnet[], stations: Station[][]) {
  const order = new Map(stations.flat().map(({ equipment }, index) => [equipment.id, index]));
  const transit = new Set(stations.flatMap((spine) => spine.flatMap(({ transit }) => transit ? [transit.id] : [])));
  const groups = new Map<string, Group>();
  for (const subnet of subnets) {
    if (transit.has(subnet.id)) continue;
    const attachment = [...subnet.attachments].sort((a, b) => order.get(a.equipment.id)! - order.get(b.equipment.id)!)[0];
    // A shared subnet has its own rail and a separate connection to each device.
    const distinct = subnet.attachments.length > 1 || attachment?.name === null;
    const key = distinct ? subnet.id : JSON.stringify([attachment?.equipment.id, attachment?.name]);
    const group = groups.get(key);
    if (group) group.subnets.push(subnet);
    else groups.set(key, { subnets: [subnet], attachment });
  }
  return groupBy([...groups.values()], ({ attachment }) => attachment?.equipment.id);
}

function sensorLetter(ordinal: number): string {
  let label = "";
  for (let value = ordinal + 1; value > 0; value = Math.floor((value - 1) / 26)) {
    label = String.fromCharCode(65 + (value - 1) % 26) + label;
  }
  return label;
}

function path(...commands: (string | number)[]): string {
  return commands.join(" ");
}

/** Draw device-centered backbones, with subnet rails branching off actual interfaces and memberships. */
export function layoutNetworkDiagram(
  graph: TopologyGraph, layers: DiagramLayers, hostsBySegment: Map<string, DiagramHost[]>, expanded: ReadonlySet<string>,
  hostPages: Readonly<Record<string, number>> = {}, viewportWidth = Infinity,
) {
  const associations = indexAssociations(graph.devices);
  const { equipment, claimedHosts } = equipmentFor(graph, layers);
  const endpointHosts = (id: string) => layers.hosts ? (hostsBySegment.get(id) ?? []).filter((host) => !claimedHosts.has(host.id)) : [];
  const { subnets, linksBySegment } = buildSubnets(graph, equipment, endpointHosts(UNASSIGNED_HOSTS).length > 0);
  const boundaries = subnets.filter(({ id }) => linksBySegment.get(id)?.link.internet);
  const boundariesByDevice = groupBy(boundaries, ({ attachments }): string | undefined => attachments[0]?.equipment.id);
  const ordinarySubnets = subnets.filter((subnet) => !boundaries.includes(subnet));
  // Start at an Internet-facing device even when another firewall was declared first.
  const roots = [...equipment].sort((a, b) => Number(boundariesByDevice.has(b.id)) - Number(boundariesByDevice.has(a.id)));
  const spines = spineStations(roots, ordinarySubnets);
  const groups = ownerGroups(ordinarySubnets, spines);
  const sensors = layers.sensors ? graph.devices.filter(({ kind }) => kind !== "firewall")
    .map((device, ordinal) => ({ device, mark: sensorLetter(ordinal) })) : [];
  const sensorIndex = new Map(sensors.map((entry) => [entry.device.id, entry]));
  for (const [segmentId, declared] of linksBySegment) {
    const tapAssociations = graph.devices.filter(({ id }) => graph.link_taps?.[id]?.link === declared.name)
      .map((device) => ({ device, segment_id: segmentId, monitored: true, interface_name: null }));
    associations.set(segmentId, [...(associations.get(segmentId) ?? []), ...tapAssociations]);
  }
  const nodes: DiagramNode[] = [];
  const nodesById = new Map<string, DiagramNode>();
  const branches: Branch[] = [];
  const branchesById = new Map<string, Branch>();
  const wires: Wire[] = [];
  const labels: InterfaceLabel[] = [];
  const allGroups = [...groups.values()].flat();
  const largestStation = Math.max(0, ...spines.flat().map(({ equipment }) =>
    (groups.get(equipment.id) ?? []).reduce((count, { subnets }) => count + subnets.length, 0)));
  const denseRouting = !!graph.routing && largestStation > 2;
  const gutter = denseRouting ? Math.max(SPINE_GAP / 2, 44 + Math.ceil(largestStation / 2) * 12) : SPINE_GAP / 2;
  const branchWidth = graph.segments.reduce((width, segment) => Math.max(width, segment.cidr.length * 8 + 24), BRANCH_WIDTH);
  const desiredColumns = Math.min(4, Math.max(denseRouting ? 4 : equipment.length ? 2 : 1, ...allGroups.map(({ subnets }) => subnets.length)));
  const wideWidth = 2 * (MARGIN + 2 * branchWidth + BRANCH_GAP + gutter);
  const columns = viewportWidth < wideWidth * MIN_READABLE_SCALE ? Math.min(2, desiredColumns) : desiredColumns;
  const stride = branchWidth + BRANCH_GAP;
  const sideWidth = stride * Math.ceil(columns / 2) - BRANCH_GAP;
  const spineX = MARGIN + sideWidth + gutter;
  const secondaryLinks = allGroups.flatMap(({ subnets, attachment: owner }) => subnets.flatMap((subnet) =>
    subnet.attachments.filter(({ equipment }) => equipment.id !== owner?.equipment.id)
      .map((attachment) => ({ subnet, attachment }))));
  const linkCount = new Map<Equipment, number>();
  for (const { attachments } of subnets) {
    for (const { equipment } of attachments) linkCount.set(equipment, (linkCount.get(equipment) ?? 0) + 1);
  }
  const peripheralLinks = new Map<string, Attachment>();
  const crossLinks = secondaryLinks.filter(({ subnet, attachment }) => {
    const { equipment } = attachment;
    if (equipment.kind !== "host" || linkCount.get(equipment) !== 1 || peripheralLinks.has(subnet.id)) return true;
    peripheralLinks.set(subnet.id, attachment);
    return false;
  });
  const peripheral = new Set([...peripheralLinks.values()].map(({ equipment }) => equipment.id));
  const outerX = spineX + gutter + sideWidth;
  const width = columns === 1 ? branchWidth + 2 * MARGIN : outerX + MARGIN + crossLinks.length * 20;
  let y = MARGIN;

  function addNode(node: DiagramNode) {
    nodes.push(node);
    if (!nodesById.has(node.id)) nodesById.set(node.id, node);
    return node;
  }

  function wire(key: string, kind: Wire["kind"], entities: string[], line: string) {
    let linkKind: DiagramLinkKind | undefined;
    if (kind !== "host") {
      for (const id of [...entities]) {
        const link = linksBySegment.get(id);
        if (link) {
          entities.push(link.id);
          linkKind = link.link.kind ?? "network";
        }
      }
    }
    wires.push({ key, kind, entities, path: line, linkKind });
  }

  function attachmentWire(link: Attachment, ids: string[], key: string, line: string) {
    wire(key, link.name === null ? "membership" : "interface", [link.equipment.id, ...ids], line);
  }

  function branchBox(subnet: Subnet, x: number, railY: number, vertical = false, side?: Branch["side"]) {
    const link = linksBySegment.get(subnet.id);
    const internet = link?.link.internet;
    const hosts = endpointHosts(subnet.id);
    const open = hosts.length > 0 && expanded.has(subnet.id);
    const hostPage = Math.min(hostPages[subnet.id] ?? 0, Math.max(0, Math.ceil(hosts.length / INLINE_HOST_LIMIT) - 1));
    const labelOnly = vertical && hosts.length === 0 && !internet;
    const node = addNode({ ...subnet, key: subnet.id, x: labelOnly ? spineX - branchWidth / 2 - 115 : x,
      y: railY - (internet ? INTERNET_HEIGHT : labelOnly ? 29 : side ? 49 : HORIZONTAL_LABEL_OFFSET),
      width: internet ? INTERNET_WIDTH : branchWidth, height: internet ? INTERNET_HEIGHT : 39 });
    const entries = associations.get(subnet.id) ?? [];
    const markers = entries.flatMap(({ device, monitored }) => {
      const entry = sensorIndex.get(device.id);
      return entry && monitored ? [entry] : [];
    });
    const railEnd = x + branchWidth - 8;
    const railX = internet ? x + INTERNET_WIDTH / 2 : vertical ? spineX : side === "left" ? railEnd : x + 8;
    const monitoringFirewalls = layers.firewalls ? entries
      .filter(({ monitored, device }) => monitored && device.kind === "firewall").map(({ device }) => device.id) : [];
    const entities = [subnet.id, ...subnet.attachments.map(({ equipment }) => equipment.id),
      ...markers.map(({ device }) => device.id), ...monitoringFirewalls];
    if (side) {
      wire(subnet.id + ":rail", "subnet", entities, path("M", railX, railY - 64, "V", railY + 44));
    } else if (subnet.kind === "segment" && (!vertical || hosts.length)) {
      wire(subnet.id + ":rail", "subnet", entities, path("M", x + 8, railY, "H", vertical ? railX : railEnd));
    }
    const center = x + branchWidth / 2;
    const singleSideHost = side && hosts.length === 1;
    const hostY = railY + (singleSideHost ? 14 : side ? 45 : 18);
    const pageRows = open ? Math.ceil(Math.min(hosts.length, INLINE_HOST_LIMIT) / HOSTS_PER_ROW) : 1;
    const paged = hosts.length > INLINE_HOST_LIMIT;
    const hostToggleY = hostY + HOST_HEIGHT + (pageRows - 1) * HOST_ROW_HEIGHT + (paged ? 20 : 14);
    const stackY = railY + 26;
    const stackLink = side ? path("M", railX, stackY, "H", center + (side === "left" ? 14 : -14))
      : path("M", center, railY, "v", 13);
    if (open) {
      const start = hostPage * INLINE_HOST_LIMIT;
      const visible = hosts.slice(start, start + INLINE_HOST_LIMIT);
      const multipleRows = pageRows > 1;
      const gutterX = side === "right" ? railEnd : x + 8;
      if (multipleRows && subnet.kind === "segment") {
        const lastJunctionY = hostY + (Math.ceil(visible.length / HOSTS_PER_ROW) - 1) * HOST_ROW_HEIGHT - 8;
        wire(subnet.id + ":fanout", "host", [subnet.id, ...visible.map(({ id }) => id)],
          side ? path("M", railX, stackY, "H", gutterX, "V", lastJunctionY)
            : path("M", gutterX, railY, "V", lastJunctionY));
      }
      for (let offset = 0; offset < visible.length; offset += HOSTS_PER_ROW) {
        const row = visible.slice(offset, offset + HOSTS_PER_ROW);
        const slot = Math.min(106, (branchWidth - (multipleRows ? 32 : 16)) / row.length);
        const rowCenter = center + (multipleRows ? (side === "right" ? -8 : 8) : 0);
        const halfSpan = (row.length - 1) * slot / 2;
        const rowY = hostY + offset / HOSTS_PER_ROW * HOST_ROW_HEIGHT;
        const junctionY = multipleRows ? rowY - 8 : side ? hostY - 6 : railY;
        if (subnet.kind === "segment") {
          const ids = [subnet.id, ...row.map(({ id }) => id)];
          if (multipleRows) {
            wire(subnet.id + ":hosts:" + offset, "host", ids,
              path("M", gutterX, junctionY, "H", rowCenter + (side === "right" ? -halfSpan : halfSpan)));
          } else if (side && !singleSideHost) {
            wire(subnet.id + ":fanout", "host", ids,
              path("M", railX, stackY, "H", center, "V", junctionY, "M", center - halfSpan, junctionY, "H", center + halfSpan));
          }
        }
        row.forEach((host, index) => {
          const hostCenter = rowCenter - halfSpan + index * slot;
          const key = JSON.stringify([subnet.id, host.id]);
          addNode({ kind: "host", host, id: host.id, key, x: hostCenter - slot / 2, y: rowY, width: slot, height: HOST_HEIGHT });
          if (subnet.kind === "segment") {
            wire(key, "host", [host.id, subnet.id], singleSideHost ? stackLink : path("M", hostCenter, junctionY, "V", rowY));
          }
        });
      }
    } else if (hosts.length && subnet.kind === "segment") {
      wire(subnet.id + ":stack", "host", [subnet.id], stackLink);
    }
    // Leave room at each endpoint and above the host branch for the sensor bodies and stems.
    const sensorStart = side ? railY - 52 : railX + 15;
    const sensorEnd = side ? railY + (hosts.length ? 11 : 31) : railEnd - 17;
    const branch: Branch = { node, hosts, expanded: open, hostPage, railY, railX, railEnd, hostToggleY, sensors: markers,
      sensorStart, sensorEnd, vertical, side };
    branches.push(branch);
    branchesById.set(subnet.id, branch);
    return branch;
  }

  function interfaceLabel(link: Attachment, key: string, x: number, baseline: number, includeDevice: boolean,
    width = branchWidth, anchor: InterfaceLabel["anchor"] = "start") {
    if (link.name === null) return;
    const owner = link.equipment;
    const hostname = owner.kind === "device" ? owner.device.hostname : owner.kind === "router" ? owner.name : owner.host.hostname;
    labels.push({ key, text: includeDevice ? hostname + " · " + link.name : link.name, x, y: baseline, width, anchor });
  }

  function descent(branch: Branch) {
    // Keep the host controls fixed across pages, including a shorter last page.
    return branch.hosts.length ? branch.hostToggleY - branch.railY + 26 : 34;
  }

  function layInternet(subnets: Subnet[], top: number, sideOfTransit = false) {
    if (!subnets.length) return top;
    const center = columns === 1 ? width / 2 : spineX;
    const cloudCenter = center + (sideOfTransit ? gutter + INTERNET_WIDTH / 2 : 0);
    const cloudBottom = top + INTERNET_HEIGHT;
    const branches = subnets.map((subnet, index) => {
      const offset = (index - (subnets.length - 1) / 2) * (INTERNET_WIDTH + 20);
      return branchBox(subnet, cloudCenter + offset - INTERNET_WIDTH / 2, cloudBottom, true);
    });
    const attached = subnets[0].attachments.length > 0;
    const markers = Math.min(4, Math.max(...branches.map(({ sensors }) => sensors.length)));
    const gap = attached ? 62 : markers ? 38 : 18;
    const bottom = cloudBottom + gap + Math.max(0, markers - 1) * 26;
    branches.forEach((branch, index) => {
      const { railX, node } = branch;
      const link = subnets[index].attachments[0];
      branch.sensorStart = cloudBottom + 16;
      branch.sensorEnd = bottom - (attached ? 36 : 12);
      if (link) {
        const port = center + Math.sign(railX - center) * 16;
        const line = railX === center ? path("M", railX, cloudBottom, "V", bottom + 13)
          : path("M", railX, cloudBottom, "V", bottom - 12, "H", port, "V", bottom + 17);
        attachmentWire(link, [node.id], node.id + ":uplink", line);
        interfaceLabel(link, node.id + ":interface", railX + 12, bottom - 17, false, branchWidth / 2);
      } else if (branch.sensors.length) {
        wire(node.id + ":uplink", "subnet", [node.id, ...branch.sensors.map(({ device }) => device.id)],
          path("M", railX, cloudBottom, "V", bottom));
      }
    });
    return bottom;
  }

  function layRows(group: Group, top: number, feedX: number) {
    let rowTop = top;
    let lastTop = top;
    const sharedSubnet = group.subnets.length === 1 && group.subnets[0].attachments.length > 1;
    for (let offset = 0; offset < group.subnets.length; offset += columns) {
      lastTop = rowTop;
      const row = group.subnets.slice(offset, offset + columns);
      const leftCount = Math.floor(row.length / 2);
      const left = spineX - gutter - leftCount * stride + BRANCH_GAP;
      const instances = row.map((subnet, index) => {
        const x = columns === 1 ? MARGIN : row.length === 1 && !group.attachment
          ? spineX - branchWidth / 2 : index < leftCount
          ? left + index * stride : spineX + gutter + (index - leftCount) * stride;
        return branchBox(subnet, x, rowTop + HORIZONTAL_LABEL_OFFSET + 3);
      });
      const link = group.attachment;
      if (link) {
        const leftPort = instances[0].node.x + (leftCount ? branchWidth - 8 : 8);
        const rightPort = instances[row.length - 1].node.x + 8;
        const ids = group.subnets.map(({ id }) => id);
        const trunk = leftCount ? leftPort : feedX;
        attachmentWire(link, ids, JSON.stringify([link.equipment.id, group.subnets[0].id, offset]),
          path("M", trunk, rowTop, "H", Math.max(rightPort, feedX)));
        instances.forEach((branch, index) => {
          const port = index < leftCount ? branch.railEnd : branch.railX;
          attachmentWire(link, [branch.node.id], branch.node.id + ":drop", path("M", port, rowTop, "V", branch.railY));
          const extra = peripheralLinks.get(branch.node.id);
          if (extra) {
            const center = branch.railX - 128;
            addNode({ ...extra.equipment, key: extra.equipment.id, x: center - DEVICE_WIDTH / 2,
              y: branch.railY - 32, width: DEVICE_WIDTH, height: DEVICE_HEIGHT });
            attachmentWire(extra, [branch.node.id], branch.node.id + ":peripheral",
              path("M", center + 22, branch.railY, "H", branch.railX));
          }
        });
        if (offset + columns < group.subnets.length) {
          attachmentWire(link, ids, group.subnets[0].id + ":spine:" + offset,
            path("M", feedX, rowTop, "V", Math.max(rowTop + GROUP_ROW, ...instances.map((b) => b.railY + descent(b)))));
        }
      }
      rowTop = Math.max(rowTop + GROUP_ROW, ...instances.map((b) => b.railY + descent(b)));
      if (sharedSubnet) rowTop += 24;
    }
    return { bottom: rowTop, lastTop };
  }

  // A separate two-device network fits in one row when neither end has other branches.
  function layDetachedPair(stations: Station[]) {
    const transit = stations[1]?.transit;
    if (y === MARGIN || stations.length !== 2 || !transit
      || stations.some(({ equipment }) => groups.has(equipment.id) || boundariesByDevice.has(equipment.id))
      || crossLinks.some(({ attachment }) => stations.some(({ equipment }) => equipment.id === attachment.equipment.id))) return false;
    const branch = branchBox(transit, spineX - branchWidth / 2, y + HORIZONTAL_LABEL_OFFSET + 2);
    stations.forEach(({ equipment }, index) => {
      const center = spineX + (index === 0 ? -1 : 1) * (branchWidth / 2 + 95);
      addNode({ ...equipment, key: equipment.id, x: center - DEVICE_WIDTH / 2, y: branch.railY - 32, width: DEVICE_WIDTH, height: DEVICE_HEIGHT });
      const link = transit.attachments.find((attachment) => attachment.equipment.id === equipment.id)!;
      attachmentWire(link, [transit.id], transit.id + ":" + equipment.id,
        path("M", center + (index === 0 ? 22 : -22), branch.railY, "H", index === 0 ? branch.railX : branch.railEnd));
      interfaceLabel(link, transit.id + ":" + equipment.id + ":interface",
        index === 0 ? branch.railX - 52 : branch.railEnd + 8, branch.railY - 10, false);
    });
    y = branch.railY + Math.max(descent(branch), 54) + 26;
    return true;
  }

  // Finish a router's access links inside its own section of the backbone.
  function layRoutedBranches(groups: Group[], deviceY: number) {
    const columnsPerSide = Math.floor(columns / 2);
    const branchesPerRow = columnsPerSide * 2;
    const leaves = groups.flatMap(({ attachment, subnets }) => subnets.map((subnet) => ({ subnet, attachment: attachment! })));
    const lanes = groupBy(leaves.map((leaf, index) => ({
      ...leaf, side: index % 2 ? 1 : -1, column: Math.floor(index / 2) % columnsPerSide, row: Math.floor(index / branchesPerRow),
    })), ({ side }) => side);
    const slots = [...lanes.values()].flatMap((side) => side
      .sort((a, b) => a.row - b.row || b.column - a.column)
      .map((leaf, index) => ({ ...leaf, lane: side.length - index, position: index / Math.max(1, side.length - 1) })));
    let top = deviceY + DEVICE_HEIGHT + 4;
    for (let row = 0; row < Math.ceil(leaves.length / branchesPerRow); row++) {
      let bottom = top;
      for (const { subnet, attachment, side, column, lane, position } of slots.filter((slot) => slot.row === row)) {
        const x = spineX + side * (gutter + column * stride) - (side < 0 ? branchWidth : 0);
        const branch = branchBox(subnet, x, top + HORIZONTAL_LABEL_OFFSET + 33);
        const exitX = spineX + side * (36 + lane * 12);
        const runY = top + (column === 1 ? 0 : 18);
        const port = side < 0 ? branch.railEnd : branch.railX;
        attachmentWire(attachment, [subnet.id], subnet.id + ":access", path(
          "M", spineX + side * 21, deviceY + 16 + position * 35, "H", exitX, "V", runY, "H", port, "V", branch.railY,
        ));
        interfaceLabel(attachment, subnet.id + ":interface", port + side * 8, runY - 4, false,
          branchWidth / 2, side < 0 ? "end" : "start");
        bottom = Math.max(bottom, branch.railY + descent(branch));
      }
      top = bottom + 12;
    }
    return top;
  }

  y = layInternet(boundariesByDevice.get(undefined) ?? [], y);
  for (const stations of spines) {
    if (stations.length === 1 && peripheral.has(stations[0].equipment.id)) continue;
    if (layDetachedPair(stations)) continue;
    const postponed: { group: Group; node: DiagramNode }[] = [];
    for (const [index, station] of stations.entries()) {
      const stationGroups = groups.get(station.equipment.id) ?? [];
      const uplinks = boundariesByDevice.get(station.equipment.id) ?? [];
      const sparse = stationGroups.every(({ subnets }) => subnets.length === 1 && subnets[0].attachments.length === 1);
      const localRows = !!graph.routing && (stationGroups.length > 2 || !sparse);
      const sideGroups = localRows ? [] : stationGroups.filter(({ subnets }) => subnets.length === 1 && subnets[0].attachments.length === 1)
        .sort((a, b) => Number(b.attachment?.name === "dmz") - Number(a.attachment?.name === "dmz"))
        .slice(0, stationGroups.some(({ subnets }) => subnets.length > 1) ? 1 : 2);
      if (station.transit) {
        const { transit } = station;
        const previous = nodesById.get(stations[index - 1].equipment.id)!;
        const upper = transit.attachments.find(({ equipment }) => equipment.id === previous.id)!;
        const lower = transit.attachments.find(({ equipment }) => equipment.id === station.equipment.id)!;
        const top = y;
        const railY = top + (graph.routing ? 28 : 48);
        const branch = branchBox(transit, spineX - gutter - branchWidth, railY, true);
        attachmentWire(upper, [transit.id], transit.id + ":up", path("M", spineX, previous.y + 55, "V", railY));
        interfaceLabel(upper, transit.id + ":upper-interface", spineX + 12, graph.routing ? top + 8 : railY - 54, false);
        if (graph.routing) {
          const markerSpace = Math.max(0, Math.min(4, branch.sensors.length) - 1) * 26;
          y = Math.max(top + 55 + markerSpace, branch.hosts.length ? railY + descent(branch) : 0);
          if (sideGroups.length) y += 22;
          branch.sensorStart = top + 21;
          branch.sensorEnd = y - 21;
        } else {
          y = Math.max(railY + 52, branch.hosts.length ? railY + descent(branch) : 0);
          if (sideGroups.length) y += 26;
          branch.sensorStart = Math.max(previous.y + DEVICE_HEIGHT + 16, upper.name === null ? railY - 43 : railY - 33);
          branch.sensorEnd = y - (lower.name === null ? 12 : 24);
        }
        y = layInternet(uplinks, y, true);
        attachmentWire(lower, [transit.id], transit.id + ":down", path("M", spineX, railY, "V", y + 13));
        interfaceLabel(lower, transit.id + ":lower-interface", spineX + 12, y - 8, false);
      } else {
        y = layInternet(uplinks, y);
      }

      const deviceY = y;
      const node = addNode({ ...station.equipment, key: station.equipment.id, x: spineX - DEVICE_WIDTH / 2,
        y: deviceY, width: DEVICE_WIDTH, height: DEVICE_HEIGHT });
      if (localRows) {
        y = layRoutedBranches(stationGroups, deviceY);
        continue;
      }
      y = deviceY + DEVICE_HEIGHT;
      sideGroups.forEach((group, slot) => {
        const link = group.attachment!;
        const left = sideGroups.length === 2 ? slot === 0 : index % 2 === 0;
        const branch = branchBox(group.subnets[0], left ? spineX - gutter - branchWidth : spineX + gutter,
          deviceY + 32, false, left ? "left" : "right");
        attachmentWire(link, [branch.node.id], branch.node.id + ":side",
          path("M", spineX + (left ? -22 : 22), branch.railY, "H", left ? branch.railEnd : branch.railX));
        interfaceLabel(link, branch.node.id + ":interface", left ? branch.railEnd + 7 : spineX + 29,
          branch.railY - 10, false, gutter - 26);
        y = Math.max(y, branch.railY + descent(branch));
      });
      const later = stationGroups.filter((group) => !sideGroups.includes(group));
      for (const group of later) postponed.push({ group, node });
      y += 12;
    }

    const feeds = groupBy(postponed, ({ node, group }) => JSON.stringify([node.id, group.attachment?.name ?? group.subnets[0].id]));
    [...feeds.values()].forEach((sections, lane) => {
      const feeder = spineX + 49 + lane * 9;
      let previousTop: number | undefined;
      for (const { group, node } of sections) {
        const link = group.attachment!;
        const top = y + 18;
        const ids = group.subnets.map(({ id }) => id);
        if (previousTop === undefined) {
          const sharedIds = sections.flatMap(({ group }) => group.subnets.map(({ id }) => id));
          attachmentWire(link, sharedIds, ids[0] + ":feed",
            path("M", spineX + 22, node.y + 34 + lane * 6, "H", feeder, "V", top));
          interfaceLabel(link, ids[0] + ":interface", feeder + 8, top - 11, true);
        } else {
          attachmentWire(link, ids, ids[0] + ":extension", path("M", feeder, previousTop, "V", top));
        }
        const rows = layRows(group, top, feeder);
        y = rows.bottom;
        previousTop = rows.lastTop;
      }
    });
    y += 36;
  }
  for (const group of groups.get(undefined) ?? []) y = layRows(group, y + 18, spineX).bottom;

  // Retain loops and extra links through shared subnets without reusing another device's port.
  let crossLane = 0;
  for (const { subnet, attachment } of crossLinks) {
    const branch = branchesById.get(subnet.id)!;
    const node = nodesById.get(attachment.equipment.id)!;
    const lane = outerX + 17 + crossLane++ * 15;
    const exitY = node.y + 12;
    attachmentWire(attachment, [subnet.id], JSON.stringify([subnet.id, attachment.equipment.id]),
      path("M", spineX + 22, exitY, "H", lane, "V", branch.railY, "H", branch.railEnd));
    interfaceLabel(attachment, subnet.id + ":" + attachment.equipment.id, branch.railEnd + 12, branch.railY - 7, false);
  }

  const entities = new Map<string, DiagramEntity>(nodesById);
  for (const { device } of sensors) {
    if (!entities.has(device.id)) entities.set(device.id, { kind: "device", id: device.id, device });
  }
  if (layers.hosts) for (const host of graph.hosts) {
    if (!entities.has(host.id)) entities.set(host.id, { kind: "host", id: host.id, host });
  }
  return { nodes, nodesById, entities, wires, labels, branches, sensors, associations, linksBySegment, spineX, width, height: Math.max(y + MARGIN, 180) };
}
