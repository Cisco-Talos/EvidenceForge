import type { TopologyGraph } from "./api";

export interface DiagramLayers { sensors: boolean; firewalls: boolean; hosts: boolean }
export type DiagramSegment = TopologyGraph["segments"][number];
export type DiagramDevice = TopologyGraph["devices"][number];
export type DiagramHost = TopologyGraph["hosts"][number];
export type DiagramAssociation = DiagramDevice["associations"][number] & { device: DiagramDevice };

export type DiagramEntity =
  | { kind: "segment"; id: string; segment: DiagramSegment }
  | { kind: "device"; id: string; device: DiagramDevice; host?: DiagramHost }
  | { kind: "host"; id: string; host: DiagramHost }
  | { kind: "unassigned"; id: string };

type EquipmentKind = "firewall" | "router" | "switch" | "network";
type Equipment = Extract<DiagramEntity, { kind: "device" | "host" }> & { equipment: EquipmentKind };
export type DiagramNode = DiagramEntity & {
  key: string; x: number; y: number; width: number; height: number; equipment?: EquipmentKind;
};
type Wire = { key: string; path: string; kind: "interface" | "membership" | "subnet" | "host"; entities: string[] };
type Attachment = { equipment: Equipment; name: string | null };
type Subnet = Extract<DiagramEntity, { kind: "segment" | "unassigned" }> & { attachments: Attachment[] };
type Group = { subnets: Subnet[]; attachment?: Attachment };
type Station = { equipment: Equipment; transit?: Subnet };
export type SensorEntry = { device: DiagramDevice; mark: string };
export type Branch = {
  node: DiagramNode; hosts: DiagramHost[]; expanded: boolean; hostPage: number; railY: number; railX: number;
  railEnd: number; hostToggleY: number; sensors: SensorEntry[]; sensorStart: number; sensorEnd: number;
  vertical: boolean; side?: "left" | "right";
};

export const UNASSIGNED_HOSTS = "unassigned";
export const INLINE_HOST_LIMIT = 12;
const HOSTS_PER_ROW = 4;
const MARGIN = 44;
const BRANCH_WIDTH = 290;
const BRANCH_GAP = 36;
const SPINE_GAP = 128;
const DEVICE_WIDTH = 182;
const DEVICE_HEIGHT = 72;
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
  if (layers.hosts) {
    for (const host of graph.hosts) {
      const kind = hostEquipment(host);
      if (kind && !claimedHosts.has(host.id) && host.segment_ids.length) {
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

function buildSubnets(graph: TopologyGraph, equipment: Equipment[], unassigned: boolean): Subnet[] {
  const attachments = new Map<string, Attachment[]>();
  for (const item of equipment) {
    const interfaces = new Map<string, string | null>(item.host?.segment_ids.map((id) => [id, null]));
    if (item.kind === "device") {
      for (const { segment_id, interface_name } of item.device.associations) {
        if (interface_name !== null) interfaces.set(segment_id, interface_name);
      }
    }
    for (const [id, name] of interfaces) {
      const link = { equipment: item, name };
      const entries = attachments.get(id);
      if (entries) entries.push(link);
      else attachments.set(id, [link]);
    }
  }
  const subnets: Subnet[] = graph.segments.map((segment) => ({
    kind: "segment", id: segment.id, segment, attachments: attachments.get(segment.id) ?? [],
  }));
  if (unassigned) subnets.push({ kind: "unassigned", id: UNASSIGNED_HOSTS, attachments: [] });
  return subnets;
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
  hostPages: Readonly<Record<string, number>> = {},
) {
  const associations = indexAssociations(graph.devices);
  const { equipment, claimedHosts } = equipmentFor(graph, layers);
  const endpointHosts = (id: string) => layers.hosts ? (hostsBySegment.get(id) ?? []).filter((host) => !claimedHosts.has(host.id)) : [];
  const subnets = buildSubnets(graph, equipment, endpointHosts(UNASSIGNED_HOSTS).length > 0);
  const spines = spineStations(equipment, subnets);
  const groups = ownerGroups(subnets, spines);
  const sensors = layers.sensors ? graph.devices.filter(({ kind }) => kind !== "firewall")
    .map((device, ordinal) => ({ device, mark: sensorLetter(ordinal) })) : [];
  const sensorIndex = new Map(sensors.map((entry) => [entry.device.id, entry]));
  const nodes: DiagramNode[] = [];
  const nodesById = new Map<string, DiagramNode>();
  const branches: Branch[] = [];
  const branchesById = new Map<string, Branch>();
  const wires: Wire[] = [];
  const labels: { key: string; text: string; x: number; y: number; width: number }[] = [];
  const allGroups = [...groups.values()].flat();
  const columns = Math.min(4, Math.max(equipment.length ? 2 : 1, ...allGroups.map(({ subnets }) => subnets.length)));
  const branchWidth = graph.segments.reduce((width, segment) => Math.max(width, segment.cidr.length * 8 + 24), BRANCH_WIDTH);
  const stride = branchWidth + BRANCH_GAP;
  const sideWidth = stride * Math.ceil(columns / 2) - BRANCH_GAP;
  const spineX = MARGIN + sideWidth + SPINE_GAP / 2;
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
  const outerX = spineX + SPINE_GAP / 2 + sideWidth;
  const width = columns === 1 ? branchWidth + 2 * MARGIN : outerX + MARGIN + crossLinks.length * 20;
  let y = MARGIN;

  function addNode(node: DiagramNode) {
    nodes.push(node);
    if (!nodesById.has(node.id)) nodesById.set(node.id, node);
    return node;
  }

  function wire(key: string, kind: Wire["kind"], entities: string[], line: string) {
    wires.push({ key, kind, entities, path: line });
  }

  function attachmentWire(link: Attachment, ids: string[], key: string, line: string) {
    wire(key, link.name === null ? "membership" : "interface", [link.equipment.id, ...ids], line);
  }

  function branchBox(subnet: Subnet, x: number, railY: number, vertical = false, side?: Branch["side"]) {
    const hosts = endpointHosts(subnet.id);
    const open = hosts.length > 0 && expanded.has(subnet.id);
    const hostPage = Math.min(hostPages[subnet.id] ?? 0, Math.max(0, Math.ceil(hosts.length / INLINE_HOST_LIMIT) - 1));
    const labelOnly = vertical && hosts.length === 0;
    const node = addNode({ ...subnet, key: subnet.id, x: labelOnly ? spineX - branchWidth / 2 - 115 : x,
      y: railY - (labelOnly ? 29 : side ? 49 : HORIZONTAL_LABEL_OFFSET), width: branchWidth, height: 39 });
    const entries = associations.get(subnet.id) ?? [];
    const markers = entries.flatMap(({ device, monitored }) => {
      const entry = sensorIndex.get(device.id);
      return entry && monitored ? [entry] : [];
    });
    const railEnd = x + branchWidth - 8;
    const railX = vertical ? spineX : side === "left" ? railEnd : x + 8;
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
    const branch = { node, hosts, expanded: open, hostPage, railY, railX, railEnd, hostToggleY, sensors: markers,
      sensorStart, sensorEnd, vertical, side };
    branches.push(branch);
    branchesById.set(subnet.id, branch);
    return branch;
  }

  function interfaceLabel(link: Attachment, key: string, x: number, baseline: number, includeDevice: boolean) {
    if (link.name === null) return;
    const hostname = link.equipment.kind === "device" ? link.equipment.device.hostname : link.equipment.host.hostname;
    labels.push({ key, text: includeDevice ? hostname + " · " + link.name : link.name, x, y: baseline, width: branchWidth });
  }

  function descent(branch: Branch) {
    // Keep the host controls fixed across pages, including a shorter last page.
    return branch.hosts.length ? branch.hostToggleY - branch.railY + 26 : 34;
  }

  function layRows(group: Group, top: number, feedX: number) {
    let rowTop = top;
    let lastTop = top;
    const sharedSubnet = group.subnets.length === 1 && group.subnets[0].attachments.length > 1;
    for (let offset = 0; offset < group.subnets.length; offset += columns) {
      lastTop = rowTop;
      const row = group.subnets.slice(offset, offset + columns);
      const leftCount = Math.floor(row.length / 2);
      const left = spineX - SPINE_GAP / 2 - leftCount * stride + BRANCH_GAP;
      const instances = row.map((subnet, index) => {
        const x = columns === 1 ? MARGIN : row.length === 1 && !group.attachment
          ? spineX - branchWidth / 2 : index < leftCount
          ? left + index * stride : spineX + SPINE_GAP / 2 + (index - leftCount) * stride;
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
    if (y === MARGIN || stations.length !== 2 || !transit || stations.some(({ equipment }) => groups.has(equipment.id))
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

  for (const stations of spines) {
    if (stations.length === 1 && peripheral.has(stations[0].equipment.id)) continue;
    if (layDetachedPair(stations)) continue;
    const postponed: { group: Group; node: DiagramNode }[] = [];
    for (const [index, station] of stations.entries()) {
      const stationGroups = groups.get(station.equipment.id) ?? [];
      // Use the upper branches for end subnets, with larger interface groups below the spine.
      const sideGroups = stationGroups.filter(({ subnets }) => subnets.length === 1 && subnets[0].attachments.length === 1)
        .sort((a, b) => Number(b.attachment?.name === "dmz") - Number(a.attachment?.name === "dmz"))
        .slice(0, stationGroups.some(({ subnets }) => subnets.length > 1) ? 1 : 2);
      if (station.transit) {
        const { transit } = station;
        const previous = nodesById.get(stations[index - 1].equipment.id)!;
        const upper = transit.attachments.find(({ equipment }) => equipment.id === previous.id)!;
        const lower = transit.attachments.find(({ equipment }) => equipment.id === station.equipment.id)!;
        const railY = y + 48;
        const branch = branchBox(transit, spineX - SPINE_GAP / 2 - branchWidth, railY, true);
        attachmentWire(upper, [transit.id], transit.id + ":up", path("M", spineX, previous.y + 55, "V", railY));
        interfaceLabel(upper, transit.id + ":upper-interface", spineX + 12, railY - 54, false);
        y = Math.max(railY + 52, branch.hosts.length ? railY + descent(branch) : 0);
        if (sideGroups.length) y += 26;
        branch.sensorStart = Math.max(previous.y + DEVICE_HEIGHT + 16, upper.name === null ? railY - 43 : railY - 33);
        branch.sensorEnd = y - (lower.name === null ? 12 : 24);
        attachmentWire(lower, [transit.id], transit.id + ":down", path("M", spineX, railY, "V", y + 13));
        interfaceLabel(lower, transit.id + ":lower-interface", spineX + 12, y - 8, false);
      }

      const deviceY = y;
      const node = addNode({ ...station.equipment, key: station.equipment.id, x: spineX - DEVICE_WIDTH / 2,
        y: deviceY, width: DEVICE_WIDTH, height: DEVICE_HEIGHT });
      y = deviceY + DEVICE_HEIGHT;
      sideGroups.forEach((group, slot) => {
        const link = group.attachment!;
        const left = sideGroups.length === 2 ? slot === 0 : index % 2 === 0;
        const branch = branchBox(group.subnets[0], left ? spineX - SPINE_GAP / 2 - branchWidth : spineX + SPINE_GAP / 2,
          deviceY + 32, false, left ? "left" : "right");
        attachmentWire(link, [branch.node.id], branch.node.id + ":side",
          path("M", spineX + (left ? -22 : 22), branch.railY, "H", left ? branch.railEnd : branch.railX));
        interfaceLabel(link, branch.node.id + ":interface", spineX + (left ? -58 : 28), branch.railY - 10, false);
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
  return { nodes, nodesById, entities, wires, labels, branches, sensors, associations, width, height: Math.max(y + MARGIN, 180) };
}
