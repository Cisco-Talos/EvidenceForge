import type { TopologyGraph } from "./api";

/*
 * The network diagram is computed in two deterministic stages. `buildDiagramModel` turns the
 * projected topology into equipment, zones, links and Internet boundaries without inventing
 * relationships the scenario does not state. `layoutNetworkDiagram` places that model, choosing
 * the zone grid width and the level of detail that best fit the viewport.
 */

/** Optional detail. Firewalls and other forwarding devices are always drawn: they shape the network. */
export interface DiagramLayers { sensors: boolean; hosts: boolean }
export type DiagramSegment = TopologyGraph["segments"][number];
export type DiagramDevice = TopologyGraph["devices"][number];
export type DiagramHost = TopologyGraph["hosts"][number];
export type Routing = NonNullable<TopologyGraph["routing"]>;
export type RoutedDevice = Routing["devices"][string];
export type DiagramLink = Routing["links"][string];
export type DiagramLinkKind = NonNullable<DiagramLink["kind"]>;
export type EquipmentKind = "firewall" | "router" | "switch" | "network";
export type AttachmentStyle = "interface" | "inferred" | "observes" | "membership";
export type Detail = "overview" | "hosts";
export type HostCategory = "domain_controller" | "database" | "web_server" | "mail_server" | "file_server"
  | "app_server" | "log_server" | "server" | "workstation" | "other";

export const UNASSIGNED_HOSTS = "unassigned";
export const MIN_READABLE_SCALE = 0.55;
/** Open at host detail only when every host card remains comfortably readable. */
export const HOST_DETAIL_SCALE = 0.8;
/** Larger subnets show this many host cards and list the rest in the details panel. */
export const ZONE_HOST_LIMIT = 48;
/** Above this many sites, sites other than the Internet-facing one start collapsed. */
export const EXPANDED_SITE_LIMIT = 4;

export type SensorPlacement = { device: DiagramDevice; via: "segment" | "tap"; scope?: "all" | "internet" };

export type Equipment = {
  id: string; name: string; kind: EquipmentKind; subtitle: string;
  device?: DiagramDevice; routed?: { name: string; device: RoutedDevice }; host?: DiagramHost;
};

export type Attachment = {
  key: string; equipmentId: string; targetId: string; interfaceName: string | null; ip?: string;
  style: AttachmentStyle; linkKind: DiagramLinkKind; linkName?: string;
};

export type Zone = {
  id: string; name: string; cidr: string; segment?: DiagramSegment; unassigned: boolean;
  hosts: DiagramHost[]; children: Zone[]; parentId?: string;
  sensors: SensorPlacement[]; attachments: Attachment[]; link?: { name: string; link: DiagramLink };
};

export type Transit = {
  id: string; name: string; link: DiagramLink; segment?: DiagramSegment; kind: DiagramLinkKind;
  ends: { equipmentId: string; interfaceName: string; ip: string }[]; sensors: SensorPlacement[];
};

export type Internet = {
  id: string; name: string; inferred: boolean; linkName?: string; link?: DiagramLink;
  attachments: Attachment[]; sensors: SensorPlacement[];
};

export type DiagramModel = {
  equipment: Map<string, Equipment>;
  zones: Map<string, Zone>;
  transits: Map<string, Transit>;
  internets: Map<string, Internet>;
  attachments: Attachment[];
  sensors: DiagramDevice[];
  routed: boolean;
  inferredLinks: boolean;
  /** Declared gateway device ID for each zone, from authored routing. */
  gateways: Map<string, string>;
};

export type DiagramEntity =
  | { kind: "zone"; id: string; zone: Zone }
  | { kind: "equipment"; id: string; equipment: Equipment }
  | { kind: "sensor"; id: string; device: DiagramDevice; host?: DiagramHost }
  | { kind: "host"; id: string; host: DiagramHost }
  | { kind: "internet"; id: string; internet: Internet }
  | { kind: "transit"; id: string; transit: Transit };

const ROLE_CATEGORIES: [string, HostCategory][] = [
  ["domain_controller", "domain_controller"], ["database", "database"], ["db_server", "database"],
  ["web_server", "web_server"], ["mail_server", "mail_server"], ["file_server", "file_server"],
  ["smb_server", "file_server"], ["app_server", "app_server"], ["log_server", "log_server"],
  ["workstation", "workstation"],
];
export const CATEGORY_ORDER: HostCategory[] = ["domain_controller", "database", "web_server", "mail_server",
  "file_server", "app_server", "log_server", "server", "workstation", "other"];

/** Roles describe function; the always-declared system type is the fallback. */
export function hostCategory(host: DiagramHost): HostCategory {
  const roles = new Set((host.roles ?? []).map((role) => role.toLowerCase().replace(/[ -]+/g, "_")));
  for (const [role, category] of ROLE_CATEGORIES) if (roles.has(role)) return category;
  if (host.type === "domain_controller") return "domain_controller";
  if (host.type === "server") return "server";
  if (host.type === "workstation") return "workstation";
  return "other";
}

function networkEquipmentKind(host: DiagramHost): EquipmentKind | null {
  const roles = new Set((host.roles ?? []).map((role) => role.toLowerCase().replace(/[ -]+/g, "_")));
  if (["router", "core_router", "edge_router", "network_router"].some((role) => roles.has(role))) return "router";
  if (["switch", "core_switch", "network_switch"].some((role) => roles.has(role))) return "switch";
  // These platforms identify network appliances, which can serve several network roles.
  if (/^(?:Cisco (?:IOS|NX-OS|ASA)|Arista EOS|Juniper Junos|MikroTik RouterOS)\b/i.test(host.os)) return "network";
  return null;
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

function ipOrder(value: string): string {
  const v4 = value.split("/")[0].split(".");
  if (v4.length === 4 && v4.every((part) => /^\d+$/.test(part))) return v4.map((part) => part.padStart(3, "0")).join(".");
  return "~" + value;
}

/** The part of an interface address that varies within its subnet, such as `.1`. */
export function interfaceSuffix(ip: string | undefined, cidr: string | undefined): string {
  if (!ip) return "";
  const parts = ip.split(".");
  if (parts.length === 4 && cidr) {
    const prefix = Number(cidr.split("/")[1]);
    if (prefix >= 24) return "." + parts[3];
    if (prefix >= 16) return "." + parts.slice(2).join(".");
  }
  return ip;
}

function evidenceLabel(device: DiagramDevice): string {
  return (device.evidence ?? []).map(({ label }) => label).join(" + ") || device.log_formats.join(", ");
}

export function buildDiagramModel(graph: TopologyGraph, layers: DiagramLayers): DiagramModel {
  const routing = graph.routing ?? undefined;
  const equipment = new Map<string, Equipment>();
  const claimed = new Set<string>();
  const hostsByName = groupBy(graph.hosts, ({ hostname }) => hostname.toLowerCase());
  const firewalls = graph.devices.filter(({ kind }) => kind === "firewall");
  const firewallNames = groupBy(firewalls, ({ hostname }) => hostname.toLowerCase());
  const uniqueHost = (name: string | null | undefined) => {
    const matches = name ? hostsByName.get(name.toLowerCase()) : undefined;
    return matches?.length === 1 ? matches[0] : undefined;
  };

  const routedFirewall = new Map<string, string>();
  for (const [name, device] of Object.entries(routing?.devices ?? {})) {
    const sensor = device.kind === "firewall" && device.firewall ? firewalls.find((entry) => entry.name === device.firewall) : undefined;
    const host = uniqueHost(device.system);
    if (host) claimed.add(host.id);
    if (sensor) routedFirewall.set(sensor.id, name);
    const id = sensor?.id ?? "router:" + name;
    const kindLabel = { firewall: "Firewall", router: "Router", switch: "Switch" }[device.kind ?? "router"];
    equipment.set(id, {
      id, name: sensor?.hostname ?? device.system ?? name, kind: device.kind ?? "router", device: sensor, routed: { name, device }, host,
      subtitle: [kindLabel, sensor ? evidenceLabel(sensor) : host?.os].filter(Boolean).join(" · "),
    });
  }
  for (const device of firewalls) {
    if (routedFirewall.has(device.id)) continue;
    const host = firewallNames.get(device.hostname.toLowerCase())?.length === 1 ? uniqueHost(device.hostname) : undefined;
    if (host) claimed.add(host.id);
    equipment.set(device.id, { id: device.id, name: device.hostname, kind: "firewall", device, host,
      subtitle: ["Firewall", evidenceLabel(device)].join(" · ") });
  }
  if (!routing) {
    for (const host of graph.hosts) {
      const kind = networkEquipmentKind(host);
      if (!kind || claimed.has(host.id) || !host.segment_ids.length) continue;
      claimed.add(host.id);
      equipment.set(host.id, { id: host.id, name: host.hostname, kind, host,
        subtitle: [kind === "network" ? "Network appliance" : kind === "router" ? "Router" : "Switch", host.os].join(" · ") });
    }
  }

  // Zones: every segment that holds endpoints or is not a pure device-to-device transit link.
  const endpoints = layers.hosts ? graph.hosts.filter((host) => !claimed.has(host.id)) : [];
  const primary = (host: DiagramHost) => host.primary_segment_id ?? host.segment_ids[0];
  const hostsByZone = groupBy(endpoints, (host) => primary(host) ?? UNASSIGNED_HOSTS);
  const segmentsByName = new Map(graph.segments.map((segment) => [segment.name, segment]));
  const linkForSegment = new Map<string, { name: string; link: DiagramLink }>();
  for (const [name, link] of Object.entries(routing?.links ?? {})) {
    const segment = link.segment ? segmentsByName.get(link.segment) : undefined;
    if (segment && !link.internet) linkForSegment.set(segment.id, { name, link });
  }
  const transitSegments = new Set<string>();
  for (const [id, { link }] of linkForSegment) {
    if (Object.keys(link.interfaces).length >= 2 && !(hostsByZone.get(id)?.length)) transitSegments.add(id);
  }
  const zones = new Map<string, Zone>();
  for (const segment of [...graph.segments].sort((a, b) => ipOrder(a.cidr).localeCompare(ipOrder(b.cidr)) || a.name.localeCompare(b.name, "en"))) {
    if (transitSegments.has(segment.id)) continue;
    zones.set(segment.id, {
      id: segment.id, name: segment.name, cidr: segment.cidr, segment, unassigned: false,
      hosts: [...(hostsByZone.get(segment.id) ?? [])].sort((a, b) => ipOrder(a.ip).localeCompare(ipOrder(b.ip))),
      children: [], sensors: [], attachments: [], link: linkForSegment.get(segment.id),
    });
  }
  for (const zone of zones.values()) {
    const parent = zone.segment?.parent_id ? zones.get(zone.segment.parent_id) : undefined;
    if (parent) { zone.parentId = parent.id; parent.children.push(zone); }
  }
  const unassigned = hostsByZone.get(UNASSIGNED_HOSTS) ?? [];
  if (unassigned.length) {
    zones.set(UNASSIGNED_HOSTS, { id: UNASSIGNED_HOSTS, name: "Unassigned hosts", cidr: "", unassigned: true,
      hosts: unassigned, children: [], sensors: [], attachments: [] });
  }
  const rootZone = (id: string) => {
    let zone = zones.get(id);
    while (zone?.parentId) zone = zones.get(zone.parentId);
    return zone;
  };

  const attachments: Attachment[] = [];
  const transits = new Map<string, Transit>();
  const internets = new Map<string, Internet>();
  const equipmentForRouted = (name: string) => {
    const device = routing?.devices[name];
    const sensor = device?.firewall ? firewalls.find((entry) => entry.name === device.firewall) : undefined;
    const id = sensor?.id ?? "router:" + name;
    return equipment.has(id) ? id : undefined;
  };
  const attach = (attachment: Omit<Attachment, "key">): Attachment => {
    const key = JSON.stringify([attachment.equipmentId, attachment.targetId, attachment.interfaceName]);
    const existing = attachments.find((entry) => entry.key === key);
    if (existing) return existing;
    const created = { ...attachment, key };
    attachments.push(created);
    return created;
  };

  if (routing) {
    const boundaries = Object.entries(routing.links).filter(([, link]) => link.internet);
    for (const [name, link] of Object.entries(routing.links)) {
      const kind = link.kind ?? "network";
      const ends = Object.entries(link.interfaces).flatMap(([device, iface]) => {
        const equipmentId = equipmentForRouted(device);
        return equipmentId ? [{ equipmentId, interfaceName: iface.name, ip: iface.ip }] : [];
      });
      const segment = link.segment ? segmentsByName.get(link.segment) : undefined;
      if (link.internet) {
        const family = Object.values(link.interfaces)[0]?.ip.includes(":") ? "IPv6" : "IPv4";
        const id = "internet:" + name;
        const internet: Internet = { id, name: boundaries.length > 1 ? `Internet (${family})` : "Internet", inferred: false,
          linkName: name, link, attachments: [], sensors: [] };
        internets.set(id, internet);
        for (const end of ends) {
          internet.attachments.push(attach({ equipmentId: end.equipmentId, targetId: id, interfaceName: end.interfaceName, ip: end.ip,
            style: "interface", linkKind: kind, linkName: name }));
        }
      } else if (segment && zones.has(segment.id)) {
        for (const end of ends) {
          attach({ equipmentId: end.equipmentId, targetId: rootZone(segment.id)!.id, interfaceName: end.interfaceName,
            ip: end.ip, style: "interface", linkKind: kind, linkName: name });
        }
      } else if (ends.length >= 2) {
        transits.set("link:" + name, { id: "link:" + name, name, link, segment, kind, ends, sensors: [] });
      }
    }
  } else {
    for (const item of equipment.values()) {
      if (item.device) {
        for (const association of item.device.associations) {
          const target = rootZone(association.segment_id);
          if (!target) continue;
          if (association.interface_name !== null) {
            attach({ equipmentId: item.id, targetId: target.id, interfaceName: association.interface_name, style: "inferred", linkKind: "network" });
          } else if (association.monitored) {
            attach({ equipmentId: item.id, targetId: target.id, interfaceName: null, style: "observes", linkKind: "network" });
          }
        }
      }
      for (const id of item.host?.segment_ids ?? []) {
        const target = rootZone(id);
        if (target && !attachments.some((entry) => entry.equipmentId === item.id && entry.targetId === target.id)) {
          attach({ equipmentId: item.id, targetId: target.id, interfaceName: null, style: "membership", linkKind: "network" });
        }
      }
    }
    // Public addresses imply an Internet boundary. Attach it only where a firewall is modeled.
    const legacyFirewalls = [...equipment.values()].filter(({ kind, device }) => kind === "firewall" && device);
    const publicHosts = graph.hosts.some(({ public_address }) => public_address);
    if (legacyFirewalls.length && (publicHosts || (graph.public_cidrs ?? []).length)) {
      const natting = legacyFirewalls.filter(({ device }) => device!.nat_rules?.length);
      const internet: Internet = { id: "internet:inferred", name: "Internet", inferred: true, attachments: [], sensors: [] };
      internets.set(internet.id, internet);
      for (const item of natting.length ? natting : legacyFirewalls) {
        internet.attachments.push(attach({ equipmentId: item.id, targetId: internet.id, interfaceName: item.device!.default_interface ?? null,
          style: "inferred", linkKind: "network" }));
      }
    }
  }
  for (const attachment of attachments) zones.get(attachment.targetId)?.attachments.push(attachment);

  const sensors = layers.sensors ? graph.devices.filter(({ kind }) => kind !== "firewall") : [];
  for (const device of sensors) {
    for (const association of device.associations) {
      const zone = zones.get(association.segment_id);
      if (zone && association.monitored) zone.sensors.push({ device, via: "segment" });
    }
    const tap = graph.link_taps?.[device.id];
    if (!tap) continue;
    const link = routing?.links[tap.link];
    const segment = link?.segment ? segmentsByName.get(link.segment) : undefined;
    const placement: SensorPlacement = { device, via: "tap", scope: tap.scope };
    if (link?.internet) internets.get("internet:" + tap.link)?.sensors.push(placement);
    else if (segment && zones.has(segment.id)) zones.get(segment.id)!.sensors.push(placement);
    else transits.get("link:" + tap.link)?.sensors.push(placement);
  }
  const gateways = new Map<string, string>();
  for (const [segmentName, device] of Object.entries(routing?.gateways ?? {})) {
    const segment = segmentsByName.get(segmentName);
    const equipmentId = equipmentForRouted(device);
    if (segment && equipmentId) gateways.set(segment.id, equipmentId);
  }
  return { equipment, zones, transits, internets, attachments, sensors, routed: !!routing, gateways,
    inferredLinks: attachments.some(({ style }) => style === "inferred" || style === "observes") };
}

// ---------------------------------------------------------------- layout ----

export type PlacedChip = { key: string; device: DiagramDevice; via: SensorPlacement["via"]; scope?: string; x: number; y: number; width: number; label: string };
export type PlacedHost = { host: DiagramHost; category: HostCategory; x: number; y: number; width: number; height: number };
export type PlacedZone = {
  zone: Zone; x: number; y: number; width: number; height: number; detail: Detail;
  chips: PlacedChip[]; overflow: DiagramDevice[]; chipY: number;
  names: PlacedHost[]; summary: { category: HostCategory; count: number }[]; osSummary: string;
  publicHosts: DiagramHost[]; morePublic: number;
  hostCards: PlacedHost[]; groupLabels: { text: string; x: number; y: number }[]; hiddenHosts: number;
  toggleY: number; children: PlacedZone[];
};
export type PlacedEquipment = { equipment: Equipment; x: number; y: number; labelSide: "left" | "above" };
export type PlacedInternet = { internet: Internet; x: number; y: number };
export type PlacedSite = { id: string; label: string; x: number; y: number; width: number; height: number; collapsed: boolean;
  summary?: { zones: number; hosts: number; devices: string[] } };
export type Wire = { key: string; path: string; style: AttachmentStyle | "host"; linkKind: DiagramLinkKind; entities: string[] };
export type DiagramLabel = { key: string; x: number; y: number; text: string; anchor: "start" | "middle" | "end"; kind: "interface" | "link" | "link-detail" | "group" };
export type PlacedTap = { key: string; x: number; y: number; chip: PlacedChip; entities: string[] };
export type Bounds = { x: number; y: number; width: number; height: number };

export type DiagramScene = {
  model: DiagramModel; width: number; height: number; detail: Detail;
  zones: PlacedZone[]; equipment: PlacedEquipment[]; internets: PlacedInternet[]; sites: PlacedSite[];
  wires: Wire[]; labels: DiagramLabel[]; taps: PlacedTap[];
  entities: Map<string, DiagramEntity>; bounds: Map<string, Bounds>;
  /** Every zone, link and Internet boundary each sensor observes. */
  coverage: Map<string, string[]>;
  /** The collapsed site holding each subnet, host or device that is not drawn. */
  collapsedSite: Map<string, string>;
};

const MARGIN = 36;
const GLYPH = 48;
const ZONE_WIDTH = 252;
const ZONE_GAP = 16;
const ROW_GAP = 34;
const BLOCK_GAP = 44;
const SITE_GAP = 72;
const SITE_PAD = 20;
const SITE_LABEL = 22;
const CLOUD_HEIGHT = 46;
/** Clear space between the Internet band and the sites below it. */
const UPLINK_BAND = 56;
const CLOUD_SPACING = 220;
const HOST_CARD_WIDTH = 188;
const HOST_CARD_HEIGHT = 48;
const HOST_GAP = 8;
const COLLAPSED_SITE = { width: 240, height: 104 };
const SIDE_STEP = 240;
/** Clear space between the row gutter and the subnet cards, so a lit gutter never reads as a card outline. */
export const GUTTER_GAP = 26;

/** Approximate text widths, so placement does not depend on font loading or a DOM. */
export function textWidth(text: string, size = 11, mono = false): number {
  return [...text].length * size * (mono ? 0.61 : 0.56);
}

const CATEGORY_LABELS: Record<HostCategory, [string, string]> = {
  domain_controller: ["domain controller", "domain controllers"], database: ["database", "databases"],
  web_server: ["web server", "web servers"], mail_server: ["mail server", "mail servers"],
  file_server: ["file server", "file servers"], app_server: ["app server", "app servers"],
  log_server: ["log server", "log servers"], server: ["server", "servers"],
  workstation: ["workstation", "workstations"], other: ["other host", "other hosts"],
};
export function categoryLabel(category: HostCategory, count: number): string {
  return CATEGORY_LABELS[category][count === 1 ? 0 : 1];
}
const SHORT_OS: [RegExp, string][] = [[/^Windows Server.*/i, "Win Server"], [/^Windows (\d+).*/i, "Win $1"],
  [/^(?:Linux )?(Ubuntu|Debian|CentOS|RHEL|Rocky|Fedora|Alma\w*|Kali|SUSE).*/i, "$1"], [/^macOS.*/i, "macOS"]];
export function shortOs(os: string): string {
  for (const [pattern, replacement] of SHORT_OS) if (pattern.test(os)) return os.replace(pattern, replacement);
  return os.split(" ").slice(0, 2).join(" ");
}

type ZoneOptions = { detail: (zone: Zone) => Detail; sensors: boolean };

function chipLabel(placement: SensorPlacement, withName: boolean): string {
  const evidence = evidenceLabel(placement.device);
  return withName ? `${placement.device.hostname} · ${evidence}` : evidence;
}
export function chipWidth(label: string): number { return 24 + textWidth(label, 10.5); }

/** Lay out one zone card relative to its own origin. */
function measureZone(zone: Zone, options: ZoneOptions): PlacedZone {
  const detail = zone.hosts.length ? options.detail(zone) : "overview";
  const pad = 12;
  const children = zone.children.map((child) => measureZone(child, options));
  let width = ZONE_WIDTH;
  let hostColumns = 0;
  if (detail === "hosts") {
    const shown = Math.min(zone.hosts.length, ZONE_HOST_LIMIT);
    hostColumns = Math.max(1, Math.min(4, Math.ceil(Math.sqrt(shown * 1.4))));
    width = Math.max(width, pad * 2 + hostColumns * HOST_CARD_WIDTH + (hostColumns - 1) * HOST_GAP);
  }
  const childColumns = Math.min(2, children.length);
  if (children.length) {
    const rows = groupBy(children.map((child, index) => ({ child, index })), ({ index }) => Math.floor(index / childColumns));
    const rowWidth = Math.max(...[...rows.values()].map((row) => row.reduce((sum, { child }) => sum + child.width, 0) + (row.length - 1) * ZONE_GAP));
    width = Math.max(width, pad * 2 + rowWidth);
  }

  // Sensor chips show names when they all fit; otherwise the evidence label alone.
  const chips: PlacedChip[] = [];
  const overflow: DiagramDevice[] = [];
  const chipY = 42;
  if (options.sensors && zone.sensors.length) {
    const room = width - pad * 2;
    const named = zone.sensors.map((placement) => chipLabel(placement, true));
    const useNames = named.reduce((sum, label) => sum + chipWidth(label) + 6, 0) <= room;
    let x = pad;
    zone.sensors.forEach((placement, index) => {
      const label = useNames ? named[index] : chipLabel(placement, false);
      const chip = chipWidth(label);
      const remaining = zone.sensors.length - index - 1;
      if (x + chip > pad + room - (remaining ? 40 : 0) && chips.length) { overflow.push(placement.device); return; }
      chips.push({ key: zone.id + placement.device.id, device: placement.device, via: placement.via, scope: placement.scope, x, y: chipY, width: chip, label });
      x += chip + 6;
    });
  }
  let y = chips.length ? chipY + 28 : 46;

  const names: PlacedHost[] = [];
  const hostCards: PlacedHost[] = [];
  const groupLabels: { text: string; x: number; y: number }[] = [];
  let summary: { category: HostCategory; count: number }[] = [];
  let osSummary = "";
  let publicHosts: DiagramHost[] = [];
  let morePublic = 0;
  let hiddenHosts = 0;
  if (detail === "hosts") {
    const shown = zone.hosts.slice(0, ZONE_HOST_LIMIT);
    hiddenHosts = zone.hosts.length - shown.length;
    const groups = groupBy(shown, hostCategory);
    for (const category of CATEGORY_ORDER) {
      const members = groups.get(category);
      if (!members) continue;
      if (groups.size > 1) {
        groupLabels.push({ text: `${categoryLabel(category, members.length).toUpperCase()}  ${members.length}`, x: pad, y: y + 9 });
        y += 16;
      }
      members.forEach((host, index) => {
        const column = index % hostColumns;
        const row = Math.floor(index / hostColumns);
        hostCards.push({ host, category, x: pad + column * (HOST_CARD_WIDTH + HOST_GAP), y: y + row * (HOST_CARD_HEIGHT + HOST_GAP),
          width: HOST_CARD_WIDTH, height: HOST_CARD_HEIGHT });
      });
      y += Math.ceil(members.length / hostColumns) * (HOST_CARD_HEIGHT + HOST_GAP) + 6;
    }
    if (hiddenHosts) y += 16;
  } else if (zone.hosts.length && zone.hosts.length <= 4) {
    const twoColumns = (width - pad * 2 - 6) / 2;
    const fits = zone.hosts.every(({ hostname }) => 30 + textWidth(hostname, 10.5) <= twoColumns);
    const perRow = fits ? 2 : 1;
    const column = fits ? twoColumns : width - pad * 2;
    zone.hosts.forEach((host, index) => {
      names.push({ host, category: hostCategory(host), x: pad + (index % perRow) * (column + 6), y: y + Math.floor(index / perRow) * 24, width: column, height: 20 });
    });
    y += Math.ceil(zone.hosts.length / perRow) * 24;
  } else if (zone.hosts.length) {
    const counts = groupBy(zone.hosts, hostCategory);
    summary = CATEGORY_ORDER.flatMap((category) => counts.get(category) ? [{ category, count: counts.get(category)!.length }] : []);
    const systems = [...groupBy(zone.hosts, (host) => shortOs(host.os))].sort((a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0], "en"));
    osSummary = systems.map(([name, members]) => `${members.length} ${name}`).join(" · ");
    y += 40;
    // Hosts with a public address are named, so they never hide inside a count.
    const reachable = zone.hosts.filter(({ public_address }) => public_address);
    publicHosts = reachable.slice(0, 3);
    morePublic = reachable.length - publicHosts.length;
    y += publicHosts.length * 24 + (morePublic ? 16 : 0);
  } else if (!children.length) {
    y += 20;
  }
  const toggleY = y + 4;
  if (zone.hosts.length > 4 || detail === "hosts") y += 22;
  let childY = y + (children.length ? 4 : 0);
  if (children.length) {
    for (let index = 0; index < children.length; index += childColumns) {
      const row = children.slice(index, index + childColumns);
      let x = pad;
      for (const child of row) { child.x = x; child.y = childY; x += child.width + ZONE_GAP; }
      childY += Math.max(...row.map(({ height }) => height)) + ZONE_GAP;
    }
    y = childY - ZONE_GAP + pad;
  } else {
    y += pad - 4;
  }
  return { zone, x: 0, y: 0, width, height: Math.max(y, 64), detail, chips, overflow, chipY, names, summary, osSummary,
    publicHosts, morePublic, hostCards, groupLabels, hiddenHosts, toggleY, children };
}

function offsetZone(zone: PlacedZone, dx: number, dy: number): PlacedZone {
  return { ...zone, x: zone.x + dx, y: zone.y + dy, children: zone.children.map((child) => offsetZone(child, zone.x + dx, zone.y + dy)) };
}

type Tree = { equipment: Equipment; zones: Zone[]; children: Tree[]; via?: Transit | { zone: Zone }; depth: number };
type Component = { id: string; trees: Tree[]; unattached: Zone[]; internetFacing: boolean; crossLinks: number; zoneCount: number; hostCount: number; label: string };

function components(model: DiagramModel): Component[] {
  const parent = new Map<string, string>([...model.equipment.keys()].map((id) => [id, id]));
  const find = (id: string): string => {
    let root = id;
    while (parent.get(root) !== root) root = parent.get(root)!;
    parent.set(id, root);
    return root;
  };
  const join = (a: string, b: string) => { const ra = find(a); const rb = find(b); if (ra !== rb) parent.set(rb < ra ? ra : rb, rb < ra ? rb : ra); };
  for (const transit of model.transits.values()) {
    if (transit.kind !== "network") continue;
    for (const end of transit.ends.slice(1)) join(transit.ends[0].equipmentId, end.equipmentId);
  }
  for (const zone of model.zones.values()) {
    const attached = [...new Set(zone.attachments.map(({ equipmentId }) => equipmentId))];
    for (const id of attached.slice(1)) join(attached[0], id);
  }
  const groups = groupBy([...model.equipment.keys()].sort(), find);
  const internetFacing = new Set(model.attachments.filter(({ targetId }) => model.internets.has(targetId)).map(({ equipmentId }) => equipmentId));
  const attachedZones = new Set(model.attachments.map(({ targetId }) => targetId));
  const result: Component[] = [];
  for (const [id, members] of groups) {
    const trees = buildTrees(model, new Set(members), internetFacing);
    const zones = trees.flatMap(function collect(tree): Zone[] { return [...tree.zones, ...tree.children.flatMap(collect)]; });
    const crossLinks = [...model.transits.values()].filter(({ kind, ends }) => kind !== "network" && ends.some(({ equipmentId }) => members.includes(equipmentId))).length;
    result.push({ id, trees, unattached: [], crossLinks, internetFacing: members.some((member) => internetFacing.has(member)),
      zoneCount: zones.length, hostCount: zones.reduce((sum, zone) => sum + countHosts(zone), 0), label: siteLabel(zones, trees) });
  }
  // The Internet-facing site leads, then the hub with the most links to other sites.
  result.sort((a, b) => Number(b.internetFacing) - Number(a.internetFacing) || b.crossLinks - a.crossLinks
    || b.zoneCount - a.zoneCount || a.id.localeCompare(b.id, "en"));
  const loose = [...model.zones.values()].filter((zone) => !zone.parentId && !attachedZones.has(zone.id));
  if (loose.length) {
    result.push({ id: "unattached", trees: [], unattached: loose, internetFacing: false, crossLinks: 0, zoneCount: loose.length,
      hostCount: loose.reduce((sum, zone) => sum + countHosts(zone), 0), label: "" });
  }
  return result;
}

function countHosts(zone: Zone): number {
  return zone.hosts.length + zone.children.reduce((sum, child) => sum + countHosts(child), 0);
}

function siteLabel(zones: Zone[], trees: Tree[]): string {
  const prefixes = groupBy(zones.map(({ name }) => name.split(/[-_]/)[0]).filter((prefix) => prefix.length > 1), (prefix) => prefix.toLowerCase());
  const [best] = [...prefixes].sort((a, b) => b[1].length - a[1].length);
  if (best && best[1].length >= 2 && best[1].length * 2 >= zones.length) return best[1][0].toUpperCase();
  return trees[0]?.equipment.name ?? "";
}

/**
 * Root each component at an Internet-facing device, else at the device that carries its WAN or VPN
 * link to another site, else at its most connected device, and walk outward.
 */
function buildTrees(model: DiagramModel, members: Set<string>, internetFacing: Set<string>): Tree[] {
  const interSite = new Set([...model.transits.values()].filter(({ kind }) => kind !== "network")
    .flatMap(({ ends }) => ends.map(({ equipmentId }) => equipmentId)));
  const degree = (id: string) => model.attachments.filter(({ equipmentId }) => equipmentId === id).length
    + [...model.transits.values()].filter(({ ends }) => ends.some(({ equipmentId }) => equipmentId === id)).length;
  const neighbors = new Map<string, { id: string; via: Tree["via"] }[]>();
  const link = (a: string, b: string, via: Tree["via"]) => {
    if (!members.has(a) || !members.has(b) || a === b) return;
    neighbors.set(a, [...(neighbors.get(a) ?? []), { id: b, via }]);
    neighbors.set(b, [...(neighbors.get(b) ?? []), { id: a, via }]);
  };
  for (const transit of model.transits.values()) {
    if (transit.kind !== "network") continue;
    for (const end of transit.ends.slice(1)) link(transit.ends[0].equipmentId, end.equipmentId, transit);
  }
  for (const zone of model.zones.values()) {
    const attached = [...new Set(zone.attachments.map(({ equipmentId }) => equipmentId))].sort();
    for (const id of attached.slice(1)) link(attached[0], id, { zone });
  }
  const ordered = [...members].sort((a, b) => Number(internetFacing.has(b)) - Number(internetFacing.has(a))
    || Number(interSite.has(b)) - Number(interSite.has(a))
    || Number(model.equipment.get(b)!.kind === "firewall") - Number(model.equipment.get(a)!.kind === "firewall") || degree(b) - degree(a) || model.equipment.get(a)!.name.localeCompare(model.equipment.get(b)!.name, "en"));
  const depth = new Map<string, number>();
  const trees: Tree[] = [];
  const nodes = new Map<string, Tree>();
  for (const root of ordered) {
    if (depth.has(root)) continue;
    const rootTree: Tree = { equipment: model.equipment.get(root)!, zones: [], children: [], depth: 0 };
    trees.push(rootTree);
    nodes.set(root, rootTree);
    depth.set(root, 0);
    const queue = [root];
    while (queue.length) {
      const current = queue.shift()!;
      const options = (neighbors.get(current) ?? []).sort((a, b) => model.equipment.get(a.id)!.name.localeCompare(model.equipment.get(b.id)!.name, "en"));
      for (const { id, via } of options) {
        if (depth.has(id)) continue;
        depth.set(id, depth.get(current)! + 1);
        const tree: Tree = { equipment: model.equipment.get(id)!, zones: [], children: [], via, depth: depth.get(id)! };
        nodes.get(current)!.children.push(tree);
        nodes.set(id, tree);
        queue.push(id);
      }
    }
  }
  // A zone belongs to its declared gateway, else to the attached device nearest the root.
  for (const zone of model.zones.values()) {
    if (zone.parentId) continue;
    const attached = [...new Set(zone.attachments.map(({ equipmentId }) => equipmentId))].filter((id) => members.has(id));
    if (!attached.length) continue;
    const declared = model.gateways.get(zone.id);
    const gateway = declared && attached.includes(declared) ? declared : undefined;
    const owner = gateway ?? [...attached].sort((a, b) => depth.get(a)! - depth.get(b)! || a.localeCompare(b, "en"))[0];
    nodes.get(owner)?.zones.push(zone);
  }
  return trees;
}

type Block = { width: number; height: number; place: (x: number, y: number) => void };

type LayoutState = {
  model: DiagramModel; options: ZoneOptions; columns: number;
  zones: PlacedZone[]; equipment: PlacedEquipment[]; internets: PlacedInternet[]; wires: Wire[]; labels: DiagramLabel[]; taps: PlacedTap[];
  glyphs: Map<string, { x: number; y: number }>;
  /** Devices with a WAN or VPN link to another site. */
  interSite: Set<string>;
};

function wireEntities(attachment: Attachment, zone?: Zone): string[] {
  const ids = [attachment.equipmentId, attachment.targetId];
  if (zone) ids.push(...zone.children.map(({ id }) => id));
  if (attachment.linkName) ids.push("link:" + attachment.linkName);
  return ids;
}

function interfaceText(attachment: Attachment, zone?: Zone): string {
  if (attachment.interfaceName === null) return "";
  const suffix = interfaceSuffix(attachment.ip, zone?.cidr);
  // An interface named after its subnet only needs its address, when one is declared.
  const name = zone && suffix && attachment.interfaceName === zone.name ? "" : attachment.interfaceName;
  return [name, suffix].filter(Boolean).join(" ");
}

function treeBlock(state: LayoutState, tree: Tree, internets: Internet[]): Block {
  const { equipment } = tree;
  const zones = tree.zones.map((zone) => measureZone(zone, state.options));
  const columns = Math.max(1, Math.min(state.columns, zones.length));
  const rows: PlacedZone[][] = [];
  for (let index = 0; index < zones.length; index += columns) rows.push(zones.slice(index, index + columns));
  const gridWidth = rows.length ? Math.max(...rows.map((row) => row.reduce((sum, zone) => sum + zone.width, 0) + (row.length - 1) * ZONE_GAP)) : 0;
  const gridHeight = rows.reduce((sum, row) => sum + Math.max(...row.map(({ height }) => height)) + ROW_GAP, 0);
  const label = Math.max(textWidth(equipment.name, 13) + 4, textWidth(equipment.subtitle, 11));
  const glyphArea = label + 12 + GLYPH;
  // A leaf device with no subnets, such as a VPN concentrator, sits beside its parent on one straight link.
  const side = tree.children.find((child) => !child.zones.length && !child.children.length);
  const belowTrees = tree.children.filter((child) => child !== side);
  const children = belowTrees.map((child) => treeBlock(state, child, []));
  // A grid with several rows needs room on its left for the gutter that feeds the later rows.
  const inset = rows.length > 1 ? GUTTER_GAP : 0;
  const gridSpan = inset + gridWidth;
  const centerOffset = Math.max(glyphArea - GLYPH / 2, inset + gridWidth / 2);
  const sideLabel = side ? Math.max(textWidth(side.equipment.name, 13), textWidth(side.equipment.subtitle, 11)) / 2 : 0;
  // A side link is long enough for its name, both end labels and its sensor chips, with padding.
  const sideLink = side?.via && "ends" in side.via ? side.via : undefined;
  const sideEnds = sideLink ? sideLink.ends.filter(({ equipmentId }) => equipmentId === equipment.id || equipmentId === side!.equipment.id) : [];
  const sideStep = Math.max(SIDE_STEP, GLYPH + (sideLink ? Math.max(
    textWidth(sideLink.name, 11) + 2 * LABEL_PAD,
    sideEnds.reduce((sum, end) => sum + textWidth(endLabel(end, sideLink.segment?.cidr), 10.5, true), 0) + 3 * LABEL_PAD,
    linkLabelWidth({ ...sideLink, name: "", segment: undefined }, true) + 2 * LABEL_PAD) : 0));
  const sideExtent = side ? centerOffset + sideStep + Math.max(GLYPH / 2, sideLabel) + 8 : 0;
  // A site root that receives a cross-site link keeps its left side clear for that link.
  const labelAbove = tree.depth === 0 && !internets.length && state.interSite.has(equipment.id);
  const sideTop = (side || labelAbove) && !internets.length ? 36 : 0;
  const sideTransit = side?.via && "ends" in side.via ? side.via : undefined;
  const sideChips = sideTransit?.sensors.length ? 28 : 0;
  const childrenWidth = children.reduce((sum, child) => sum + child.width, 0) + Math.max(0, children.length - 1) * BLOCK_GAP;
  const childrenHeight = children.length ? Math.max(...children.map(({ height }) => height)) : 0;
  // Internet boundaries are outside every site; they are placed in a band above all of them.
  const ownTop = sideTop;
  // Links to child devices run down a gutter on the right, labeled beside it.
  const gutterLabels = Math.max(0, ...belowTrees.map(({ via }) => via && "ends" in via
    ? Math.max(textWidth(via.name, 11), via.segment ? textWidth(via.segment.cidr, 10.5, true) : 0,
      ...via.sensors.map((placement) => 14 + chipWidth(chipLabel(placement, true)))) : 0));
  const upperWidth = Math.max(glyphArea, gridSpan, sideExtent) + (children.length ? 30 + gutterLabels + 8 : 0);
  const width = Math.max(upperWidth, childrenWidth);
  const height = ownTop + GLYPH + sideChips + (rows.length ? 30 + gridHeight : 12) + (children.length ? 36 + childrenHeight : 0);
  return {
    width, height,
    place(x, y) {
      const gridLeft = x + inset;
      const center = rows.length ? gridLeft + gridWidth / 2 : x + glyphArea - GLYPH / 2;
      const gx = Math.max(x + glyphArea - GLYPH / 2, center);
      const gy = y + ownTop + GLYPH / 2;
      state.glyphs.set(equipment.id, { x: gx, y: gy });
      state.equipment.push({ equipment, x: gx, y: gy, labelSide: labelAbove ? "above" : "left" });
      if (side) {
        const sx = gx + sideStep;
        state.glyphs.set(side.equipment.id, { x: sx, y: gy });
        state.equipment.push({ equipment: side.equipment, x: sx, y: gy, labelSide: "above" });
        const via = side.via;
        const transit = via && "ends" in via ? via : undefined;
        state.wires.push({ key: equipment.id + ":" + side.equipment.id, style: transit ? "interface" : "membership", linkKind: transit?.kind ?? "network",
          entities: [equipment.id, side.equipment.id, ...(transit ? [transit.id, ...transit.sensors.map(({ device }) => device.id)] : [])],
          path: `M ${gx + GLYPH / 2} ${gy} H ${sx - GLYPH / 2}` });
        if (transit) {
          const cidr = transit.segment?.cidr;
          const near = transit.ends.find(({ equipmentId }) => equipmentId === equipment.id);
          const far = transit.ends.find(({ equipmentId }) => equipmentId === side.equipment.id);
          const mid = (gx + sx) / 2;
          if (near) state.labels.push({ key: transit.id + ":upper", x: gx + GLYPH / 2 + 6, y: gy - 6, kind: "interface", anchor: "start",
            text: [near.interfaceName, interfaceSuffix(near.ip, cidr)].filter(Boolean).join(" ") });
          if (far) state.labels.push({ key: transit.id + ":lower", x: sx - GLYPH / 2 - 6, y: gy - 6, kind: "interface", anchor: "end",
            text: [far.interfaceName, interfaceSuffix(far.ip, cidr)].filter(Boolean).join(" ") });
          state.labels.push({ key: transit.id + ":name", x: mid, y: gy - 20, text: transit.name, anchor: "middle", kind: "link" });
          // Sensor chips sit under the link, centered on their TAP marks.
          const room = sideStep - GLYPH - 12;
          placeTaps(state, transit.id, transit.sensors, mid, gy, room);
        }
      }
      // Access links: a bus above each row of zones, joined along the grid's left gutter.
      let rowTop = gy + GLYPH / 2 + 30 + sideChips;
      const busX = gridLeft - GUTTER_GAP;
      const trunkStyles = tree.zones.map((zone) => zone.attachments.find(({ equipmentId }) => equipmentId === equipment.id)?.style ?? "interface");
      if (rows.length) state.wires.push({ key: equipment.id + ":trunk", linkKind: "network", entities: [equipment.id, ...tree.zones.map(({ id }) => id)],
        style: trunkStyles.every((style) => style === trunkStyles[0]) ? trunkStyles[0] : "interface",
        path: `M ${gx} ${gy + GLYPH / 2} V ${rowTop - 14}` });
      rows.forEach((row, rowIndex) => {
        let zx = gridLeft;
        const busY = rowTop - 14;
        const centers: number[] = [];
        for (const zone of row) {
          const placed = offsetZone(zone, zx, rowTop);
          state.zones.push(placed);
          const cx = zx + Math.min(zone.width / 2, 124);
          centers.push(cx);
          const attachment = zone.zone.attachments.find(({ equipmentId }) => equipmentId === equipment.id);
          if (attachment) {
            state.wires.push({ key: attachment.key, style: attachment.style, linkKind: attachment.linkKind,
              entities: wireEntities(attachment, zone.zone), path: `M ${cx} ${busY} V ${rowTop}` });
            const text = interfaceText(attachment, zone.zone);
            if (text) state.labels.push({ key: attachment.key + ":label", x: cx + 6, y: rowTop - 4, text, anchor: "start", kind: "interface" });
          }
          zx += zone.width + ZONE_GAP;
        }
        // Each bus is split at its drops, so every piece lights up for exactly the subnets whose
        // access path runs through it. The first bus is fed by the device trunk; later buses by the
        // gutter, which also carries every row below it.
        const styles = row.map(({ zone }) => zone.attachments.find(({ equipmentId }) => equipmentId === equipment.id)?.style ?? "interface");
        const style = styles.every((entry) => entry === styles[0]) ? styles[0] : "interface";
        const feed = rowIndex === 0 ? gx : busX;
        const later = rows.slice(rowIndex + 1).flatMap((next) => next.map(({ zone }) => zone.id));
        const spans = row.map(({ zone }, index) => ({ from: Math.min(feed, centers[index]), to: Math.max(feed, centers[index]), ids: [zone.id] }));
        if (later.length && feed !== busX) spans.push({ from: Math.min(feed, busX), to: Math.max(feed, busX), ids: later });
        const stops = [...new Set(spans.flatMap(({ from, to }) => [from, to]))].sort((a, b) => a - b);
        stops.slice(1).forEach((to, index) => {
          const from = stops[index];
          const ids = spans.filter((span) => span.from <= from && span.to >= to).flatMap((span) => span.ids);
          if (!ids.length) return;
          state.wires.push({ key: `${equipment.id}:bus:${rowIndex}:${index}`, style, linkKind: "network", entities: [equipment.id, ...ids],
            path: `M ${from} ${busY} H ${to}` });
        });
        if (rowIndex > 0) {
          const downstream = rows.slice(rowIndex).flatMap((next) => next.map(({ zone }) => zone.id));
          state.wires.push({ key: equipment.id + ":gutter:" + rowIndex, style, linkKind: "network", entities: [equipment.id, ...downstream],
            path: `M ${busX} ${rowTop - 14 - ROW_GAP - Math.max(...rows[rowIndex - 1].map(({ height }) => height))} V ${busY}` });
        }
        rowTop += Math.max(...row.map(({ height }) => height)) + ROW_GAP;
      });
      // Child devices sit below the grid. Their links leave the device to the right, outside the grid.
      if (children.length) {
        const childTop = (rows.length ? rowTop - ROW_GAP + 36 : gy + GLYPH / 2 + 48);
        const gutter = x + Math.max(glyphArea, gridSpan, sideExtent) + 18;
        let cx = x;
        belowTrees.forEach((child, index) => {
          children[index].place(cx, childTop);
          const target = state.glyphs.get(child.equipment.id)!;
          const via = child.via;
          const transit = via && "ends" in via ? via : undefined;
          const entities = [equipment.id, child.equipment.id, ...(transit ? [transit.id, ...transit.sensors.map(({ device }) => device.id)] : via && "zone" in via ? [via.zone.id] : [])];
          const exitY = gy + 10 + index * 6;
          const path = `M ${gx + GLYPH / 2} ${exitY} H ${gutter + index * 8} V ${target.y - GLYPH / 2 - 18 - index * 4} H ${target.x} V ${target.y - GLYPH / 2}`;
          state.wires.push({ key: equipment.id + ":" + child.equipment.id, style: transit ? "interface" : "membership", linkKind: transit?.kind ?? "network", entities, path });
          if (transit) {
            const upper = transit.ends.find(({ equipmentId }) => equipmentId === equipment.id);
            const lower = transit.ends.find(({ equipmentId }) => equipmentId === child.equipment.id);
            const cidr = transit.segment?.cidr;
            if (upper) state.labels.push({ key: transit.id + ":upper", x: gx + GLYPH / 2 + 6, y: exitY - 5, kind: "interface", anchor: "start",
              text: [upper.interfaceName, interfaceSuffix(upper.ip, cidr)].filter(Boolean).join(" ") });
            if (lower) state.labels.push({ key: transit.id + ":lower", x: target.x + 8, y: target.y - GLYPH / 2 - 6, kind: "interface", anchor: "start",
              text: [lower.interfaceName, interfaceSuffix(lower.ip, cidr)].filter(Boolean).join(" ") });
            const midY = (exitY + target.y - GLYPH / 2 - 18) / 2;
            state.labels.push({ key: transit.id + ":name", x: gutter + index * 8 + 8, y: midY - 6, text: transit.name, anchor: "start", kind: "link" });
            if (cidr) state.labels.push({ key: transit.id + ":cidr", x: gutter + index * 8 + 8, y: midY + 7, text: cidr, anchor: "start", kind: "link-detail" });
            transit.sensors.forEach((placement, tapIndex) => {
              const ty = midY + 22 + tapIndex * 24;
              const tx = gutter + index * 8;
              const label = chipLabel(placement, true);
              state.taps.push({ key: transit.id + placement.device.id, x: tx, y: ty, entities: [transit.id, placement.device.id],
                chip: { key: transit.id + placement.device.id + ":chip", device: placement.device, via: "tap", scope: placement.scope,
                  x: tx + 14, y: ty - 9, width: chipWidth(label), label } });
            });
          }
          cx += children[index].width + BLOCK_GAP;
        });
      }
    },
  };
}

/** Clear space on each side of a link's labels, and the jog a link between sites takes near its end. */
const LABEL_PAD = 14;
const LINK_JOG = 18;

function transitTitle(transit: Transit): string {
  return transit.kind === "network" ? transit.name : `${transit.name} · ${transit.kind.toUpperCase()}`;
}

/** The widest label a link carries along its length: its name, address range, or sensor chips. */
function linkLabelWidth(transit: Transit, withChips: boolean): number {
  const chips = withChips && transit.sensors.length
    ? transit.sensors.reduce((sum, placement) => sum + chipWidth(chipLabel(placement, false)) + 6, -6) : 0;
  return Math.max(textWidth(transitTitle(transit), 11), transit.segment ? textWidth(transit.segment.cidr, 10.5, true) : 0, chips);
}

function endLabel(end: Transit["ends"][number], cidr: string | undefined): string {
  return [end.interfaceName, interfaceSuffix(end.ip, cidr)].filter(Boolean).join(" ");
}

/** TAP marks along a horizontal link with their chips below, named only when the names fit. */
function placeTaps(state: LayoutState, linkId: string, sensors: SensorPlacement[], center: number, y: number, room: number) {
  if (!sensors.length) return;
  const named = sensors.map((placement) => chipLabel(placement, true));
  const useNames = named.reduce((sum, label) => sum + chipWidth(label) + 6, -6) <= room;
  const labels = useNames ? named : sensors.map((placement) => chipLabel(placement, false));
  const widths = labels.map(chipWidth);
  let x = center - (widths.reduce((sum, width) => sum + width + 6, -6)) / 2;
  sensors.forEach((placement, index) => {
    const tapX = x + widths[index] / 2;
    state.taps.push({ key: linkId + placement.device.id, x: tapX, y, entities: [linkId, placement.device.id],
      chip: { key: linkId + placement.device.id + ":chip", device: placement.device, via: "tap", scope: placement.scope,
        x, y: y + 12, width: widths[index], label: labels[index] } });
    x += widths[index] + 6;
  });
}

function looseBlock(state: LayoutState, zones: Zone[]): Block {
  const measured = zones.map((zone) => measureZone(zone, state.options));
  const columns = Math.max(1, Math.min(state.columns, measured.length));
  const rows: PlacedZone[][] = [];
  for (let index = 0; index < measured.length; index += columns) rows.push(measured.slice(index, index + columns));
  const width = Math.max(...rows.map((row) => row.reduce((sum, zone) => sum + zone.width, 0) + (row.length - 1) * ZONE_GAP));
  const height = 24 + rows.reduce((sum, row) => sum + Math.max(...row.map(({ height }) => height)) + ZONE_GAP, 0);
  return {
    width, height,
    place(x, y) {
      if (state.equipment.length || state.zones.length) {
        state.labels.push({ key: "unattached:label", x, y: y + 10, text: "NOT ATTACHED TO A MODELED DEVICE", anchor: "start", kind: "group" });
      }
      let top = y + 24;
      for (const row of rows) {
        let left = x;
        for (const zone of row) { state.zones.push(offsetZone(zone, left, top)); left += zone.width + ZONE_GAP; }
        top += Math.max(...row.map(({ height }) => height)) + ZONE_GAP;
      }
    },
  };
}

export type LayoutOptions = {
  viewport: { width: number; height: number };
  /** Per-zone detail chosen by the user, overriding the automatic choice. */
  zoneDetail?: Readonly<Record<string, Detail>>;
  /** Sites the user expanded or collapsed, overriding the automatic choice. */
  siteChoices?: Readonly<Record<string, boolean>>;
};

function layoutWith(model: DiagramModel, layers: DiagramLayers, columns: number, detail: Detail, options: LayoutOptions,
  parts: Component[]): DiagramScene {
  const zoneDetail = (zone: Zone) => options.zoneDetail?.[zone.id] ?? detail;
  const state: LayoutState = { model, columns, options: { detail: zoneDetail, sensors: layers.sensors },
    zones: [], equipment: [], internets: [], wires: [], labels: [], taps: [], glyphs: new Map(),
    interSite: new Set([...model.transits.values()].filter(({ kind }) => kind !== "network").flatMap(({ ends }) => ends.map(({ equipmentId }) => equipmentId))) };
  const sites: PlacedSite[] = [];
  const collapsedSite = new Map<string, string>();
  /** Devices inside collapsed sites: only their cross-site links are drawn, ending at the card. */
  const hidden = new Set<string>();
  const showSites = model.routed && parts.filter(({ trees }) => trees.length).length > 1;
  const collapsedByDefault = parts.filter(({ trees }) => trees.length).length > EXPANDED_SITE_LIMIT;
  let x = MARGIN;
  let tallest = 0;
  const pending: { part: Component; block: Block; collapsed: boolean }[] = [];
  parts.forEach((part, index) => {
    const collapsed = showSites && part.trees.length > 0 && (options.siteChoices?.[part.id] ?? !(collapsedByDefault && index > 0)) === false;
    const block: Block = collapsed ? { width: collapsedWidth(part), height: COLLAPSED_SITE.height, place: () => undefined }
      : part.trees.length ? stackTrees(state, part.trees) : looseBlock(state, part.unattached);
    pending.push({ part, block, collapsed });
  });
  // Sites and components share one row; with many, they wrap to keep the diagram near the viewport aspect.
  const aspect = options.viewport.width / Math.max(1, options.viewport.height);
  const totalArea = pending.reduce((sum, { block }) => sum + (block.width + SITE_GAP) * (block.height + SITE_GAP), 0);
  // Internet-facing components share the top row, so their uplinks come straight down from the band.
  const facing = pending.filter(({ part }) => part.internetFacing);
  const facingWidth = facing.reduce((sum, { block }) => sum + block.width + 2 * SITE_PAD + SITE_GAP, -SITE_GAP);
  // Wrap only when one row would be wider than the canvas.
  const rowLimit = Math.max(...pending.map(({ block }) => block.width), Math.sqrt(totalArea * aspect), facingWidth,
    options.viewport.width - 2 * MARGIN);
  // Reserve a band above every site for Internet boundaries and the TAPs on their uplinks.
  const boundaryTaps = Math.max(0, ...[...model.internets.values()].map(({ sensors }) => sensors.length));
  const band = model.internets.size ? CLOUD_HEIGHT + UPLINK_BAND + boundaryTaps * 24 : 0;
  let y = MARGIN + band;
  let rowHeight = 0;
  const membersOf = new Map(parts.map((part) => [part.id, new Set(part.trees.flatMap(function ids(tree): string[] {
    return [tree.equipment.id, ...tree.children.flatMap(ids)]; }))]));
  // Neighbouring sites leave room for the labels of the links between them.
  const gapBetween = (a: Component, b: Component) => {
    const left = membersOf.get(a.id)!;
    const right = membersOf.get(b.id)!;
    const widths = [...model.transits.values()]
      .filter(({ ends }) => ends.some(({ equipmentId }) => left.has(equipmentId)) && ends.some(({ equipmentId }) => right.has(equipmentId)))
      .map((transit) => linkLabelWidth(transit, true) + 2 * LABEL_PAD + LINK_JOG);
    return Math.max(SITE_GAP, ...widths);
  };
  let previous: Component | undefined;
  let previousRight = 0;
  for (const { part, block, collapsed } of pending) {
    const framed = showSites && part.trees.length > 0;
    if (previous && framed && x > MARGIN) x = previousRight + gapBetween(previous, part);
    // A collapsed site is its own card, so it needs no frame padding or label band.
    const pad = framed && !collapsed ? SITE_PAD : 0;
    const label = framed && !collapsed ? SITE_LABEL : 0;
    const outerWidth = block.width + pad * 2;
    if (x > MARGIN && x + outerWidth - MARGIN > rowLimit) { x = MARGIN; y += rowHeight + SITE_GAP; rowHeight = 0; previous = undefined; }
    block.place(x + pad, y + pad + label);
    if (collapsed) {
      // Links into a collapsed site end at its summary card.
      for (const id of part.trees.flatMap(function ids(tree): string[] { return [tree.equipment.id, ...tree.children.flatMap(ids)]; })) {
        state.glyphs.set(id, { x: x + outerWidth / 2, y: y + (block.height + pad * 2 + label) / 2 });
        collapsedSite.set(id, part.id);
        hidden.add(id);
      }
      for (const zone of part.trees.flatMap(function zones(tree): Zone[] { return [...tree.zones, ...tree.children.flatMap(zones)]; })) {
        for (const member of [zone, ...zone.children]) {
          collapsedSite.set(member.id, part.id);
          for (const host of member.hosts) collapsedSite.set(host.id, part.id);
        }
      }
    }
    if (framed) {
      const total = part.trees.flatMap(function devices(tree): string[] { return [tree.equipment.name, ...tree.children.flatMap(devices)]; });
      sites.push({ id: part.id, label: part.label, x, y, width: outerWidth, height: block.height + pad * 2 + label, collapsed,
        summary: collapsed ? { zones: part.zoneCount, hosts: part.hostCount, devices: total } : undefined });
    }
    previous = part;
    previousRight = x + outerWidth;
    x += outerWidth + (framed ? SITE_GAP : BLOCK_GAP);
    rowHeight = Math.max(rowHeight, block.height + pad * 2 + label);
    tallest = Math.max(tallest, y + rowHeight);
  }
  // Each Internet boundary is centered over the devices it connects to, in the band above all
  // sites. Its uplinks reach into the sites, or end at a collapsed site's card.
  const clouds = [...model.internets.values()].flatMap((internet) => {
    const anchors = internet.attachments.flatMap((attachment) => {
      const glyph = state.glyphs.get(attachment.equipmentId);
      return glyph ? [{ attachment, glyph }] : [];
    });
    if (!anchors.length) return [];
    return [{ internet, anchors, x: anchors.reduce((sum, { glyph }) => sum + glyph.x, 0) / anchors.length }];
  }).sort((a, b) => a.x - b.x || a.internet.id.localeCompare(b.internet.id, "en"));
  clouds.forEach((cloud, index) => { if (index > 0) cloud.x = Math.max(cloud.x, clouds[index - 1].x + CLOUD_SPACING); });
  for (const { internet, anchors, x: cx } of clouds) {
    const top = MARGIN + CLOUD_HEIGHT;
    state.internets.push({ internet, x: cx, y: MARGIN + CLOUD_HEIGHT / 2 });
    const turn = top + 18 + internet.sensors.length * 24;
    anchors.forEach(({ attachment, glyph }, index) => {
      const collapsedEnd = hidden.has(attachment.equipmentId);
      const end = collapsedEnd ? glyph.y : glyph.y - GLYPH / 2;
      const bend = turn + index * 8;
      state.wires.push({ key: attachment.key, style: attachment.style, linkKind: attachment.linkKind,
        entities: [attachment.equipmentId, internet.id, ...internet.sensors.map(({ device }) => device.id)],
        path: glyph.x === cx ? `M ${cx} ${top} V ${end}` : `M ${cx} ${top} V ${bend} H ${glyph.x} V ${end}` });
      const text = interfaceText(attachment) || (attachment.ip ?? "");
      if (text && !collapsedEnd) state.labels.push({ key: attachment.key + ":label", x: glyph.x + 10, y: end - 8, text, anchor: "start", kind: "interface" });
    });
    internet.sensors.forEach((placement, index) => {
      const ty = top + 16 + index * 24;
      const label = chipLabel(placement, true);
      state.taps.push({ key: internet.id + placement.device.id, x: cx, y: ty, entities: [internet.id, placement.device.id],
        chip: { key: internet.id + placement.device.id + ":chip", device: placement.device, via: "tap", scope: placement.scope,
          x: cx - 14 - chipWidth(label), y: ty - 9, width: chipWidth(label), label } });
    });
  }
  // Links between sites, and any other link outside the device trees, run below everything.
  let lane = 0;
  const below = tallest + 24;
  const drawn = new Set(state.wires.map(({ key }) => key));
  const siteFor = (id: string) => sites.find((site) => {
    const glyph = state.glyphs.get(id);
    return glyph && glyph.x >= site.x && glyph.x <= site.x + site.width && glyph.y >= site.y && glyph.y <= site.y + site.height;
  });
  for (const transit of model.transits.values()) {
    const [first, second] = transit.ends;
    if (!first || !second || drawn.has(transit.id)) continue;
    const a = state.glyphs.get(first.equipmentId);
    const b = state.glyphs.get(second.equipmentId);
    const treeLinked = state.wires.some(({ key }) => key === first.equipmentId + ":" + second.equipmentId || key === second.equipmentId + ":" + first.equipmentId);
    // A link inside one collapsed site is part of its summary card, not the map.
    const insideCollapsed = hidden.has(first.equipmentId) && hidden.has(second.equipmentId)
      && collapsedSite.get(first.equipmentId) === collapsedSite.get(second.equipmentId);
    if (!a || !b || treeLinked || insideCollapsed) continue;
    const [left, right] = a.x <= b.x ? [a, b] : [b, a];
    const [leftEnd, rightEnd] = a.x <= b.x ? [first, second] : [second, first];
    const leftSite = siteFor(leftEnd.equipmentId);
    const rightSite = siteFor(rightEnd.equipmentId);
    const adjacent = leftSite && rightSite && leftSite !== rightSite && leftSite.y === rightSite.y
      && sites.indexOf(rightSite) === sites.indexOf(leftSite) + 1;
    // Sites stacked in a column connect straight down, through the gap between them.
    const [upperSite, lowerSite] = leftSite && rightSite && leftSite.y <= rightSite.y ? [leftSite, rightSite] : [rightSite, leftSite];
    const stacked = !adjacent && upperSite && lowerSite && upperSite !== lowerSite && upperSite.y + upperSite.height < lowerSite.y
      && Math.max(upperSite.x, lowerSite.x) < Math.min(upperSite.x + upperSite.width, lowerSite.x + lowerSite.width);
    const entities = [first.equipmentId, second.equipmentId, transit.id, ...transit.sensors.map(({ device }) => device.id)];
    let path: string;
    let mid: { x: number; y: number };
    let labelAnchor: DiagramLabel["anchor"] = "middle";
    if (adjacent) {
      // The link jogs just before the right site, so its labels sit centered in the gap on a straight run.
      const gapLeft = leftSite.x + leftSite.width;
      const jog = rightSite.x - LINK_JOG;
      path = left.y === right.y ? `M ${left.x + GLYPH / 2} ${left.y} H ${right.x - GLYPH / 2}`
        : `M ${left.x + GLYPH / 2} ${left.y} H ${jog} V ${right.y} H ${right.x - GLYPH / 2}`;
      mid = { x: (gapLeft + (left.y === right.y ? rightSite.x : jog)) / 2, y: left.y };
    } else if (stacked) {
      const [upper, lower] = a.y <= b.y ? [a, b] : [b, a];
      const [upperId, lowerId] = a.y <= b.y ? [first.equipmentId, second.equipmentId] : [second.equipmentId, first.equipmentId];
      const gapY = upperSite.y + upperSite.height + (lowerSite.y - upperSite.y - upperSite.height) / 2;
      const clear = (x1: number, y1: number, x2: number, y2: number) => !crosses(state, [upperId, lowerId], x1, y1, x2, y2);
      // Leave a site straight down or up when nothing is in the way; otherwise along the device's
      // own row to the site's side, and down (or up) inside the frame's edge.
      const exit = (glyph: { x: number; y: number }, id: string, site: PlacedSite, edgeY: number) => {
        if (hidden.has(id)) return { points: [] as [number, number][], x: glyph.x, start: glyph.y };
        const outward = Math.sign(edgeY - glyph.y);
        const start = glyph.y + outward * GLYPH / 2;
        if (clear(glyph.x, start, glyph.x, edgeY)) return { points: [], x: glyph.x, start };
        const towards = lower.x >= upper.x ? [1, -1] : [-1, 1];
        for (const side of id === upperId ? towards : towards.map((s) => -s)) {
          // The run follows the frame's inner padding, which subnet cards never occupy.
          const sideX = side > 0 ? site.x + site.width - SITE_PAD / 2 : site.x + SITE_PAD / 2;
          if (clear(glyph.x + side * GLYPH / 2, glyph.y, sideX, glyph.y) && clear(sideX, glyph.y, sideX, edgeY)) {
            return { points: [[glyph.x + side * GLYPH / 2, glyph.y], [sideX, glyph.y]] as [number, number][], x: sideX, start: glyph.y };
          }
        }
        return { points: [], x: glyph.x, start };
      };
      const top = exit(upper, upperId, upperSite, upperSite.y + upperSite.height);
      const bottom = exit(lower, lowerId, lowerSite, lowerSite.y);
      path = orthogonalPath([...top.points.length ? top.points : [[top.x, top.start] as [number, number]], [top.x, gapY], [bottom.x, gapY],
        ...bottom.points.length ? [...bottom.points].reverse() : [[bottom.x, bottom.start] as [number, number]]]);
      mid = { x: bottom.x + 12, y: gapY + 4 };
      labelAnchor = "start";
    } else {
      const laneY = below + lane++ * 12;
      path = `M ${left.x} ${left.y + GLYPH / 2} V ${laneY} H ${right.x} V ${right.y + GLYPH / 2}`;
      mid = { x: (left.x + right.x) / 2, y: laneY };
    }
    state.wires.push({ key: transit.id, style: "interface", linkKind: transit.kind, entities, path });
    const cidr = transit.segment?.cidr;
    // With sensor chips under the link, the name and range both sit above it.
    const chipsBelow = transit.sensors.length > 0 && !hidden.has(leftEnd.equipmentId) && !hidden.has(rightEnd.equipmentId);
    state.labels.push({ key: transit.id + ":name", x: mid.x, y: mid.y - (chipsBelow && cidr ? 21 : 8), text: transitTitle(transit), anchor: labelAnchor, kind: "link" });
    if (cidr) state.labels.push({ key: transit.id + ":cidr", x: mid.x, y: chipsBelow ? mid.y - 7 : mid.y + 16, text: cidr, anchor: labelAnchor, kind: "link-detail" });
    // Interface labels and sensors at a collapsed end would sit on its summary card.
    if (!hidden.has(leftEnd.equipmentId)) state.labels.push({ key: transit.id + ":left", x: left.x + GLYPH / 2 + 6, y: left.y + 16, kind: "interface", anchor: "start",
      text: [leftEnd.interfaceName, interfaceSuffix(leftEnd.ip, cidr)].join(" ") });
    if (!hidden.has(rightEnd.equipmentId)) state.labels.push({ key: transit.id + ":right", x: right.x - GLYPH / 2 - 6, y: right.y + 16, kind: "interface", anchor: "end",
      text: [rightEnd.interfaceName, interfaceSuffix(rightEnd.ip, cidr)].join(" ") });
    if (!hidden.has(leftEnd.equipmentId) && !hidden.has(rightEnd.equipmentId)) placeTaps(state, transit.id, transit.sensors, mid.x, mid.y, 160);
  }
  // Secondary attachments, such as a subnet shared by two devices, enter the zone from its right edge.
  for (const attachment of model.attachments) {
    if (drawn.has(attachment.key) || state.wires.some(({ key }) => key === attachment.key)) continue;
    if (hidden.has(attachment.equipmentId)) continue;
    const glyph = state.glyphs.get(attachment.equipmentId);
    const zone = state.zones.find(({ zone }) => zone.id === attachment.targetId);
    if (!glyph || !zone) continue;
    const laneX = Math.max(zone.x + zone.width, glyph.x + GLYPH / 2) + 14 + (lane++ % 6) * 8;
    const entryY = zone.y + 20;
    const path = `M ${glyph.x + GLYPH / 2} ${glyph.y + 10} H ${laneX} V ${entryY} H ${zone.x + zone.width}`;
    const text = interfaceText(attachment, zone.zone);
    if (text) state.labels.push({ key: attachment.key + ":label", x: zone.x + zone.width + 6, y: entryY - 6, text, anchor: "start", kind: "interface" });
    state.wires.push({ key: attachment.key, style: attachment.style, linkKind: attachment.linkKind,
      entities: wireEntities(attachment, zone?.zone), path });
  }

  const zonesFlat = state.zones.flatMap(function flatten(zone): PlacedZone[] { return [zone, ...zone.children.flatMap(flatten)]; });
  const entities = new Map<string, DiagramEntity>();
  const bounds = new Map<string, Bounds>();
  for (const placed of zonesFlat) {
    entities.set(placed.zone.id, { kind: "zone", id: placed.zone.id, zone: placed.zone });
    bounds.set(placed.zone.id, placed);
    for (const card of [...placed.hostCards, ...placed.names]) bounds.set(card.host.id, { x: placed.x + card.x, y: placed.y + card.y, width: card.width, height: card.height });
  }
  for (const zone of model.zones.values()) {
    if (!entities.has(zone.id)) entities.set(zone.id, { kind: "zone", id: zone.id, zone });
    for (const host of zone.hosts) entities.set(host.id, { kind: "host", id: host.id, host });
  }
  for (const placed of state.equipment) {
    entities.set(placed.equipment.id, { kind: "equipment", id: placed.equipment.id, equipment: placed.equipment });
    bounds.set(placed.equipment.id, { x: placed.x - GLYPH / 2, y: placed.y - GLYPH / 2, width: GLYPH, height: GLYPH });
  }
  for (const item of model.equipment.values()) if (!entities.has(item.id)) entities.set(item.id, { kind: "equipment", id: item.id, equipment: item });
  for (const site of sites) bounds.set("site:" + site.id, site);
  for (const placed of state.internets) {
    entities.set(placed.internet.id, { kind: "internet", id: placed.internet.id, internet: placed.internet });
    bounds.set(placed.internet.id, { x: placed.x - 30, y: placed.y - CLOUD_HEIGHT / 2, width: 60, height: CLOUD_HEIGHT });
  }
  for (const transit of model.transits.values()) entities.set(transit.id, { kind: "transit", id: transit.id, transit });
  const hostByName = new Map<string, DiagramHost>();
  for (const zone of model.zones.values()) for (const host of zone.hosts) hostByName.set(host.hostname.toLowerCase(), host);
  const coverage = new Map<string, string[]>();
  for (const device of model.sensors) {
    entities.set(device.id, { kind: "sensor", id: device.id, device, host: hostByName.get(device.hostname.toLowerCase()) });
    coverage.set(device.id, [
      ...[...model.zones.values()].filter(({ sensors }) => sensors.some((placement) => placement.device.id === device.id)).map(({ id }) => id),
      ...[...model.transits.values()].filter(({ sensors }) => sensors.some((placement) => placement.device.id === device.id)).map(({ id }) => id),
      ...[...model.internets.values()].filter(({ sensors }) => sensors.some((placement) => placement.device.id === device.id)).map(({ id }) => id),
    ]);
  }
  const extent = drawnExtent(state, zonesFlat, sites);
  return { model, width: Math.max(extent.right, MARGIN) + MARGIN, height: Math.max(extent.bottom, tallest) + MARGIN, detail, zones: state.zones, equipment: state.equipment,
    internets: state.internets, sites, wires: state.wires, labels: state.labels, taps: state.taps, entities, bounds, coverage, collapsedSite };
}

/** The device line a collapsed site card shows: up to three names, then a count. */
export function siteDeviceLine(devices: string[]): string {
  return devices.slice(0, 3).join(", ") + (devices.length > 3 ? ` +${devices.length - 3}` : "");
}

/** A collapsed site card wide enough for its summary lines. */
/** An M/H/V path through corner points that differ in only one coordinate at a time. */
function orthogonalPath(points: [number, number][]): string {
  const [[x0, y0], ...rest] = points;
  let [x, y] = [x0, y0];
  const commands = [`M ${x0} ${y0}`];
  for (const [nx, ny] of rest) {
    if (nx !== x) commands.push(`H ${nx}`);
    if (ny !== y) commands.push(`V ${ny}`);
    [x, y] = [nx, ny];
  }
  return commands.join(" ");
}

/** Whether a straight horizontal or vertical run would pass over a subnet card or another device. */
function crosses(state: LayoutState, except: string[], x1: number, y1: number, x2: number, y2: number): boolean {
  const [left, right] = [Math.min(x1, x2), Math.max(x1, x2)];
  const [top, bottom] = [Math.min(y1, y2), Math.max(y1, y2)];
  const overlaps = (x: number, y: number, width: number, height: number) =>
    left < x + width && right > x && top < y + height && bottom > y;
  return state.zones.some(({ x, y, width, height }) => overlaps(x, y, width, height))
    || state.equipment.some(({ equipment, x, y }) => !except.includes(equipment.id)
      && overlaps(x - GLYPH / 2, y - GLYPH / 2, GLYPH, GLYPH));
}

function collapsedWidth(part: Component): number {
  const devices = part.trees.flatMap(function names(tree): string[] { return [tree.equipment.name, ...tree.children.flatMap(names)]; });
  return Math.max(COLLAPSED_SITE.width, Math.min(420, textWidth(siteDeviceLine(devices), 11) + 40), textWidth(part.label, 14) + 40);
}

/** The far edges of everything drawn, so fitting the view never leaves anything out. */
function drawnExtent(state: LayoutState, zones: PlacedZone[], sites: PlacedSite[]): { right: number; bottom: number } {
  let right = 0;
  let bottom = 0;
  const include = (x: number, y: number) => { right = Math.max(right, x); bottom = Math.max(bottom, y); };
  for (const wire of state.wires) {
    const tokens = wire.path.trim().split(/\s+/);
    let x = 0;
    let y = 0;
    for (let index = 0; index < tokens.length; index++) {
      const command = tokens[index];
      if (command === "M") { x = Number(tokens[++index]); y = Number(tokens[++index]); }
      else if (command === "H") x = Number(tokens[++index]);
      else if (command === "V") y = Number(tokens[++index]);
      else continue;
      include(x, y);
    }
  }
  for (const label of state.labels) {
    const width = label.kind === "interface" || label.kind === "link-detail" ? textWidth(label.text, 10.5, true) : textWidth(label.text, 11);
    include(label.anchor === "start" ? label.x + width : label.anchor === "middle" ? label.x + width / 2 : label.x, label.y + 4);
  }
  for (const tap of state.taps) include(tap.chip.x + tap.chip.width, tap.chip.y + 18);
  for (const zone of zones) include(zone.x + zone.width, zone.y + zone.height);
  for (const site of sites) include(site.x + site.width, site.y + site.height);
  for (const item of state.equipment) {
    const label = Math.max(textWidth(item.equipment.name, 13), textWidth(item.equipment.subtitle, 11));
    include(item.x + (item.labelSide === "above" ? Math.max(GLYPH / 2, label / 2) : GLYPH / 2), item.y + GLYPH / 2);
  }
  for (const item of state.internets) include(item.x + 34 + Math.max(textWidth(item.internet.name, 13), item.internet.inferred ? textWidth("inferred from public addresses", 11) : 0), item.y + CLOUD_HEIGHT / 2);
  return { right, bottom };
}

/** Several trees in one component (rare) stack left to right. */
function stackTrees(state: LayoutState, trees: Tree[]): Block {
  const blocks = trees.map((tree, index) => {
    const internets = [...state.model.internets.values()].filter(({ attachments }) =>
      attachments.some(({ equipmentId }) => equipmentId === tree.equipment.id) && index >= 0);
    return treeBlock(state, tree, internets);
  });
  return {
    width: blocks.reduce((sum, block) => sum + block.width, 0) + (blocks.length - 1) * BLOCK_GAP,
    height: Math.max(...blocks.map(({ height }) => height)),
    place(x, y) {
      let left = x;
      for (const block of blocks) { block.place(left, y); left += block.width + BLOCK_GAP; }
    },
  };
}

/**
 * Place the model, choosing the zone grid width and level of detail that best fit the viewport.
 * Small environments open at host detail; larger ones open at the zone overview.
 */
export function layoutNetworkDiagram(graph: TopologyGraph, layers: DiagramLayers, options: LayoutOptions): DiagramScene {
  const model = buildDiagramModel(graph, layers);
  const parts = components(model);
  const fit = (scene: DiagramScene) => Math.min(options.viewport.width / scene.width, options.viewport.height / scene.height);
  const best = (detail: Detail) => {
    let chosen: DiagramScene | undefined;
    for (let columns = 1; columns <= 6; columns++) {
      const scene = layoutWith(model, layers, columns, detail, options, parts);
      if (!chosen || fit(scene) > fit(chosen) + 1e-6) chosen = scene;
    }
    return chosen!;
  };
  const hasHosts = [...model.zones.values()].some(({ hosts }) => hosts.length);
  if (hasHosts) {
    const detailed = best("hosts");
    if (fit(detailed) >= HOST_DETAIL_SCALE) return detailed;
  }
  return best("overview");
}
