import type { TopologyGraph } from "./api";
import type { DiagramDevice, DiagramModel } from "./networkDiagramLayout";

/*
 * Network evidence coverage. The engine computes which sensors observe traffic between every pair
 * of subnets and the Internet; this module only ranks that evidence and groups it for display.
 */

type RawPath = NonNullable<NonNullable<TopologyGraph["coverage"]>["paths"]>[number];
/** One engine-computed flow, with optional fields filled in. */
export type CoveragePath = { source: string; destination: string; sensors: string[]; delivered: boolean | null;
  reason: string; hops: { link: string; forwarder: string | null }[] };

function normalize(path: RawPath): CoveragePath {
  return { source: path.source, destination: path.destination, sensors: path.sensors ?? [], delivered: path.delivered ?? null,
    reason: path.reason ?? "", hops: (path.hops ?? []).map(({ link, forwarder }) => ({ link, forwarder: forwarder ?? null })) };
}
export type CoverageTier = "full" | "protocol" | "alerts" | "connection" | "firewall" | "none";
export type Direction = "to" | "from";

/** Richest first. "Weakest" coverage of a subnet is the last tier any of its flows reaches. */
export const TIER_ORDER: CoverageTier[] = ["full", "protocol", "alerts", "connection", "firewall", "none"];
export const TIER_LABELS: Record<CoverageTier, string> = {
  full: "Protocol logs and IDS alerts",
  protocol: "Protocol logs",
  alerts: "IDS alerts without protocol logs",
  connection: "Connection records only",
  firewall: "Firewall logs only",
  none: "Not observed by any network sensor",
};
export const INTERNET = "internet";

/** Rank the evidence a set of observing sensors produces. */
export function tierOf(sensorIds: string[], devices: ReadonlyMap<string, DiagramDevice>): CoverageTier {
  const depths = new Set(sensorIds.flatMap((id) => (devices.get(id)?.evidence ?? []).map(({ depth }) => depth)));
  const protocol = depths.has("protocol");
  const alerts = depths.has("alert");
  if (protocol && alerts) return "full";
  if (protocol) return "protocol";
  if (alerts) return "alerts";
  if (depths.has("connection") || depths.has("other")) return "connection";
  if (depths.has("firewall")) return "firewall";
  return "none";
}

export type CoverageRow = { peer: string; tier: CoverageTier; path: CoveragePath };
export type CoverageGroup = { tier: CoverageTier; rows: CoverageRow[] };

export type CoverageIndex = {
  devices: Map<string, DiagramDevice>;
  /** Every flow to (or from) a subnet, keyed by subnet ID. */
  rows: (zoneId: string, direction: Direction) => CoverageRow[];
  /** The poorest coverage of traffic reaching a subnet from other subnets and the Internet. */
  weakest: (zoneId: string) => CoverageTier | undefined;
  /** Coverage of traffic between hosts inside one subnet. */
  within: (zoneId: string) => CoverageTier | undefined;
};

/**
 * Index the engine's flows. `isEndpoint` keeps only subnets drawn as subnets and the Internet;
 * device-to-device transit links are not places a host's traffic starts or ends.
 */
export function indexCoverage(graph: TopologyGraph, isEndpoint: (id: string) => boolean = () => true): CoverageIndex | undefined {
  const paths = (graph.coverage?.paths ?? []).map(normalize).filter(({ source, destination }) => isEndpoint(source) && isEndpoint(destination));
  if (!paths.length) return undefined;
  const devices = new Map(graph.devices.map((device) => [device.id, device]));
  const inbound = new Map<string, CoverageRow[]>();
  const outbound = new Map<string, CoverageRow[]>();
  for (const path of paths) {
    const tier = tierOf(path.sensors, devices);
    inbound.set(path.destination, [...(inbound.get(path.destination) ?? []), { peer: path.source, tier, path }]);
    outbound.set(path.source, [...(outbound.get(path.source) ?? []), { peer: path.destination, tier, path }]);
  }
  return {
    devices,
    rows: (zoneId, direction) => (direction === "to" ? inbound : outbound).get(zoneId) ?? [],
    weakest: (zoneId) => {
      const tiers = (inbound.get(zoneId) ?? []).filter(({ peer }) => peer !== zoneId).map(({ tier }) => TIER_ORDER.indexOf(tier));
      return tiers.length ? TIER_ORDER[Math.max(...tiers)] : undefined;
    },
    within: (zoneId) => (inbound.get(zoneId) ?? []).find(({ peer }) => peer === zoneId)?.tier,
  };
}

/** Rows grouped by tier, richest first, with the subnet's own traffic and the Internet first in a group. */
export function groupRows(rows: CoverageRow[], self: string): CoverageGroup[] {
  const rank = (row: CoverageRow) => row.peer === self ? 0 : row.peer === INTERNET ? 1 : 2;
  return TIER_ORDER.flatMap((tier) => {
    const members = rows.filter((row) => row.tier === tier).sort((a, b) => rank(a) - rank(b) || a.peer.localeCompare(b.peer, "en"));
    return members.length ? [{ tier, rows: members }] : [];
  });
}

/**
 * The diagram elements a flow passes through: the links it crosses, the devices that forward it,
 * the subnets at either end, and its observing sensors.
 */
export function traceEntities(path: CoveragePath, model: DiagramModel): Set<string> {
  const traced = new Set<string>([path.source, path.destination, ...path.sensors]);
  const routedEquipment = new Map([...model.equipment.values()].flatMap((item) => item.routed ? [[item.routed.name, item.id] as const] : []));
  for (const hop of path.hops) {
    traced.add("link:" + hop.link);
    if (hop.forwarder) traced.add(routedEquipment.get(hop.forwarder) ?? hop.forwarder);
    const segment = model.routed ? [...model.zones.values()].find(({ link }) => link?.name === hop.link) : undefined;
    if (segment) traced.add(segment.id);
    const internet = [...model.internets.values()].find(({ linkName }) => linkName === hop.link);
    if (internet) traced.add(internet.id);
  }
  if (path.source === INTERNET || path.destination === INTERNET) for (const internet of model.internets.values()) traced.add(internet.id);
  return traced;
}
