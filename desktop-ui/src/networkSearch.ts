import type { TopologyGraph } from "./api";
import type { DiagramModel } from "./networkDiagramLayout";

/*
 * Diagram search. Matches hostnames, addresses, subnets, sensors and devices, and answers
 * "which subnet would this address land in?" with the most specific declared range.
 */

export type SearchResult = {
  id: string;
  kind: "host" | "zone" | "sensor" | "equipment" | "containing";
  label: string;
  detail: string;
};

const RESULT_LIMIT = 8;

type Address = { value: bigint; bits: 32 | 128 };

/** Parse a complete IPv4 or IPv6 address. Partial input returns null. */
export function parseAddress(text: string): Address | null {
  const value = text.trim();
  const v4 = value.split(".");
  if (v4.length === 4 && v4.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255)) {
    return { value: v4.reduce((sum, part) => (sum << 8n) + BigInt(Number(part)), 0n), bits: 32 };
  }
  if (!value.includes(":") || !/^[0-9a-f:]+$/i.test(value)) return null;
  const halves = value.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - head.length - tail.length;
  if (halves.length === 1 ? head.length !== 8 : missing < 1) return null;
  const groups = [...head, ...Array(halves.length === 2 ? missing : 0).fill("0"), ...tail];
  if (!groups.every((group) => /^[0-9a-f]{1,4}$/i.test(group))) return null;
  return { value: groups.reduce((sum, group) => (sum << 16n) + BigInt(parseInt(group, 16)), 0n), bits: 128 };
}

/** The prefix length of a CIDR when it contains the address, else null. */
export function containsAddress(cidr: string, address: Address): number | null {
  const [base, length] = cidr.split("/");
  const network = parseAddress(base);
  const prefix = Number(length ?? (network?.bits ?? 32));
  if (!network || network.bits !== address.bits || !(prefix >= 0 && prefix <= network.bits)) return null;
  const shift = BigInt(network.bits - prefix);
  return (network.value >> shift) === (address.value >> shift) ? prefix : null;
}

function rank(text: string, query: string): number | null {
  const value = text.toLowerCase();
  if (value === query) return 0;
  if (value.startsWith(query)) return 1;
  return value.includes(query) ? 2 : null;
}

export function searchDiagram(graph: TopologyGraph, model: DiagramModel, rawQuery: string): SearchResult[] {
  const query = rawQuery.trim().toLowerCase();
  if (!query) return [];
  const scored: (SearchResult & { score: number; order: number })[] = [];
  const add = (result: SearchResult, score: number | null) => {
    if (score === null || scored.some(({ id }) => id === result.id)) return;
    scored.push({ ...result, score, order: scored.length });
  };
  const zoneOf = new Map<string, string>();
  for (const zone of model.zones.values()) for (const host of zone.hosts) zoneOf.set(host.id, zone.name);

  // An exact address first finds its host, then the subnet that contains it.
  const address = parseAddress(query);
  for (const host of graph.hosts) {
    const byName = rank(host.hostname, query);
    const byAddress = host.ip.toLowerCase().startsWith(query) ? (host.ip.toLowerCase() === query ? 0 : 1) : null;
    const byPublic = host.public_address?.toLowerCase().startsWith(query) ? 1 : null;
    const scores = [byName, byAddress, byPublic].filter((score): score is number => score !== null);
    if (!scores.length) continue;
    add({ id: host.id, kind: "host", label: host.hostname,
      detail: [host.ip, host.public_address && `public ${host.public_address}`, zoneOf.get(host.id)].filter(Boolean).join(" · ") }, Math.min(...scores));
  }
  if (address) {
    const containing = [...model.zones.values()]
      .flatMap((zone) => zone.cidr ? [{ zone, prefix: containsAddress(zone.cidr, address) }] : [])
      .filter((entry): entry is { zone: typeof entry.zone; prefix: number } => entry.prefix !== null)
      .sort((a, b) => b.prefix - a.prefix);
    if (containing.length) {
      const { zone } = containing[0];
      add({ id: zone.id, kind: "containing", label: zone.name, detail: `Subnet containing ${rawQuery.trim()} · ${zone.cidr}` }, 0.5);
    }
  }
  for (const zone of model.zones.values()) {
    if (zone.unassigned) continue;
    const score = [rank(zone.name, query), zone.cidr.toLowerCase().startsWith(query) ? 1 : null]
      .filter((value): value is number => value !== null);
    if (score.length) add({ id: zone.id, kind: "zone", label: zone.name, detail: zone.cidr }, Math.min(...score));
  }
  for (const device of graph.devices.filter(({ kind }) => kind !== "firewall")) {
    const score = [rank(device.hostname, query), rank(device.name, query)].filter((value): value is number => value !== null);
    if (score.length) {
      add({ id: device.id, kind: "sensor", label: device.hostname,
        detail: `${(device.evidence ?? []).map(({ label }) => label).join(" + ") || "Sensor"} · ${device.placement.toUpperCase()}` }, Math.min(...score));
    }
  }
  for (const item of model.equipment.values()) {
    const score = [rank(item.name, query), item.routed ? rank(item.routed.name, query) : null].filter((value): value is number => value !== null);
    if (score.length) add({ id: item.id, kind: "equipment", label: item.name, detail: item.subtitle }, Math.min(...score));
  }
  return scored.sort((a, b) => a.score - b.score || a.order - b.order).slice(0, RESULT_LIMIT)
    .map(({ id, kind, label, detail }) => ({ id, kind, label, detail }));
}
