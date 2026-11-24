import type { TopologyGraph } from "./api";

/*
 * What changed between two revisions of an environment's topology, by stable diagram IDs. Studio
 * remembers the last revision shown for each item during this session, so after an Author edit
 * the diagram can show exactly what the edit added, changed or removed.
 */

export type DiagramChanges = {
  added: Set<string>;
  changed: Set<string>;
  removed: { id: string; label: string; kind: string }[];
};

type Entry = { id: string; label: string; kind: string; signature: string };

function stable(value: unknown): string {
  if (Array.isArray(value)) return "[" + value.map(stable).join(",") + "]";
  if (value && typeof value === "object") {
    return "{" + Object.keys(value).sort().filter((key) => (value as Record<string, unknown>)[key] !== undefined)
      .map((key) => JSON.stringify(key) + ":" + stable((value as Record<string, unknown>)[key])).join(",") + "}";
  }
  return JSON.stringify(value ?? null);
}

function entries(graph: TopologyGraph): Map<string, Entry> {
  const result = new Map<string, Entry>();
  const add = (id: string, label: string, kind: string, facts: unknown) => result.set(id, { id, label, kind, signature: stable(facts) });
  for (const { id, name, cidr, exposure, description } of graph.segments) add(id, name, "subnet", { cidr, exposure, description });
  for (const host of graph.hosts) {
    add(host.id, host.hostname, "host", { ip: host.ip, os: host.os, roles: host.roles, type: host.type, users: host.primary_users,
      segment: host.primary_segment_id ?? host.segment_ids, public: host.public_address });
  }
  for (const device of graph.devices) {
    add(device.id, device.hostname, device.kind === "firewall" ? "firewall" : "sensor", {
      kind: device.kind, placement: device.placement, direction: device.direction, formats: device.log_formats,
      associations: device.associations, nat: device.nat_rules, policy: device.policy, tap: graph.link_taps?.[device.id],
    });
  }
  for (const [name, link] of Object.entries(graph.routing?.links ?? {})) add("link:" + name, name, "link", link);
  for (const [name, device] of Object.entries(graph.routing?.devices ?? {})) {
    if (!device.firewall) add("router:" + name, device.system ?? name, "router", device);
  }
  return result;
}

/** Changes from one topology to the next, or null when nothing a diagram shows differs. */
export function diffTopology(previous: TopologyGraph, next: TopologyGraph): DiagramChanges | null {
  const before = entries(previous);
  const after = entries(next);
  const added = new Set([...after.keys()].filter((id) => !before.has(id)));
  const changed = new Set([...after.values()].filter(({ id, signature }) => before.has(id) && before.get(id)!.signature !== signature).map(({ id }) => id));
  const removed = [...before.values()].filter(({ id }) => !after.has(id)).map(({ id, label, kind }) => ({ id, label, kind }));
  return added.size || changed.size || removed.length ? { added, changed, removed } : null;
}

const lastShown = new Map<string, { revision: string; graph: TopologyGraph }>();

/** Changes since this item's previously shown revision. Pure, so it is safe during render. */
export function changesSinceLastShown(key: string, revision: string, graph: TopologyGraph): DiagramChanges | null {
  const previous = lastShown.get(key);
  return previous && previous.revision !== revision ? diffTopology(previous.graph, graph) : null;
}

/** Remember the revision now shown for an item. Call after rendering it. */
export function rememberShown(key: string, revision: string, graph: TopologyGraph): void {
  lastShown.set(key, { revision, graph });
}

/** Forget remembered revisions, for tests. */
export function resetShownRevisions(): void {
  lastShown.clear();
}
