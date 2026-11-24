import { expect, test } from "vitest";
import type { TopologyGraph } from "../src/api";
import { buildDiagramModel } from "../src/networkDiagramLayout";
import { containsAddress, firewallRuleFilter, parseAddress, searchDiagram } from "../src/networkSearch";

test("complete IPv4 and IPv6 addresses parse, and partial input does not", () => {
  expect(parseAddress("10.40.20.44")).toEqual({ value: 0x0a28142cn, bits: 32 });
  expect(parseAddress("2001:db8::1")).toEqual({ value: (0x20010db8n << 96n) + 1n, bits: 128 });
  expect(parseAddress("::")).toEqual({ value: 0n, bits: 128 });
  for (const partial of ["10.40.20", "10.40.20.256", "2001:db8", "1::2::3", "host-1", ""]) expect(parseAddress(partial)).toBeNull();
});

test("containment checks the prefix and address family", () => {
  const address = parseAddress("10.40.20.200")!;
  expect(containsAddress("10.40.20.0/24", address)).toBe(24);
  expect(containsAddress("10.0.0.0/8", address)).toBe(8);
  expect(containsAddress("10.40.21.0/24", address)).toBeNull();
  expect(containsAddress("2001:db8::/32", address)).toBeNull();
  expect(containsAddress("2001:db8::/32", parseAddress("2001:db8:1::5")!)).toBe(32);
  expect(containsAddress("0.0.0.0/0", address)).toBe(0);
});

test("an address lands in its most specific subnet, even when no host uses it", () => {
  const graph: TopologyGraph = {
    segments: [
      { id: "segment:campus", name: "campus", cidr: "10.0.0.0/8", exposure: "internal", description: "" },
      { id: "segment:eng", name: "eng", cidr: "10.40.20.0/24", exposure: "internal", description: "", parent_id: "segment:campus" },
    ],
    hosts: [{ id: "host:A", hostname: "A", ip: "10.40.20.10", os: "Linux", os_family: "linux", segment_ids: ["segment:campus", "segment:eng"], primary_segment_id: "segment:eng" }],
    devices: [], findings: [],
  };
  const model = buildDiagramModel(graph, { sensors: true, hosts: true });
  expect(searchDiagram(graph, model, "10.40.20.250").map(({ kind, label }) => [kind, label])).toEqual([["containing", "eng"]]);
  expect(searchDiagram(graph, model, "10.40.20.10")[0]).toMatchObject({ kind: "host", label: "A", detail: "10.40.20.10 · eng" });
  expect(searchDiagram(graph, model, "  ")).toEqual([]);
});

test("a firewall rule filter finds the rules that apply to an address, a port, or matching text", () => {
  const segments = [{ id: "segment:users", name: "users", cidr: "10.1.0.0/24", exposure: "internal" as const, description: "" },
    { id: "segment:dmz", name: "dmz", cidr: "10.9.0.0/24", exposure: "internal" as const, description: "" }];
  const policy = [
    { src: "users", dst: "dmz", ports: ["443"], action: "permit" as const },
    { src: "external", dst: "dmz", ports: ["80", "4433"], action: "permit" as const },
    { src: "10.1.0.0/16", dst: "any", ports: [], action: "deny" as const },
    { src: "10.9.0.7", dst: "external", ports: ["53"], action: "permit" as const },
  ];
  const nat = [{ type: "static" as const, src: [], real_ip: "10.9.0.7", mapped_ip: "203.0.113.7" },
    { type: "dynamic_pat" as const, src: ["users"], mapped_ip: "203.0.113.1", real_ip: "" }];
  const matching = (query: string) => {
    const filter = firewallRuleFilter(query, segments)!;
    return [policy.flatMap((rule, index) => filter.policy(rule) ? [index] : []), nat.flatMap((rule, index) => filter.nat(rule) ? [index] : [])];
  };
  expect(firewallRuleFilter("  ", segments)).toBeNull();
  // A user's address: its subnet by name, a containing range and "any" all apply, and so does its PAT.
  expect(matching("10.1.0.20")).toEqual([[0, 2], [1]]);
  // A DMZ server: its subnet, its exact address, and its static translation.
  expect(matching("10.9.0.7")).toEqual([[0, 1, 2, 3], [0]]);
  // An address in no subnet is "external".
  expect(matching("198.51.100.9")).toEqual([[1, 2, 3], []]);
  // A port number matches listed ports exactly, not as a substring.
  expect(matching("443")).toEqual([[0], []]);
  expect(matching("deny")).toEqual([[2], []]);
  expect(matching("pat")).toEqual([[], [1]]);
});
