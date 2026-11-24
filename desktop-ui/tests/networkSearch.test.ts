import { expect, test } from "vitest";
import type { TopologyGraph } from "../src/api";
import { buildDiagramModel } from "../src/networkDiagramLayout";
import { containsAddress, parseAddress, searchDiagram } from "../src/networkSearch";

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
