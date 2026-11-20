import { expect, test } from "vitest";
import { parseProjectPackKey, projectPackKey } from "../src/ProjectPackField";

test("project pack keys round-trip an exact released pack", () => {
  const pack = { kind: "organization" as const, publisher: "talos", name: "acme", version: "2.1.0" };
  expect(parseProjectPackKey(projectPackKey(pack))).toEqual(pack);
  expect(projectPackKey(null)).toBe("");
  expect(parseProjectPackKey("")).toBeNull();
  expect(parseProjectPackKey("scenario|talos|acme|1.0.0")).toBeNull();
});
