import { expect, test } from "vitest";
import { ancestorFolders, buildFileTree, type FileTreeNode } from "../src/bundleFileTree";

/** Compact outline of a tree: folders as `name/ (count)`, files by name, children indented. */
function outline(nodes: FileTreeNode[], depth = 0): string[] {
  return nodes.flatMap((node) => node.kind === "folder"
    ? [`${"  ".repeat(depth)}${node.name}/ (${node.fileCount}) [${node.path}]`, ...outline(node.children, depth + 1)]
    : [`${"  ".repeat(depth)}${node.name} [${node.path}] ${node.size}`]);
}

test("buildFileTree nests flat paths under folders, folders first, in natural name order with recursive counts", () => {
  const tree = buildFileTree([
    { path: "README.md", size: 1 },
    { path: "HOST-10/zeek/conn.log", size: 2 },
    { path: "HOST-2/zeek/dns.log", size: 3 },
    { path: "HOST-2/zeek/conn.log", size: 4 },
    { path: "HOST-2/sysmon.xml", size: 5 },
    { path: "GROUND_TRUTH.md", size: 6 },
    { path: "host-2/lower.log", size: 7 },
  ]);
  expect(outline(tree)).toEqual([
    "HOST-2/ (3) [HOST-2]",
    "  zeek/ (2) [HOST-2/zeek]",
    "    conn.log [HOST-2/zeek/conn.log] 4",
    "    dns.log [HOST-2/zeek/dns.log] 3",
    "  sysmon.xml [HOST-2/sysmon.xml] 5",
    "host-2/ (1) [host-2]",
    "  lower.log [host-2/lower.log] 7",
    "HOST-10/ (1) [HOST-10]",
    "  zeek/ (1) [HOST-10/zeek]",
    "    conn.log [HOST-10/zeek/conn.log] 2",
    "GROUND_TRUTH.md [GROUND_TRUTH.md] 6",
    "README.md [README.md] 1",
  ]);
});

test("buildFileTree keeps file paths exact, tolerates redundant slashes and returns nothing for no files", () => {
  const tree = buildFileTree([{ path: "data//a.log", size: 1 }]);
  expect(tree).toHaveLength(1);
  expect(tree[0]).toMatchObject({ kind: "folder", path: "data", name: "data", fileCount: 1 });
  expect((tree[0] as Extract<FileTreeNode, { kind: "folder" }>).children).toEqual([{ kind: "file", path: "data//a.log", name: "a.log", size: 1 }]);
  expect(buildFileTree([])).toEqual([]);
});

test("ancestorFolders lists a file's folders outermost first", () => {
  expect(ancestorFolders("HOST-01/zeek/conn.log")).toEqual(["HOST-01", "HOST-01/zeek"]);
  expect(ancestorFolders("GROUND_TRUTH.md")).toEqual([]);
  expect(ancestorFolders(null)).toEqual([]);
  expect(ancestorFolders("")).toEqual([]);
});
