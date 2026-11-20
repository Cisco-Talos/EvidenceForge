/** One file listed by a bundle browser endpoint: a relative POSIX path and its size. */
export interface ListedFile { path: string; size: number }

export interface FileTreeFolder {
  kind: "folder";
  /** Relative POSIX path of the folder, e.g. `HOST-01/zeek`. */
  path: string;
  name: string;
  /** Files anywhere below this folder. */
  fileCount: number;
  children: FileTreeNode[];
}

export interface FileTreeFile { kind: "file"; path: string; name: string; size: number }

export type FileTreeNode = FileTreeFolder | FileTreeFile;

const byName = (a: FileTreeNode, b: FileTreeNode) => a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: "base" });

/** Build a folder tree from flat relative paths: folders first, then files, each in name order. */
export function buildFileTree(files: ListedFile[]): FileTreeNode[] {
  const root: FileTreeFolder = { kind: "folder", path: "", name: "", fileCount: 0, children: [] };
  const folders = new Map<string, FileTreeFolder>([["", root]]);
  for (const file of files) {
    const parts = file.path.split("/").filter(Boolean);
    let parent = root;
    for (let depth = 0; depth < parts.length - 1; depth += 1) {
      const path = parts.slice(0, depth + 1).join("/");
      let folder = folders.get(path);
      if (!folder) {
        folder = { kind: "folder", path, name: parts[depth], fileCount: 0, children: [] };
        folders.set(path, folder);
        parent.children.push(folder);
      }
      parent = folder;
    }
    parent.children.push({ kind: "file", path: file.path, name: parts[parts.length - 1] || file.path, size: file.size });
  }
  const finish = (folder: FileTreeFolder): number => {
    folder.children.sort((a, b) => (a.kind === b.kind ? byName(a, b) : a.kind === "folder" ? -1 : 1));
    folder.fileCount = folder.children.reduce((total, child) => total + (child.kind === "folder" ? finish(child) : 1), 0);
    return folder.fileCount;
  };
  finish(root);
  return root.children;
}

/** Folder paths that contain `path`, outermost first, so a selected file's folders can open. */
export function ancestorFolders(path: string | null): string[] {
  if (!path) return [];
  const parts = path.split("/").filter(Boolean);
  return parts.slice(0, -1).map((_, index) => parts.slice(0, index + 1).join("/"));
}
