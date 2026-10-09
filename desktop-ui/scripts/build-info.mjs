import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const version = JSON.parse(readFileSync(path.join(root, "desktop-ui/package.json"), "utf8")).version;
let build = "source archive";
try {
  const revision = execFileSync("git", ["rev-parse", "--short=12", "HEAD"], { cwd: root, encoding: "utf8" }).trim();
  const dirty = execFileSync("git", ["status", "--porcelain", "--untracked-files=normal"], { cwd: root, encoding: "utf8" }).trim();
  build = `${revision}${dirty ? " (modified)" : ""}`;
} catch {
  // Source archives can be built without a Git checkout.
}

export const buildInfo = {
  __STUDIO_VERSION__: JSON.stringify(version.replace(/-(alpha|beta|rc)\.(\d+)$/, (_match, phase, number) => `${{ alpha: "a", beta: "b", rc: "rc" }[phase]}${number}`)),
  __STUDIO_BUILD__: JSON.stringify(build),
};
