import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const frontend = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const args = process.argv.slice(2);
if (process.platform === "darwin") {
  const bundlesIndex = args.indexOf("--bundles");
  if (bundlesIndex >= 0 && args[bundlesIndex + 1] !== "app") {
    throw new Error("This source-run build produces a .app. Use --bundles app; distribution packaging is separate.");
  }
  if (bundlesIndex < 0) args.push("--bundles", "app");
}
function run(command, arguments_) {
  const result = spawnSync(command, arguments_, { cwd: frontend, stdio: "inherit" });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status || 1);
}

run(process.execPath, [path.join(frontend, "node_modules", "@tauri-apps", "cli", "tauri.js"), "build", ...args]);
