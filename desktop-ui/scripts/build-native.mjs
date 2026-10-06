import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync } from "node:fs";
import os from "node:os";
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
if (process.platform === "darwin") {
  const targetIndex = args.indexOf("--target");
  const targetTriple = targetIndex >= 0 ? args[targetIndex + 1] : "";
  const targetRoot = process.env.CARGO_TARGET_DIR
    ? path.resolve(frontend, "src-tauri", process.env.CARGO_TARGET_DIR)
    : path.join(frontend, "src-tauri", "target");
  const appPath = path.join(targetRoot, targetTriple, args.includes("--debug") ? "debug" : "release",
    "bundle", "macos", "EvidenceForge Studio.app");
  if (existsSync(appPath)) {
    const moduleCache = path.join(os.tmpdir(), "evidenceforge-studio-swift-module-cache");
    mkdirSync(moduleCache, { recursive: true });
    run("xcrun", ["swift", "-module-cache-path", moduleCache,
      path.join(frontend, "scripts", "set-macos-app-icon.swift"), appPath,
      path.join(frontend, "src-tauri", "icons", "icon.icns")]);
  }
}
