import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const localPython = path.join(root, process.platform === "win32" ? ".venv/Scripts/python.exe" : ".venv/bin/python");
const python = process.env.EFORGE_STUDIO_PYTHON || (existsSync(localPython) ? localPython : "python3");
const result = spawnSync(python, [path.join(root, "scripts/sync_studio_version.py"), ...process.argv.slice(2)], {
  cwd: root, stdio: "inherit",
});
if (result.error) throw result.error;
process.exit(result.status ?? 1);
