// Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: MIT
// Harmless reference extension installed only in this run's fresh extensions dir.
// It uses VS Code APIs and files in the invented workspace; no network/child exec.
const fs = require("fs");
const path = require("path");
const vscode = require("vscode");
const config = JSON.parse(fs.readFileSync(path.join(__dirname, "reference.json"), "utf8"));
const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function publish(name, value) {
  fs.writeFileSync(path.join(config.root, name), JSON.stringify({ nonce: config.nonce, ...value }), { mode: 0o600, flag: "wx" });
}

exports.activate = async function () {
  const folders = vscode.workspace.workspaceFolders || [];
  if (folders.length !== 1) return;
  const current = folders[0].uri.fsPath;
  if (current === path.join(config.root, "second-workspace")) {
    try { publish("second-window.json", { ready: true, pid: process.pid }); } catch (_) {}
    return;
  }
  if (current !== path.join(config.root, "workspace")) return;
  try {
    fs.closeSync(fs.openSync(path.join(config.root, "driver-lock"), "wx", 0o600));
  } catch (_) { return; }
  try {
    const document = await vscode.workspace.openTextDocument(vscode.Uri.file(path.join(current, "example.txt")));
    const editor = await vscode.window.showTextDocument(document);
    const range = new vscode.Range(document.positionAt(0), document.positionAt(document.getText().length));
    const changed = await editor.edit((edit) => edit.replace(range, "reference save complete\n"));
    const saved = changed && await document.save();
    publish("save-control.json", { saved, pid: process.pid });
    await vscode.commands.executeCommand("vscode.openFolder", vscode.Uri.file(path.join(config.root, "second-workspace")), { forceNewWindow: true });
    for (let i = 0; i < 50 && !fs.existsSync(path.join(config.root, "second-window.json")); ++i) await pause(200);
    publish("workflow-control.json", { saved, second: fs.existsSync(path.join(config.root, "second-window.json")), pid: process.pid });
  } catch (_) {
    try { publish("workflow-control.json", { saved: false, second: false, pid: process.pid }); } catch (_) {}
  } finally {
    await pause(1000);
    await vscode.commands.executeCommand("workbench.action.quit");
  }
};
exports.deactivate = function () {};
