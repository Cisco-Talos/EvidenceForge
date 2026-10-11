import type { MouseEvent } from "react";
import { isTauri } from "@tauri-apps/api/core";
import { openUrl } from "@tauri-apps/plugin-opener";
import type { LinuxSandboxNotice as Notice } from "./api";

const setupUrl = "https://learn.chatgpt.com/docs/sandboxing#prerequisites";
const ubuntuSetup = `sudo apt-get update
sudo apt-get install -y bubblewrap apparmor-profiles apparmor-utils
sudo install -m 0644 \\
  /usr/share/apparmor/extra-profiles/bwrap-userns-restrict \\
  /etc/apparmor.d/bwrap-userns-restrict
sudo apparmor_parser -r /etc/apparmor.d/bwrap-userns-restrict`;

export function LinuxSandboxNotice({ notice, onError }: { notice?: Notice | null; onError: (message: string) => void }) {
  if (!notice) return null;
  const namespaceIssue = notice.code === "user_namespace_restricted";
  async function openInstructions(event: MouseEvent<HTMLAnchorElement>) {
    if (!isTauri()) return;
    event.preventDefault();
    try { await openUrl(setupUrl); }
    catch (error) { onError(String(error)); }
  }
  return <details className="linux-sandbox-notice" role="alert">
    <summary>Linux authoring sandbox may need setup. Show instructions.</summary>
    <p>{namespaceIssue
      ? "Codex reports that bubblewrap cannot create the user namespaces needed for sandboxed commands. AppArmor or another host restriction may be responsible."
      : "Codex could not find system bubblewrap. Install bubblewrap using your distribution's package manager."}</p>
    {namespaceIssue && <>
      <p>On Ubuntu 24.04, if no AppArmor profile already covers /usr/bin/bwrap, install and load Ubuntu's supplied profile:</p>
      <pre><code>{ubuntuSetup}</code></pre>
      <p>For other distributions or an existing profile, use your distribution's AppArmor guidance or ask your administrator to repair the policy for bubblewrap.</p>
    </>}
    <p>After setup, reconnect Codex using the status dot when authoring is idle. This notice is advisory; it does not change your system configuration.</p>
    <a href={setupUrl} target="_blank" rel="noopener noreferrer" onClick={(event) => void openInstructions(event)}>Codex sandbox setup documentation</a>
  </details>;
}
