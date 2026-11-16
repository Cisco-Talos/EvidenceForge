import { useCallback, useRef, useState } from "react";
import { Tooltip } from "radix-ui";
import { Modal } from "./Modal";
import type { CodexHealth, StudioApi } from "./api";
import { useCodexAccount } from "./CodexAccount";

const labels = { disconnected: "Not connected", unavailable: "Connected, unavailable for work", ready: "Ready for work" };

export function CodexStatusIndicator({ health, api, activeTurns, reconnecting, canReconnect = true, onReconnect, onError }: {
  health: CodexHealth;
  api: StudioApi;
  activeTurns: number;
  reconnecting: boolean;
  canReconnect?: boolean;
  onReconnect: () => Promise<boolean>;
  onError: (message: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [error, setError] = useState("");
  const reportError = useCallback((message: string) => { setError(message); onError(message); }, [onError]);
  const availability = health.availability || (health.state === "connected" || health.state === "stalled" ? "unavailable" : "disconnected");
  const { login, loginPending, loginStarting } = useCodexAccount(api, open && availability !== "disconnected", reportError);
  const checking = health.state === "checking" || reconnecting;
  const label = checking ? "Checking connection" : labels[availability];
  const connected = availability !== "disconnected";
  const trigger = useRef<HTMLButtonElement>(null);
  return <>
    <Tooltip.Root>
      <Tooltip.Trigger asChild>
        <button ref={trigger} className={`codex-indicator ${availability}${checking ? " checking" : ""}`} aria-label={`Codex ${label.toLowerCase()}: ${health.detail}`} aria-haspopup="dialog" onClick={() => setOpen(true)}>
          <span className="codex-indicator-dot" />
        </button>
      </Tooltip.Trigger>
      <Tooltip.Portal><Tooltip.Content className="studio-tooltip" sideOffset={7}>
        <strong>Codex · {label}</strong><span>{health.detail}</span><span className="tooltip-action">Click for details and login</span>
      </Tooltip.Content></Tooltip.Portal>
    </Tooltip.Root>
    {open && <Modal title="Codex status" description={health.detail} className="codex-status-dialog" dismissOnOutside onClose={() => setOpen(false)} onCloseAutoFocus={(event) => { event.preventDefault(); trigger.current?.focus(); }} actions={<>
      <button type="button" className="button-quiet" onClick={() => setOpen(false)}>Close</button>
      <button type="button" className="button-quiet" disabled={!canReconnect || reconnecting} onClick={() => void onReconnect().then((success) => { if (success) setOpen(false); })}>{reconnecting ? "Reconnecting…" : "Reconnect"}</button>
      <button type="button" className="button-primary" disabled={!connected || reconnecting || loginStarting} title={!connected ? "Connect to Codex before logging in" : undefined} onClick={() => { setError(""); void login(); }}>{loginStarting ? "Opening login…" : "Login"}</button>
    </>}>
      <dl className="codex-status-details">
        <div><dt>Connection</dt><dd>{checking ? "Checking connection…" : connected ? "Connected" : "Not connected"}</dd></div>
        <div><dt>Account</dt><dd>{health.account_label || (checking || connected ? "Checking account…" : "Unavailable while disconnected")}</dd></div>
        <div><dt>Work status</dt><dd>{label}</dd></div>
      </dl>
      {loginPending && <p role="status">Complete login in your browser. Waiting for sign-in…</p>}
      {error && <p role="alert">{error}</p>}
      {activeTurns > 0 && <p>Reconnecting will interrupt {activeTurns} active {activeTurns === 1 ? "turn" : "turns"}. Their conversation history remains available for review.</p>}
    </Modal>}
  </>;
}
