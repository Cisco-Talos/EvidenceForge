import { useEffect, useState } from "react";
import { isTauri } from "@tauri-apps/api/core";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { StudioBrand } from "./StudioBrand";
import "./App.css";

export function About() {
  const [error, setError] = useState<string | null>(null);
  async function close() {
    if (!isTauri()) return;
    try { await getCurrentWindow().close(); }
    catch (failure) { setError(`Could not close About: ${String(failure)}`); }
  }
  useEffect(() => {
    const dismiss = (event: KeyboardEvent) => { if (event.key === "Escape") void close(); };
    window.addEventListener("keydown", dismiss);
    return () => window.removeEventListener("keydown", dismiss);
  }, []);
  return <main className="about-window" aria-label="About EvidenceForge Studio">
    <StudioBrand className="brand about-brand" />
    <p className="about-version">Version {__STUDIO_VERSION__}</p>
    <p className="about-description">Synthetic security logs for threat hunting training and research.</p>
    <p className="about-copyright">Copyright © 2026 Cisco Systems, Inc. and its affiliates.</p>
    <p className="about-build">Build {__STUDIO_BUILD__}</p>
    {error && <p role="alert" className="error-text">{error}</p>}
    {isTauri() && <button className="button-quiet" onClick={() => void close()}>Close</button>}
  </main>;
}
