import type { StartupProgress } from "./api";

export function StartupScreen({ progress, error }: { progress?: StartupProgress; error: string | null }) {
  const percent = progress?.percent;
  return <div className="boot-screen">
    <img className="boot-logo" src="/brand/evidenceforge-dark.png" alt="EvidenceForge" />
    <h1>{error ? "Studio could not start" : progress?.title || "Starting Studio"}</h1>
    <p role={error ? "alert" : "status"}>{error || progress?.detail || "Connecting to the local service…"}</p>
    {!error && <progress aria-label="Studio startup" max={100} value={percent == null ? undefined : Math.max(0, Math.min(100, percent))} />}
    {error && <button onClick={() => window.location.reload()}>Retry</button>}
  </div>;
}
