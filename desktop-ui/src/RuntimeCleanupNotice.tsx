import type { RuntimeCleanupReport } from "./api";

export function RuntimeCleanupNotice({ report }: { report?: RuntimeCleanupReport | null }) {
  if (!report?.warnings?.length) return null;
  const groups = new Map<string, string[]>();
  for (const warning of report.warnings) {
    const paths = groups.get(warning.message) ?? [];
    if (!paths.includes(warning.path)) paths.push(warning.path);
    groups.set(warning.message, paths);
  }
  return <details className="runtime-cleanup-notice" role="alert">
    <summary>App runtime cleanup needs attention. Older files were kept for safety.</summary>
    <p>Cleanup retries at startup, after background work finishes, and hourly. A retry can clear
      this notice once the condition below is resolved.</p>
    <ul>{Array.from(groups, ([message, paths]) => <li key={message}>
      <p>{message}</p>
      <ul>{paths.map((path) => <li key={path}><code>{path}</code></li>)}</ul>
    </li>)}</ul>
  </details>;
}
