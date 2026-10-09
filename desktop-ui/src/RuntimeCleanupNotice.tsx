import type { RuntimeCleanupReport } from "./api";

export function RuntimeCleanupNotice({ report }: { report?: RuntimeCleanupReport | null }) {
  if (!report?.warnings?.length) return null;
  return <details className="runtime-cleanup-notice" role="alert">
    <summary>App runtime cleanup needs attention. Older files were kept for safety.</summary>
    <p>Studio will retry automatically. It could not verify or complete safe removal of these files:</p>
    <ul>{report.warnings.map((warning) => <li key={warning.path}>
      <p>{warning.message}</p><code>{warning.path}</code>
    </li>)}</ul>
  </details>;
}
