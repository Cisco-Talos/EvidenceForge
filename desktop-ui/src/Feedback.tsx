import type { ReactNode } from "react";
import { TriangleAlert } from "lucide-react";

/** One empty-state layout: icon, short title, optional sentence and action. */
export function EmptyState({ icon, title, children, action, tall = false, compact = false }: {
  icon?: ReactNode; title: string; children?: ReactNode; action?: ReactNode; tall?: boolean; compact?: boolean;
}) {
  return <div className={`empty-panel ${tall ? "tall" : ""} ${compact ? "compact" : ""}`}>
    {icon}<h3>{title}</h3>{children && <p>{children}</p>}{action && <div className="empty-action">{action}</div>}
  </div>;
}

/** A recoverable failure: what went wrong and, when possible, a retry. */
export function ErrorBanner({ children, onRetry, retryLabel = "Retry", busy = false }: {
  children: ReactNode; onRetry?: () => void; retryLabel?: string; busy?: boolean;
}) {
  return <div className="error-banner" role="alert">
    <TriangleAlert size={16} aria-hidden="true" /><div className="error-banner-message">{children}</div>
    {onRetry && <button type="button" className="button-quiet" disabled={busy} onClick={onRetry}>{retryLabel}</button>}
  </div>;
}
