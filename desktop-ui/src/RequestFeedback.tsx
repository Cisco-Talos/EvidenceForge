import { LoaderCircle } from "lucide-react";

export interface RequestState {
  pending: boolean;
  error?: string;
  completedAt?: number;
}

export function requestTime(value: number): string {
  return new Date(value * 1000).toLocaleString(undefined, {
    month: "short", day: "numeric", hour: "numeric", minute: "2-digit", second: "2-digit",
  });
}

export function RequestSpinner() {
  return <LoaderCircle size={16} className="request-spinner" aria-hidden="true" />;
}

/** Feedback for an in-place request, separate from the outcome of the data it returns. */
export function RequestFeedback({ pending, label, error, completedAt, completedLabel = "Updated", previousLabel }: RequestState & {
  label: string; completedLabel?: string; previousLabel?: string;
}) {
  return <div className="request-feedback">
    {pending ? <p className="request-progress" role="status"><RequestSpinner />{label}</p>
      : error ? <p className="error-text" role="alert">{error}</p>
      : completedAt ? <p className="muted small" role="status">{completedLabel} {requestTime(completedAt)}</p> : null}
    {(pending || error) && previousLabel && <p className="muted small">{previousLabel}</p>}
  </div>;
}
