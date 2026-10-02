import { useId, type ReactNode } from "react";
import { ChevronRight, TriangleAlert } from "lucide-react";
import type { SectionSummary } from "./workspaceSummaries";

export function HeaderSummary({ summary }: { summary: SectionSummary }) {
  return <span className="header-summary"><span className="summary-outcome">{summary.headline}</span><span className="summary-context" title={summary.detail}>{summary.detail}</span>{summary.inputs && summary.inputs.state !== "current" && <span className="summary-inputs" title={summary.inputs.detail}><TriangleAlert size={12} aria-hidden="true" />{summary.inputs.label}</span>}</span>;
}

/** Workspace headers remain useful even when their optional details are folded. */
export function WorkspaceSection({ title, summary, icon, actions, expanded, onToggle, children, footer }: {
  title: string; summary: ReactNode; icon?: ReactNode; actions?: ReactNode; expanded: boolean;
  onToggle: () => void; children?: ReactNode; footer?: ReactNode;
}) {
  const bodyId = useId();
  const summaryId = useId();
  return <section className="workspace-section" aria-label={title}>
    <header className="workspace-section-header">
      {children ? <button className="workspace-section-toggle" aria-label={title} aria-describedby={summaryId} aria-expanded={expanded} aria-controls={bodyId} onClick={onToggle}>
        <ChevronRight size={17} className={`disclosure-chevron ${expanded ? "expanded" : ""}`} />{icon}<span><strong>{title}</strong><small id={summaryId}>{summary}</small></span>
      </button> : <div className="workspace-section-static">{icon}<span><strong>{title}</strong><small id={summaryId}>{summary}</small></span></div>}
      <div className="workspace-section-actions">{actions}</div>
    </header>
    {footer}
    {children && <div id={bodyId} hidden={!expanded} className="workspace-section-body">{expanded && children}</div>}
  </section>;
}
