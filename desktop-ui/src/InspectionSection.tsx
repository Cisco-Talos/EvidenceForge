import { useId, useState, type ReactNode } from "react";
import { ChevronRight } from "lucide-react";

/** Counted inspection details that stay compact until the user opens them. */
export function InspectionSection({ title, count, summary, actions, children, className = "" }: {
  title: string; count?: string; summary?: string; actions?: ReactNode; children: ReactNode; className?: string;
}) {
  const [expanded, setExpanded] = useState(false);
  const bodyId = useId();
  const summaryId = useId();
  return <section className={`surface inspection-section ${className}`}>
    <header className="inspection-heading"><h2><button className="inspection-toggle" aria-label={[title, count].filter(Boolean).join(" ")} aria-describedby={summary ? summaryId : undefined} aria-expanded={expanded} aria-controls={bodyId} onClick={() => setExpanded(!expanded)}><ChevronRight size={17} className="disclosure-chevron" /><span className="inspection-label"><span>{title}</span>{summary && <small id={summaryId} className="inspection-summary">{summary}</small>}</span>{count && <small>{count}</small>}</button></h2>{actions}</header>
    <div id={bodyId} hidden={!expanded}>{expanded && <div className="inspection-content">{children}</div>}</div>
  </section>;
}
