import { useId, useState, type ReactNode } from "react";
import { ChevronRight } from "lucide-react";

/** Counted inspection details that stay compact until the user opens them. */
export function InspectionSection({ title, count, actions, children, className = "" }: {
  title: string; count?: string; actions?: ReactNode; children: ReactNode; className?: string;
}) {
  const [expanded, setExpanded] = useState(false);
  const bodyId = useId();
  return <section className={`surface inspection-section ${className}`}>
    <header className="inspection-heading"><h2><button className="inspection-toggle" aria-label={[title, count].filter(Boolean).join(" ")} aria-expanded={expanded} aria-controls={bodyId} onClick={() => setExpanded(!expanded)}><ChevronRight size={17} className="disclosure-chevron" /><span>{title}</span>{count && <small>{count}</small>}</button></h2>{actions}</header>
    <div id={bodyId} hidden={!expanded}>{expanded && <div className="inspection-content">{children}</div>}</div>
  </section>;
}
