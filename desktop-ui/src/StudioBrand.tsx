export function StudioBrand({ className = "brand", compact = false }: { className?: string; compact?: boolean }) {
  return <div className={className}>
    <img className="brand-logo" src="/brand/evidenceforge-dark.png" alt="EvidenceForge" />
    {compact && <img className="brand-mini" src="/brand/icon-32.png" alt="" />}
    <small>STUDIO</small>
  </div>;
}
