import { useResolvedTheme } from "./theme";

/** The full EvidenceForge logo, with the wordmark color matched to the current theme. */
export function BrandLogo({ className }: { className: string }) {
  const theme = useResolvedTheme();
  return <img className={className} src={`/brand/evidenceforge-${theme}.png`} alt="EvidenceForge" />;
}

/** Compact mark and wordmark for the sidebar, or the full logo for About. */
export function StudioBrand({ className = "brand", compact = false }: { className?: string; compact?: boolean }) {
  if (compact) {
    return <div className={`${className} brand-compact`}>
      <img className="brand-mark" src="/brand/icon-32.png" alt="" />
      <span className="brand-wordmark"><strong>EvidenceForge</strong><small>Studio</small></span>
    </div>;
  }
  return <div className={className}>
    <BrandLogo className="brand-logo" />
    <small>STUDIO</small>
  </div>;
}
