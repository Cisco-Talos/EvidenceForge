import { useResolvedTheme } from "./theme";

/** The full EvidenceForge logo, with the wordmark color matched to the current theme. */
export function BrandLogo({ className }: { className: string }) {
  const theme = useResolvedTheme();
  return <img className={className} src={`/brand/evidenceforge-${theme}.png`} alt="EvidenceForge" />;
}

/** The sidebar brand (compact) or the larger About logo; both use the full EvidenceForge artwork. */
export function StudioBrand({ className = "brand", compact = false }: { className?: string; compact?: boolean }) {
  if (compact) {
    // The full docs/logos artwork, sized to stay legible without crowding the navigation; narrow
    // windows switch to the high-resolution anvil mark alone.
    return <div className={`${className} brand-compact`}>
      <BrandLogo className="brand-logo-sidebar" />
      <img className="brand-mark" src="/brand/mark-256.png" alt="" />
      <small>STUDIO</small>
    </div>;
  }
  return <div className={className}>
    <BrandLogo className="brand-logo" />
    <small>STUDIO</small>
  </div>;
}
