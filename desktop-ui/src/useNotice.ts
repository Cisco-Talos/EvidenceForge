import { useCallback, useEffect, useState } from "react";

/** An optional follow-up offered in a notice, such as revealing an exported file. */
export interface NoticeAction { label: string; run: () => void }
export interface Notice { message: string; kind: "info" | "error"; action?: NoticeAction }

export function useNotice() {
  const [notice, setNotice] = useState<Notice | null>(null);
  const showNotice = useCallback((message: string, action?: NoticeAction) => setNotice({ message, kind: "info", action }), []);
  const showError = useCallback((message: string) => setNotice({ message, kind: "error" }), []);
  const dismiss = useCallback(() => setNotice(null), []);

  useEffect(() => {
    if (notice?.kind !== "info") return;
    // Leave time to act on a follow-up such as Reveal in Finder.
    const timer = setTimeout(dismiss, notice.action ? 9000 : 5000);
    return () => clearTimeout(timer);
  }, [notice, dismiss]);

  return { notice, showNotice, showError, dismiss };
}
