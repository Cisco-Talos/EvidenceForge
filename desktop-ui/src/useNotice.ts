import { useCallback, useEffect, useState } from "react";

export function useNotice() {
  const [notice, setNotice] = useState<{ message: string; kind: "info" | "error" } | null>(null);
  const showNotice = useCallback((message: string) => setNotice({ message, kind: "info" }), []);
  const showError = useCallback((message: string) => setNotice({ message, kind: "error" }), []);
  const dismiss = useCallback(() => setNotice(null), []);

  useEffect(() => {
    if (notice?.kind !== "info") return;
    const timer = setTimeout(dismiss, 5000);
    return () => clearTimeout(timer);
  }, [notice, dismiss]);

  return { notice, showNotice, showError, dismiss };
}
