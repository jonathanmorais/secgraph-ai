import { useEffect, useState } from "react";
import { BlastReport, fetchBlastRadius } from "../api/client";

/** Busca o Blast Radius de um identity (ARN/uid/nome). Null limpa o estado. */
export function useBlastRadius(ident: string | null) {
  const [report, setReport] = useState<BlastReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!ident) {
      setReport(null);
      setError(null);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError(null);
    fetchBlastRadius(ident)
      .then((data) => {
        if (!cancelled) setReport(data);
      })
      .catch((e) => {
        if (!cancelled) setError(String(e));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [ident]);

  return { report, loading, error };
}
