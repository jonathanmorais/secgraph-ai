import { Core } from "cytoscape";
import { useEffect } from "react";
import { BlastResource } from "../api/client";
import { useBlastRadius } from "../hooks/useBlastRadius";
import { clearBlastRadius, renderBlastRadius } from "../overlay/blastRender";

const CRIT_ICON: Record<string, string> = {
  critical: "🔴",
  high: "🟠",
  medium: "🟡",
  low: "⚪",
};

interface Props {
  cy: Core | null;
  ident: string | null;
  onClose: () => void;
}

export function BlastRadius({ cy, ident, onClose }: Props) {
  const { report, loading, error } = useBlastRadius(ident);

  useEffect(() => {
    if (!cy || !report) return;
    const timers = renderBlastRadius(cy, report);
    return () => {
      timers.forEach(clearTimeout);
      if (cy && !cy.destroyed()) clearBlastRadius(cy);
    };
  }, [cy, report]);

  if (!ident) return null;

  const focusResource = (r: BlastResource) => {
    if (!cy || cy.destroyed()) return;
    const node = cy.getElementById(r.uid);
    if (node.nonempty()) {
      cy.animate({ center: { eles: node }, zoom: 1.4 }, { duration: 350 });
      node.addClass("blast-focus");
      setTimeout(() => node.removeClass("blast-focus"), 1200);
    }
  };

  const exportJson = () => {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `blast-${report.compromised_identity.split("/").pop()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="blast-panel">
      <button className="close" onClick={onClose}>
        ×
      </button>
      <div className="blast-head">
        💥 Blast Radius
        <div className="blast-identity">
          {ident.split("/").pop()}
        </div>
      </div>

      {loading && <div className="nd-muted">computando…</div>}
      {error && <div className="blast-err">{error}</div>}

      {report && (
        <>
          <div className="blast-meta">
            computado em {report.computation_time_ms}ms
            {report.partial && " (parcial)"}
          </div>

          <div className="blast-section">IMPACTO</div>
          <ul className="blast-metrics">
            <li>● {report.total_resources_reached} recursos alcançáveis</li>
            <li>● {report.total_roles_escalatable} roles escaláveis</li>
            {report.pii_data_exposed && (
              <li className="danger">🔴 Dados sensíveis expostos (PII/financeiro)</li>
            )}
            <li>● Profundidade máxima: {report.max_depth_reached} hops</li>
          </ul>

          {report.resources.length > 0 && (
            <>
              <div className="blast-section">RECURSOS ALCANÇADOS</div>
              <div className="blast-list">
                {report.resources.map((r) => (
                  <button
                    key={r.uid}
                    className="blast-res"
                    onClick={() => focusResource(r)}
                    title={`via ${r.path_via.join(" → ")}`}
                  >
                    <span className="ic">{CRIT_ICON[r.criticality] ?? "⚪"}</span>
                    <span className="nm">{r.name}</span>
                    <span className="hp">{r.hops}h</span>
                    {r.data_classification &&
                      r.data_classification !== "unknown" && (
                        <span className="badge danger">{r.data_classification}</span>
                      )}
                  </button>
                ))}
              </div>
            </>
          )}

          {report.escalation_paths.length > 0 && (
            <>
              <div className="blast-section">CADEIA DE ESCALAÇÃO</div>
              <div className="blast-list">
                {report.escalation_paths.map((e) => (
                  <div key={e.uid} className="blast-esc">
                    {e.assumption_chain
                      .map((c) => c.split("/").pop())
                      .join(" → ")}
                    <span className="hp">{e.chain_length}h</span>
                  </div>
                ))}
              </div>
            </>
          )}

          <div className="blast-actions">
            <button className="btn" onClick={exportJson}>
              Exportar
            </button>
          </div>
          <div className="blast-contain">
            Contenção: revogar as credenciais de{" "}
            <strong>{ident.split("/").pop()}</strong> elimina acesso a{" "}
            {report.total_resources_reached} recurso(s) e{" "}
            {report.total_roles_escalatable} escalação(ões).
          </div>
        </>
      )}
    </div>
  );
}
