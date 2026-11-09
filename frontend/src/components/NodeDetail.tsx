import { useEffect, useState } from "react";
import { Node, PathEdge, Workload, fetchEc2AttackPath, fetchEc2Workloads } from "../api/client";
import { badges, displayName, props } from "../presenter";

const IDENTITY_LABELS = ["IAMUser", "IAMRole", "EC2Instance"];

/** Identificador sem barras para a URL do blast radius (evita 404 de routing
 * com ARNs, que contêm '/'). O engine resolve por nome/instance_id. */
export function blastIdentOf(node: Node): string {
  const p = node.properties as Record<string, unknown>;
  return String(
    p.user_name || p.role_name || p.instance_id || node.id
  );
}

interface Props {
  node: Node | null;
  onClose: () => void;
  onTracePath?: (nodeIds: string[], edges: PathEdge[]) => void;
  onBlastRadius?: (ident: string) => void;
  drillMode?: boolean;
}

export function NodeDetail({ node, onClose, onTracePath, onBlastRadius, drillMode }: Props) {
  const [workloads, setWorkloads] = useState<Workload[]>([]);
  const [loadingWl, setLoadingWl] = useState(false);
  const isEc2 = node?.label === "EC2Instance";
  const isIdentity = !!node && IDENTITY_LABELS.includes(node.label);
  const instanceId = (node?.properties?.instance_id as string) || node?.id || "";

  useEffect(() => {
    if (!isEc2 || !instanceId) {
      setWorkloads([]);
      return;
    }
    setLoadingWl(true);
    fetchEc2Workloads(instanceId)
      .then((d) => setWorkloads(d.workloads || []))
      .catch(() => setWorkloads([]))
      .finally(() => setLoadingWl(false));
  }, [isEc2, instanceId]);

  if (!node) return null;
  const bs = badges(node);
  const rows = props(node);

  const tracePath = async () => {
    const d = await fetchEc2AttackPath(instanceId);
    onTracePath?.(d.node_ids || [], d.path_edges || []);
  };

  return (
    <div className="node-detail">
      <button className="close" onClick={onClose}>
        ×
      </button>
      <div className="nd-label">{node.label}</div>
      <h3>{displayName(node)}</h3>

      {bs.length > 0 && (
        <div className="nd-badges">
          {bs.map((b, i) => (
            <span key={i} className={`badge ${b.tone}`}>
              {b.text}
            </span>
          ))}
        </div>
      )}

      <table>
        <tbody>
          {rows.map((r) => (
            <tr key={r.key}>
              <td className="k">{r.key}</td>
              <td className="v">{r.value}</td>
            </tr>
          ))}
        </tbody>
      </table>

      {isIdentity && onBlastRadius && (
        <button
          className="btn primary nd-trace"
          onClick={() => onBlastRadius(blastIdentOf(node))}
        >
          💥 Calcular Blast Radius
        </button>
      )}

      {isEc2 && (
        <div className="nd-workloads">
          <div className="nd-section">Containers rodando</div>
          {loadingWl && <div className="nd-muted">carregando…</div>}
          {!loadingWl && workloads.length === 0 && (
            <div className="nd-muted">Nenhum workload. Rode o sync K8s.</div>
          )}
          {workloads.map((w, i) => (
            <div key={i} className="nd-wl">
              <div className="nd-wl-img">{w.image}</div>
              <div className="nd-wl-meta">
                <span className="nd-muted">
                  {w.namespace}/{w.pod}
                </span>
                {w.critical && w.critical > 0 ? (
                  <span className="badge danger">{w.critical} crítica(s)</span>
                ) : w.cve_count && w.cve_count > 0 ? (
                  <span className="badge warn">{w.cve_count} CVE(s)</span>
                ) : (
                  <span className="nd-muted">sem CVE</span>
                )}
              </div>
            </div>
          ))}
          {workloads.length > 0 && drillMode && (
            <button className="btn primary nd-trace" onClick={tracePath}>
              Traçar path de privilégio →
            </button>
          )}
        </div>
      )}
    </div>
  );
}
