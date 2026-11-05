import { GraphData } from "../api/client";
import { badges, displayName } from "../presenter";

export function TableView({ data }: { data: GraphData }) {
  const rows = data.nodes;
  if (!rows.length) {
    return <div className="canvas-empty">Sem dados. Rode o sync AWS.</div>;
  }
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Tipo</th>
            <th>Recurso</th>
            <th>Riscos</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((n) => {
            const bs = badges(n);
            return (
              <tr key={n.id}>
                <td>{n.label}</td>
                <td>{displayName(n)}</td>
                <td style={{ whiteSpace: "normal" }}>
                  {bs.length === 0 ? (
                    <span style={{ color: "var(--muted)" }}>—</span>
                  ) : (
                    <span style={{ display: "inline-flex", flexWrap: "wrap", gap: 4 }}>
                      {bs.map((b, i) => (
                        <span key={i} className={`badge ${b.tone}`}>
                          {b.text}
                        </span>
                      ))}
                    </span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
