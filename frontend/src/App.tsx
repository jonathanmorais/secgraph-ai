import { useState } from "react";
import { Node, PathEdge } from "./api/client";
import { Chat } from "./components/Chat";
import { GraphViewer } from "./components/GraphViewer";
import { NodeDetail } from "./components/NodeDetail";
import { TableView } from "./components/TableView";
import { useGraph } from "./hooks/useGraph";

const LAYOUTS = ["cose", "breadthfirst", "concentric", "circle", "grid"];
const DEFAULT_QUERY = "MATCH (n)-[r]->(m) RETURN n, r, m";

export default function App() {
  const { data, loading, error, reload } = useGraph();
  const [selected, setSelected] = useState<Node | null>(null);
  const [highlight, setHighlight] = useState<string[]>([]);
  const [pathEdges, setPathEdges] = useState<PathEdge[]>([]);
  const [tab, setTab] = useState<"graph" | "table">("graph");
  const [query, setQuery] = useState(DEFAULT_QUERY);
  const [layout, setLayout] = useState("cose");

  const cycleLayout = () => {
    const i = LAYOUTS.indexOf(layout);
    setLayout(LAYOUTS[(i + 1) % LAYOUTS.length]);
  };

  return (
    <div className="layout">
      <div className="header">
        <span className="brand">GraphSec</span>
        <span className="meta">
          {loading ? "carregando…" : `${data.nodes.length} nós · ${data.edges.length} relações`}
        </span>
        <span className="spacer" />
        <button className="btn" onClick={reload}>
          Recarregar
        </button>
      </div>

      <div className="graph-pane">
        <div className="query-bar">
          <span className="query-text">{highlightCypher(query)}</span>
          <span className="pill success">pronto</span>
        </div>

        <div className="sub-toolbar">
          <div className="tabs">
            <button className={tab === "graph" ? "active" : ""} onClick={() => setTab("graph")}>
              Graph
            </button>
            <button className={tab === "table" ? "active" : ""} onClick={() => setTab("table")}>
              Table
            </button>
          </div>
          <span className="counter">
            {data.nodes.length} nós, {data.edges.length} rels
          </span>
        </div>

        <div className="canvas">
          {error && <div className="canvas-empty" style={{ color: "var(--danger)" }}>{error}</div>}
          {!error && data.nodes.length === 0 && (
            <div className="canvas-empty">Grafo vazio — rode o sync AWS para popular.</div>
          )}
          {tab === "graph" ? (
            <>
              <GraphViewer
                data={data}
                highlight={highlight}
                pathEdges={pathEdges}
                layout={layout}
                onNodeClick={setSelected}
              />
              <NodeDetail
                node={selected}
                onClose={() => setSelected(null)}
                onTracePath={(ids, edges) => {
                  setHighlight(ids);
                  setPathEdges(edges);
                }}
              />
              <div className="bottom-left">
                <button className="btn" onClick={cycleLayout}>
                  Layout: {layout}
                </button>
              </div>
            </>
          ) : (
            <TableView data={data} />
          )}
        </div>
      </div>

      <div className="sidebar">
        <Chat
          onHighlight={(ids, edges) => {
            setHighlight(ids);
            setPathEdges(edges);
          }}
          onQuery={setQuery}
        />
      </div>
    </div>
  );
}

const KEYWORDS = new Set([
  "MATCH", "RETURN", "WHERE", "AND", "OR", "NOT", "WITH", "LIMIT",
  "ORDER", "BY", "AS", "CONTAINS", "IN", "ANY", "shortestPath",
]);

function highlightCypher(q: string): JSX.Element {
  const tokens = q.split(/(\s+)/);
  return (
    <>
      {tokens.map((t, i) =>
        KEYWORDS.has(t) ? (
          <span key={i} className="kw">
            {t}
          </span>
        ) : (
          <span key={i}>{t}</span>
        )
      )}
    </>
  );
}
