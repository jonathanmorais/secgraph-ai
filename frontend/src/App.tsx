import { Core } from "cytoscape";
import { useCallback, useMemo, useState } from "react";
import { GraphData, Node, PathEdge } from "./api/client";
import { AgentOverlay } from "./components/AgentOverlay";
import { BlastRadius } from "./components/BlastRadius";
import { Chat } from "./components/Chat";
import { GraphViewer } from "./components/GraphViewer";
import { NodeDetail, blastIdentOf } from "./components/NodeDetail";
import { TableView } from "./components/TableView";
import { useAgentActivity } from "./hooks/useAgentActivity";
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
  const [drillEc2, setDrillEc2] = useState<Node | null>(null);
  const [drillData, setDrillData] = useState<GraphData | null>(null);
  const [cy, setCy] = useState<Core | null>(null);
  const [blastIdent, setBlastIdent] = useState<string | null>(null);
  const { agents, connected, sendBrowse } = useAgentActivity();

  const IDENTITY_LABELS = ["IAMUser", "IAMRole", "EC2Instance"];
  const handleNodeContext = useCallback((n: Node) => {
    if (IDENTITY_LABELS.includes(n.label)) {
      setBlastIdent(blastIdentOf(n));
    }
  }, []);

  const mergedData = useMemo<GraphData>(() => drillData ?? data, [data, drillData]);

  const enterDrill = useCallback(async (ec2: Node) => {
    const { fetchEc2Subgraph } = await import("./api/client");
    const sg = await fetchEc2Subgraph(ec2.properties.instance_id as string || ec2.id);
    setDrillEc2(ec2);
    setDrillData(sg);
    setHighlight([]);
    setPathEdges([]);
    setLayout("breadthfirst");
  }, []);

  const exitDrill = useCallback(() => {
    setDrillEc2(null);
    setDrillData(null);
    setHighlight([]);
    setPathEdges([]);
    setLayout("cose");
    setSelected(null);
  }, []);

  const handleNodeClick = useCallback((n: Node) => {
    setSelected(n);
    sendBrowse([n.id]);
    if (n.label === "EC2Instance" && !drillEc2) {
      enterDrill(n);
    }
  }, [drillEc2, enterDrill, sendBrowse]);

  const cycleLayout = () => {
    const i = LAYOUTS.indexOf(layout);
    setLayout(LAYOUTS[(i + 1) % LAYOUTS.length]);
  };

  return (
    <div className="layout">
      <div className="header">
        <span className="brand">GraphSec</span>
        <span className="meta">
          {loading ? "carregando…" : `${mergedData.nodes.length} nós · ${mergedData.edges.length} relações`}
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
            {mergedData.nodes.length} nós, {mergedData.edges.length} rels
          </span>
        </div>

        <div className="canvas">
          {error && <div className="canvas-empty" style={{ color: "var(--danger)" }}>{error}</div>}
          {!error && mergedData.nodes.length === 0 && (
            <div className="canvas-empty">Grafo vazio — rode o sync AWS para popular.</div>
          )}
          {tab === "graph" ? (
            <>
              <GraphViewer
                data={mergedData}
                highlight={highlight}
                pathEdges={pathEdges}
                layout={layout}
                onNodeClick={handleNodeClick}
                onNodeContext={handleNodeContext}
                onCyReady={setCy}
              />
              <AgentOverlay cy={cy} agents={agents} connected={connected} />
              <BlastRadius cy={cy} ident={blastIdent} onClose={() => setBlastIdent(null)} />
              {drillEc2 && (
                <div className="drill-banner">
                  <button className="btn" onClick={exitDrill}>← Voltar ao grafo AWS</button>
                  <span className="drill-title">
                    Workloads K8s em <strong>{(drillEc2.properties.instance_id as string) || drillEc2.id}</strong>
                  </span>
                </div>
              )}
              <NodeDetail
                node={selected}
                drillMode={!!drillEc2}
                onClose={() => setSelected(null)}
                onBlastRadius={(id) => {
                  if (drillEc2) exitDrill();
                  setSelected(null);
                  setBlastIdent(id);
                }}
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
            <TableView data={mergedData} />
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
