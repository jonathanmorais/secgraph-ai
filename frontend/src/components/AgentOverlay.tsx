import { Core } from "cytoscape";
import { useEffect } from "react";
import { ActiveAgent, AgentType } from "../hooks/useAgentActivity";
import { AGENT_COLORS, syncAgentsToCy } from "../overlay/agentSync";

interface Props {
  cy: Core | null;
  agents: Record<string, ActiveAgent>;
  connected?: boolean;
}

/** Camada efêmera: desenha agents como losangos tracejados ligados aos alvos.
 * Toda a manipulação do Cytoscape vive em syncAgentsToCy (testável headless). */
export function AgentOverlay({ cy, agents, connected }: Props) {
  useEffect(() => {
    if (!cy) return;
    syncAgentsToCy(cy, agents);
  }, [cy, agents]);

  const counts = Object.values(agents).reduce<Record<string, number>>((acc, a) => {
    acc[a.agent_type] = (acc[a.agent_type] ?? 0) + 1;
    return acc;
  }, {});
  const types: AgentType[] = ["collector", "llm_query", "path_engine", "user_session"];

  return (
    <div className="agent-legend">
      <div className="agent-legend-head">
        <span className={`dot ${connected ? "on" : "off"}`} />
        Agents ativos
      </div>
      {types.map((t) => (
        <div key={t} className="agent-legend-row">
          <span className="swatch" style={{ background: AGENT_COLORS[t] }} />
          <span className="lbl">{t}</span>
          <span className="cnt">{counts[t] ?? 0}</span>
        </div>
      ))}
    </div>
  );
}
