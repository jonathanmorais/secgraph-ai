import { Core } from "cytoscape";
import { ActiveAgent, AgentType } from "../hooks/useAgentActivity";

export const AGENT_COLORS: Record<AgentType, string> = {
  collector: "#3b82f6",
  llm_query: "#a78bfa",
  path_engine: "#ef4444",
  user_session: "#22c55e",
  unknown: "#9ca3af",
};

export const AGENT_PREFIX = "agent:";
export const OFFSET = 80; // distância do agent ao centroide dos alvos
export const DECAY_MS = 1000;

/** Ângulo estável por agent (determinístico), pra não "pular" a cada update. */
export function angleFor(id: string): number {
  let h = 0;
  for (let i = 0; i < id.length; i++) h = (h * 31 + id.charCodeAt(i)) | 0;
  return ((h % 360) * Math.PI) / 180;
}

/** Reconcilia os nós-agent efêmeros no grafo Cytoscape SEM re-rodar o layout.
 * Adiciona losangos tracejados perto do centroide dos alvos visíveis e liga
 * arestas tracejadas; agents que sumiram ganham fade-out e são removidos. */
export function syncAgentsToCy(
  cy: Core,
  agents: Record<string, ActiveAgent>,
  decayMs: number = DECAY_MS
): Set<string> {
  if (cy.destroyed()) return new Set();
  const present = new Set<string>();

  for (const a of Object.values(agents)) {
    const targetsInView = a.targets.filter((t) => cy.getElementById(t).nonempty());
    if (targetsInView.length === 0) continue;
    present.add(a.agent_id);

    const color = AGENT_COLORS[a.agent_type] ?? AGENT_COLORS.unknown;
    const nodeId = `${AGENT_PREFIX}${a.agent_id}`;

    let cx = 0;
    let cyc = 0;
    for (const t of targetsInView) {
      const p = cy.getElementById(t).position();
      cx += p.x;
      cyc += p.y;
    }
    cx /= targetsInView.length;
    cyc /= targetsInView.length;
    const ang = angleFor(a.agent_id);
    const pos = { x: cx + Math.cos(ang) * OFFSET, y: cyc + Math.sin(ang) * OFFSET };

    let node = cy.getElementById(nodeId);
    if (node.empty()) {
      node = cy.add({
        group: "nodes",
        data: { id: nodeId, agentLabel: a.agent_type, label: "Agent" },
        classes: "agent-node",
      });
      node.style({ "border-color": color, color });
      node.position(pos);
    } else {
      node.removeClass("agent-decaying");
      node.position(pos);
    }

    for (const t of targetsInView) {
      const edgeId = `agentedge:${a.agent_id}:${t}`;
      if (cy.getElementById(edgeId).empty()) {
        cy.add({
          group: "edges",
          data: { id: edgeId, source: nodeId, target: t },
          classes: "agent-edge",
        }).style({ "line-color": color, "target-arrow-color": color });
      }
    }
  }

  // fade-out dos agents sem atividade recente
  cy.nodes().forEach((n) => {
    const id = n.id();
    if (!id.startsWith(AGENT_PREFIX)) return;
    const agentId = id.slice(AGENT_PREFIX.length);
    if (present.has(agentId) || n.hasClass("agent-decaying")) return;
    n.addClass("agent-decaying");
    cy.edges().forEach((e) => {
      if (e.data("source") === id) e.addClass("agent-decaying");
    });
    setTimeout(() => {
      if (cy.destroyed()) return;
      cy.edges().forEach((e) => {
        if (e.data("source") === id) e.remove();
      });
      cy.getElementById(id).remove();
    }, decayMs);
  });

  return present;
}
