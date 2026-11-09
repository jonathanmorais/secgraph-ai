import cytoscape, { Core } from "cytoscape";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ActiveAgent } from "../hooks/useAgentActivity";
import { syncAgentsToCy } from "./agentSync";

function agent(partial: Partial<ActiveAgent> & { agent_id: string }): ActiveAgent {
  return {
    agent_type: "collector",
    action: "write",
    targets: [],
    lastSeen: Date.now(),
    ...partial,
  };
}

describe("syncAgentsToCy", () => {
  let cy: Core;

  beforeEach(() => {
    cy = cytoscape({ headless: true });
    cy.add([
      { group: "nodes", data: { id: "n1" } },
      { group: "nodes", data: { id: "n2" } },
    ]);
    cy.getElementById("n1").position({ x: 0, y: 0 });
    cy.getElementById("n2").position({ x: 100, y: 0 });
  });

  afterEach(() => cy.destroy());

  it("adiciona nó-agent (losango) e aresta perto do alvo", () => {
    const agents = {
      "collector:aws": agent({ agent_id: "collector:aws", targets: ["n1"] }),
    };
    const present = syncAgentsToCy(cy, agents);

    expect(present.has("collector:aws")).toBe(true);
    const node = cy.getElementById("agent:collector:aws");
    expect(node.nonempty()).toBe(true);
    expect(node.hasClass("agent-node")).toBe(true);
    expect(cy.getElementById("agentedge:collector:aws:n1").nonempty()).toBe(true);
  });

  it("posiciona o agent no centroide de múltiplos alvos (com offset)", () => {
    const agents = {
      p: agent({ agent_id: "p", agent_type: "path_engine", targets: ["n1", "n2"] }),
    };
    syncAgentsToCy(cy, agents);
    const pos = cy.getElementById("agent:p").position();
    // centroide dos alvos é (50, 0); offset de 80px desloca a partir daí
    const dist = Math.hypot(pos.x - 50, pos.y - 0);
    expect(dist).toBeCloseTo(80, 5);
    expect(cy.getElementById("agentedge:p:n1").nonempty()).toBe(true);
    expect(cy.getElementById("agentedge:p:n2").nonempty()).toBe(true);
  });

  it("ignora agents cujos alvos não estão no grafo atual", () => {
    const agents = {
      a: agent({ agent_id: "a", agent_type: "llm_query", targets: ["ghost"] }),
    };
    const present = syncAgentsToCy(cy, agents);
    expect(present.size).toBe(0);
    expect(cy.getElementById("agent:a").empty()).toBe(true);
  });

  it("faz fade-out e remove agents que somem", () => {
    vi.useFakeTimers();
    try {
      syncAgentsToCy(cy, { a: agent({ agent_id: "a", targets: ["n1"] }) }, 1000);
      expect(cy.getElementById("agent:a").nonempty()).toBe(true);

      // agent some do mapa -> ganha classe de decaimento, depois é removido
      syncAgentsToCy(cy, {}, 1000);
      expect(cy.getElementById("agent:a").hasClass("agent-decaying")).toBe(true);

      vi.advanceTimersByTime(1001);
      expect(cy.getElementById("agent:a").empty()).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it("reaproveita o nó-agent entre updates (não duplica)", () => {
    const a1 = { a: agent({ agent_id: "a", targets: ["n1"] }) };
    syncAgentsToCy(cy, a1);
    syncAgentsToCy(cy, { a: agent({ agent_id: "a", targets: ["n1", "n2"] }) });
    const nodes = cy.nodes().filter((n) => n.id() === "agent:a");
    expect(nodes.length).toBe(1);
  });
});
