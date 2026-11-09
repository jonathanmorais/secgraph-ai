import { Core } from "cytoscape";

export interface BlastGraphNode {
  id: string;
  label: string;
  criticality: string; // origin | path | critical | high | medium | low
}
export interface BlastGraphEdge {
  source: string;
  target: string;
  relation: string;
}
export interface BlastResource {
  uid: string;
  hops: number;
  criticality: string;
}
export interface BlastReport {
  compromised_identity: string;
  graph_nodes: BlastGraphNode[];
  graph_edges: BlastGraphEdge[];
  resources: BlastResource[];
  max_depth_reached: number;
}

const HOP_DELAY = 300; // ms entre camadas (efeito de onda)

function shortName(uid: string): string {
  const seg = uid.split("/").pop() || uid;
  return seg.length > 22 ? seg.slice(0, 20) + "…" : seg;
}

/** Desenha o blast radius sobre o grafo: nó de origem destacado, recursos
 * revelados camada a camada (por hop) e tudo fora do blast esmaecido.
 * Nunca re-roda o layout. Retorna os timers criados (p/ testes/cleanup). */
export function renderBlastRadius(
  cy: Core,
  report: BlastReport,
  hopDelay: number = HOP_DELAY
): ReturnType<typeof setTimeout>[] {
  if (cy.destroyed()) return [];
  clearBlastRadius(cy);

  const blastIds = new Set<string>([report.compromised_identity]);

  // adiciona/marca nós alcançados
  for (const n of report.graph_nodes) {
    blastIds.add(n.id);
    let ele = cy.getElementById(n.id);
    if (ele.empty()) {
      ele = cy.add({
        group: "nodes",
        data: { id: n.id, label: n.label, name: shortName(n.id) },
        classes: "blast-added",
      });
    }
    if (n.id === report.compromised_identity) {
      ele.addClass("blast-origin");
    } else {
      ele.addClass(`blast-reached blast-${n.criticality}`);
    }
  }

  // arestas do blast
  for (const e of report.graph_edges) {
    const id = `blast-${e.source}-${e.target}`;
    if (cy.getElementById(id).empty()) {
      cy.add({
        group: "edges",
        data: { id, source: e.source, target: e.target, label: e.relation },
        classes: "blast-edge",
      });
    }
  }

  // esmaece tudo que está fora do blast
  cy.elements().forEach((ele) => {
    const id = ele.id();
    const inBlast =
      blastIds.has(id) ||
      ele.hasClass("blast-edge") ||
      (ele.isEdge() && blastIds.has(ele.data("source")) && blastIds.has(ele.data("target")));
    if (!inBlast) ele.addClass("blast-dimmed");
  });

  // revela os recursos camada por camada (hop 1, 2, 3…)
  const timers: ReturnType<typeof setTimeout>[] = [];
  const maxHops = report.max_depth_reached || 1;
  // origem visível imediatamente
  cy.getElementById(report.compromised_identity).addClass("blast-visible");
  for (let hop = 1; hop <= maxHops; hop++) {
    const atHop = report.resources.filter((r) => r.hops === hop).map((r) => r.uid);
    const t = setTimeout(() => {
      if (cy.destroyed()) return;
      for (const uid of atHop) cy.getElementById(uid).addClass("blast-visible");
      // também revela nós intermediários do caminho (path) até esse hop
      cy.nodes(".blast-reached").forEach((n) => {
        n.addClass("blast-visible");
      });
    }, hop * hopDelay);
    timers.push(t);
  }
  return timers;
}

/** Remove todo o overlay de blast (nós adicionados, arestas e classes). */
export function clearBlastRadius(cy: Core): void {
  if (cy.destroyed()) return;
  cy.remove(".blast-added");
  cy.remove(".blast-edge");
  cy.elements().removeClass(
    "blast-origin blast-reached blast-visible blast-dimmed " +
      "blast-critical blast-high blast-medium blast-low blast-path"
  );
}
