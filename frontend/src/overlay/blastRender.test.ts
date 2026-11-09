import cytoscape, { Core } from "cytoscape";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { BlastReport, clearBlastRadius, renderBlastRadius } from "./blastRender";

function report(over: Partial<BlastReport> = {}): BlastReport {
  return {
    compromised_identity: "arn:user/dev",
    graph_nodes: [
      { id: "arn:user/dev", label: "IAMUser", criticality: "origin" },
      { id: "arn:s3:::pii", label: "S3Bucket", criticality: "critical" },
    ],
    graph_edges: [{ source: "arn:user/dev", target: "arn:s3:::pii", relation: "ALLOWS" }],
    resources: [{ uid: "arn:s3:::pii", hops: 1, criticality: "critical" }],
    max_depth_reached: 1,
    ...over,
  };
}

describe("renderBlastRadius", () => {
  let cy: Core;

  beforeEach(() => {
    cy = cytoscape({ headless: true });
    cy.add([
      { group: "nodes", data: { id: "arn:user/dev" } },
      { group: "nodes", data: { id: "arn:s3:::pii" } },
      { group: "nodes", data: { id: "unrelated" } },
    ]);
  });
  afterEach(() => cy.destroy());

  it("marca a origem e esmaece nós fora do blast", () => {
    renderBlastRadius(cy, report());
    expect(cy.getElementById("arn:user/dev").hasClass("blast-origin")).toBe(true);
    expect(cy.getElementById("arn:s3:::pii").hasClass("blast-reached")).toBe(true);
    expect(cy.getElementById("arn:s3:::pii").hasClass("blast-critical")).toBe(true);
    expect(cy.getElementById("unrelated").hasClass("blast-dimmed")).toBe(true);
    expect(cy.getElementById("blast-arn:user/dev-arn:s3:::pii").nonempty()).toBe(true);
  });

  it("adiciona nós alcançados que não estavam no grafo", () => {
    const r = report({
      graph_nodes: [
        { id: "arn:user/dev", label: "IAMUser", criticality: "origin" },
        { id: "arn:rds/novo", label: "RDSInstance", criticality: "high" },
      ],
      resources: [{ uid: "arn:rds/novo", hops: 2, criticality: "high" }],
      max_depth_reached: 2,
    });
    renderBlastRadius(cy, r);
    const added = cy.getElementById("arn:rds/novo");
    expect(added.nonempty()).toBe(true);
    expect(added.hasClass("blast-added")).toBe(true);
  });

  it("revela recursos camada a camada (por hop)", () => {
    vi.useFakeTimers();
    try {
      renderBlastRadius(cy, report(), 300);
      // antes do timer: recurso ainda invisível (sem blast-visible)
      expect(cy.getElementById("arn:s3:::pii").hasClass("blast-visible")).toBe(false);
      vi.advanceTimersByTime(301);
      expect(cy.getElementById("arn:s3:::pii").hasClass("blast-visible")).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it("clearBlastRadius remove nós adicionados, arestas e classes", () => {
    const r = report({
      graph_nodes: [
        { id: "arn:user/dev", label: "IAMUser", criticality: "origin" },
        { id: "arn:rds/novo", label: "RDSInstance", criticality: "high" },
      ],
      graph_edges: [{ source: "arn:user/dev", target: "arn:rds/novo", relation: "ALLOWS" }],
      resources: [{ uid: "arn:rds/novo", hops: 1, criticality: "high" }],
    });
    renderBlastRadius(cy, r);
    clearBlastRadius(cy);
    expect(cy.getElementById("arn:rds/novo").empty()).toBe(true); // era adicionado
    expect(cy.getElementById("arn:user/dev").hasClass("blast-origin")).toBe(false);
    expect(cy.getElementById("unrelated").hasClass("blast-dimmed")).toBe(false);
    expect(cy.edges().filter((e) => e.hasClass("blast-edge")).length).toBe(0);
  });
});
