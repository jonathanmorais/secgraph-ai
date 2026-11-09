import cytoscape, { Core, ElementDefinition, LayoutOptions } from "cytoscape";
import { useEffect, useRef } from "react";
import { GraphData, Node, PathEdge } from "../api/client";
import { iconFor } from "../icons";

const RISK_LABELS = new Set(["Finding", "InternetGateway"]);

function nodeColor(n: any): string {
  const label = n.data("label");
  const sev = n.data("severity") || n.data("worst_severity");
  if (label === "CVE" || label === "ContainerImage") {
    if (sev === "CRITICAL") return "#dc2626";
    if (sev === "HIGH") return "#ea580c";
    if (sev === "MEDIUM") return "#d97706";
    if ((n.data("cve_count") || 0) > 0) return "#ca8a04";
  }
  if (n.data("exposes_world") || n.data("is_public") || n.data("publicly_accessible")) return "#dc2626";
  if (n.data("has_mfa") === false) return "#ea580c";
  if (RISK_LABELS.has(label)) return "#dc2626";
  return "#374151";
}

interface Props {
  data: GraphData;
  highlight?: string[];
  pathEdges?: PathEdge[];
  layout?: string;
  onNodeClick?: (node: Node) => void;
  onNodeContext?: (node: Node) => void;
  onCyReady?: (cy: Core | null) => void;
}

export function GraphViewer({
  data,
  highlight = [],
  pathEdges = [],
  layout = "cose",
  onNodeClick,
  onNodeContext,
  onCyReady,
}: Props) {
  const ref = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);

  useEffect(() => {
    if (!ref.current) return;

    const elements: ElementDefinition[] = [
      ...data.nodes.map((n) => ({
        data: {
          id: n.id,
          label: n.label,
          name: shortName(n),
          ...n.properties,
        },
      })),
      ...data.edges.map((e, i) => ({
        data: { id: `e${i}`, source: e.source, target: e.target, label: e.type },
      })),
    ];

    const cy = cytoscape({
      container: ref.current,
      elements,
      wheelSensitivity: 1.5,
      style: [
        {
          selector: "node",
          style: {
            "background-color": "#ffffff",
            "background-image": (n: any) => iconFor(n.data("label"), nodeColor(n)),
            "background-fit": "none",
            "background-width": "22px",
            "background-height": "22px",
            "background-position-x": "50%",
            "background-position-y": "50%",
            "border-width": 1.5,
            "border-color": nodeColor,
            width: 40,
            height: 40,
            shape: "round-rectangle",
          },
        },
        {
          selector: "edge",
          style: {
            width: 1.2,
            "line-color": "#c4c4bd",
            "target-arrow-color": "#c4c4bd",
            "target-arrow-shape": "triangle",
            "arrow-scale": 0.9,
            "curve-style": "bezier",
            label: "data(label)",
            "font-size": 8.5,
            color: "#9a9a92",
            "text-background-color": "#fafaf7",
            "text-background-opacity": 1,
            "text-background-padding": "2px",
          },
        },
        {
          selector: ".highlight",
          style: {
            "border-color": "#f97316",
            "border-width": 3,
            "background-color": "#fff7ed",
          },
        },
        {
          selector: "node.path-node",
          style: {
            "background-image": (n: any) => iconFor(n.data("label"), "#15803d"),
            "border-color": "#16a34a",
            "border-width": 3,
            "background-color": "#f0fdf4",
            width: 46,
            height: 46,
            "z-index": 100,
          },
        },
        {
          selector: "edge.path-edge",
          style: {
            "line-color": "#16a34a",
            "target-arrow-color": "#16a34a",
            width: 3,
            "arrow-scale": 1.1,
            color: "#15803d",
            "font-weight": "bold",
            "z-index": 100,
          },
        },
        {
          selector: ".agent-node",
          style: {
            shape: "diamond",
            "border-style": "dashed",
            "border-width": 2,
            "background-color": "transparent",
            "background-image": "none",
            opacity: 0.85,
            width: 30,
            height: 30,
            label: "data(agentLabel)",
            "font-size": 8,
            "text-valign": "top",
            "text-margin-y": -2,
            "z-index": 200,
          },
        },
        {
          selector: ".agent-edge",
          style: {
            "line-style": "dashed",
            "line-dash-pattern": [6, 3],
            opacity: 0.6,
            width: 1.5,
            "target-arrow-shape": "none",
            label: "",
            "z-index": 150,
          },
        },
        {
          selector: ".agent-decaying",
          style: {
            opacity: 0,
            "transition-property": "opacity",
            "transition-duration": "1000ms" as unknown as number,
          },
        },
        // ----- Blast Radius -----
        {
          selector: ".blast-origin",
          style: {
            "background-color": "#dc2626",
            "border-width": 4,
            "border-color": "#fca5a5",
            width: 52,
            height: 52,
            "z-index": 300,
          },
        },
        { selector: ".blast-reached", style: { opacity: 0 } },
        {
          selector: ".blast-visible",
          style: {
            opacity: 1,
            "transition-property": "opacity",
            "transition-duration": "500ms" as unknown as number,
          },
        },
        {
          selector: ".blast-critical",
          style: { "border-color": "#dc2626", "border-width": 3, "background-color": "#fef2f2" },
        },
        {
          selector: ".blast-high",
          style: { "border-color": "#f97316", "border-width": 2, "background-color": "#fff7ed" },
        },
        {
          selector: ".blast-medium",
          style: { "border-color": "#eab308", "border-width": 2, "background-color": "#fefce8" },
        },
        { selector: ".blast-low", style: { "border-color": "#6b7280", "border-width": 1 } },
        {
          selector: ".blast-edge",
          style: {
            "line-color": "#ef4444",
            "target-arrow-color": "#ef4444",
            "target-arrow-shape": "triangle",
            width: 2,
            opacity: 0.75,
            "z-index": 250,
            label: "",
          },
        },
        { selector: ".blast-dimmed", style: { opacity: 0.12 } },
        {
          selector: ".blast-focus",
          style: { "border-color": "#2563eb", "border-width": 4 },
        },
      ],
      layout: layoutOptions(layout),
    });

    attachNameLabels(cy);

    cy.on("tap", "node", (evt) => {
      const n = evt.target;
      onNodeClick?.({ id: n.id(), label: n.data("label"), properties: n.data() });
    });

    cy.on("cxttap", "node", (evt) => {
      const n = evt.target;
      if (n.id().startsWith("agent:")) return;
      onNodeContext?.({ id: n.id(), label: n.data("label"), properties: n.data() });
    });

    const pathSet = new Set(pathEdges.map((e) => `${e.source}→${e.target}`));
    if (pathSet.size > 0) {
      highlight.forEach((id) => cy.getElementById(id).addClass("path-node"));
      cy.edges().forEach((edge) => {
        const key = `${edge.data("source")}→${edge.data("target")}`;
        if (pathSet.has(key)) edge.addClass("path-edge");
      });
    } else {
      highlight.forEach((id) => cy.getElementById(id).addClass("highlight"));
    }

    cyRef.current = cy;
    onCyReady?.(cy);
    return () => {
      onCyReady?.(null);
      cy.destroy();
    };
  }, [data, highlight, pathEdges, layout, onNodeClick, onNodeContext, onCyReady]);

  return <div ref={ref} style={{ width: "100%", height: "100%" }} />;
}

function shortName(n: Node): string {
  const p = n.properties as Record<string, unknown>;
  const img = p.image_ref ? `${p.repo}:${p.tag}` : undefined;
  const raw =
    (p.user_name || p.role_name || p.policy_name || p.bucket_name || p.instance_id ||
      p.db_id || p.function_name || p.group_id || p.vpc_id || p.igw_id || p.account_id ||
      p.cve_id || img || p.name ||
      n.id) as string;
  return raw.length > 22 ? raw.slice(0, 20) + "…" : raw;
}

function layoutOptions(name: string): LayoutOptions {
  const base = { animate: false, padding: 40, fit: true } as const;
  switch (name) {
    case "breadthfirst":
      return { name: "breadthfirst", directed: true, spacingFactor: 1.3, ...base } as LayoutOptions;
    case "circle":
      return { name: "circle", ...base } as LayoutOptions;
    case "grid":
      return { name: "grid", ...base } as LayoutOptions;
    case "concentric":
      return { name: "concentric", ...base } as LayoutOptions;
    default:
      return { name: "cose", nodeRepulsion: 8000, idealEdgeLength: 90, ...base } as LayoutOptions;
  }
}

// Render a text label (type + name) under each node using an overlay canvas.
function attachNameLabels(cy: Core) {
  const container = cy.container();
  if (!container) return;
  let overlay = container.querySelector<HTMLDivElement>(".name-overlay");
  if (!overlay) {
    overlay = document.createElement("div");
    overlay.className = "name-overlay";
    Object.assign(overlay.style, {
      position: "absolute",
      inset: "0",
      pointerEvents: "none",
      overflow: "hidden",
    } as CSSStyleDeclaration);
    container.appendChild(overlay);
  }
  const draw = () => {
    overlay!.innerHTML = "";
    cy.nodes().forEach((n) => {
      if (n.id().startsWith("agent:")) return;
      const pos = n.renderedPosition();
      const z = cy.zoom();
      const el = document.createElement("div");
      el.style.position = "absolute";
      el.style.left = `${pos.x}px`;
      el.style.top = `${pos.y + 22 * z}px`;
      el.style.transform = "translate(-50%, 0)";
      el.style.textAlign = "center";
      el.style.font = "500 10px ui-sans-serif, system-ui";
      el.style.color = "#555";
      el.style.lineHeight = "1.2";
      el.style.whiteSpace = "nowrap";
      el.innerHTML = `<div style="color:#999">${n.data("label")}</div><div>${n.data("name")}</div>`;
      overlay!.appendChild(el);
    });
  };
  draw();
  cy.on("render pan zoom drag position", draw);
}
