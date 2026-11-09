export interface Node {
  id: string;
  label: string;
  properties: Record<string, unknown>;
}

export interface Edge {
  source: string;
  target: string;
  type: string;
  properties: Record<string, unknown>;
}

export interface GraphData {
  nodes: Node[];
  edges: Edge[];
}

export interface PathEdge {
  source: string;
  target: string;
}

export interface ChatResponse {
  answer: string;
  cypher?: string;
  rows: Record<string, unknown>[];
  node_ids: string[];
  path_edges: PathEdge[];
  error?: string;
}

const BASE = "";

export async function fetchGraph(limit = 500): Promise<GraphData> {
  const r = await fetch(`${BASE}/api/graph/?limit=${limit}`);
  if (!r.ok) throw new Error(`graph fetch failed: ${r.status}`);
  return r.json();
}

export async function sendChat(
  question: string,
  history: Array<{ role: string; content: string }> = []
): Promise<ChatResponse> {
  const r = await fetch(`${BASE}/api/chat/`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ question, history }),
  });
  return r.json();
}

export async function fetchAttackPaths(limit = 20) {
  const r = await fetch(`${BASE}/api/graph/paths?limit=${limit}`);
  return r.json();
}

export async function triggerAwsSync(): Promise<{ status: string }> {
  const r = await fetch(`${BASE}/api/connectors/aws/sync`, { method: "POST" });
  return r.json();
}

export interface Workload {
  pod: string;
  namespace: string;
  container: string;
  image: string;
  cve_count: number | null;
  critical: number | null;
  worst: string | null;
}

export async function fetchEc2Workloads(
  instanceId: string
): Promise<{ instance_id: string; workloads: Workload[] }> {
  const r = await fetch(`${BASE}/api/workloads/ec2/${encodeURIComponent(instanceId)}`);
  return r.json();
}

export async function fetchEc2Subgraph(
  instanceId: string
): Promise<GraphData> {
  const r = await fetch(
    `${BASE}/api/workloads/ec2/${encodeURIComponent(instanceId)}/subgraph`
  );
  return r.json();
}

export async function fetchEc2AttackPath(
  instanceId: string
): Promise<{ node_ids: string[]; path_edges: PathEdge[] }> {
  const r = await fetch(
    `${BASE}/api/workloads/ec2/${encodeURIComponent(instanceId)}/attack-path`
  );
  return r.json();
}
