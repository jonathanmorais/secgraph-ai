import { useCallback, useEffect, useRef, useState } from "react";

export type AgentType =
  | "collector"
  | "llm_query"
  | "path_engine"
  | "user_session"
  | "unknown";

export interface AgentEvent {
  agent_id: string;
  agent_type: AgentType;
  action: string;
  targets: string[];
}

export interface ActivityBatch {
  ts: number;
  events: AgentEvent[];
}

export interface ActiveAgent {
  agent_id: string;
  agent_type: AgentType;
  action: string;
  targets: string[];
  lastSeen: number;
}

const IDLE_MS = 5000; // agent some após 5s sem atividade
const PRUNE_INTERVAL = 1000;

/** Conecta ao /ws/activity, mantém o estado dos agents ativos e seus alvos. */
export function useAgentActivity(enabled = true) {
  const [agents, setAgents] = useState<Record<string, ActiveAgent>>({});
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    if (!enabled) return;
    const proto = window.location.protocol === "https:" ? "wss" : "ws";
    const url = `${proto}://${window.location.host}/ws/activity`;
    let closed = false;
    let retry: ReturnType<typeof setTimeout>;

    const connect = () => {
      const ws = new WebSocket(url);
      wsRef.current = ws;
      ws.onopen = () => setConnected(true);
      ws.onclose = () => {
        setConnected(false);
        if (!closed) retry = setTimeout(connect, 2000);
      };
      ws.onerror = () => ws.close();
      ws.onmessage = (ev) => {
        let payload: { batches?: ActivityBatch[] };
        try {
          payload = JSON.parse(ev.data);
        } catch {
          return;
        }
        const now = Date.now();
        const flat: AgentEvent[] = [];
        for (const b of payload.batches ?? []) flat.push(...b.events);
        if (flat.length === 0) return;
        setAgents((prev) => {
          const next = { ...prev };
          for (const e of flat) {
            next[e.agent_id] = {
              agent_id: e.agent_id,
              agent_type: e.agent_type,
              action: e.action,
              targets: e.targets,
              lastSeen: now,
            };
          }
          return next;
        });
      };
    };

    connect();
    return () => {
      closed = true;
      clearTimeout(retry);
      wsRef.current?.close();
    };
  }, [enabled]);

  // poda agents ociosos (dispara o fade-out no overlay)
  useEffect(() => {
    const t = setInterval(() => {
      const cutoff = Date.now() - IDLE_MS;
      setAgents((prev) => {
        const next: Record<string, ActiveAgent> = {};
        let changed = false;
        for (const [id, a] of Object.entries(prev)) {
          if (a.lastSeen >= cutoff) next[id] = a;
          else changed = true;
        }
        return changed ? next : prev;
      });
    }, PRUNE_INTERVAL);
    return () => clearInterval(t);
  }, []);

  const sendBrowse = useCallback((targets: string[], action = "browse") => {
    const ws = wsRef.current;
    if (ws && ws.readyState === WebSocket.OPEN && targets.length > 0) {
      ws.send(JSON.stringify({ action, targets }));
    }
  }, []);

  return { agents, connected, sendBrowse };
}
