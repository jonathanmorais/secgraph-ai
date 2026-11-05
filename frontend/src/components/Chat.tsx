import { useState } from "react";
import { PathEdge } from "../api/client";
import { useChat } from "../hooks/useChat";
import { Markdown } from "./Markdown";

interface Props {
  onHighlight?: (ids: string[], edges: PathEdge[]) => void;
  onQuery?: (cypher: string) => void;
}

export function Chat({ onHighlight, onQuery }: Props) {
  const { messages, send, loading } = useChat();
  const [input, setInput] = useState("");

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const q = input.trim();
    if (!q || loading) return;
    setInput("");
    const resp = await send(q);
    if (resp?.cypher) onQuery?.(resp.cypher);
    // sempre reseta o destaque: novo path em verde, ou limpa o anterior
    onHighlight?.(resp?.node_ids || [], resp?.path_edges || []);
  };

  return (
    <>
      <div className="chat-header">
        <div className="title">Chat</div>
        <div className="icons">
          <button title="Expandir">⤢</button>
        </div>
      </div>

      <div className="chat-log">
        {messages.length === 0 && (
          <div style={{ color: "var(--muted)", fontSize: 13 }}>
            Pergunte sobre seu ambiente. Ex.: “quais buckets estão públicos?”
          </div>
        )}
        {messages.map((m, i) =>
          m.role === "user" ? (
            <div key={i} className="msg-user">
              {m.content}
            </div>
          ) : (
            <div key={i} className="msg-bot">
              <Markdown text={m.content} />
              {m.cypher && <pre className="cypher">{m.cypher}</pre>}
            </div>
          )
        )}
        {loading && (
          <div className="msg-bot">
            <span className="thinking">Pensando…</span>
          </div>
        )}
      </div>

      <form className="chat-input" onSubmit={submit}>
        <div className="box">
          <button type="button" className="plus" title="Novo">
            +
          </button>
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Pergunte ao seu grafo…"
            disabled={loading}
          />
          <button type="submit" className="send" disabled={loading}>
            {loading ? "…" : "Enviar"}
          </button>
        </div>
      </form>
    </>
  );
}
