import { useState } from "react";
import { ChatResponse, sendChat } from "../api/client";

export interface ChatMessage {
  role: "user" | "assistant";
  content: string;
  cypher?: string;
  nodeIds?: string[];
}

export function useChat() {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [loading, setLoading] = useState(false);

  const send = async (question: string): Promise<ChatResponse | null> => {
    setMessages((m) => [...m, { role: "user", content: question }]);
    setLoading(true);
    try {
      const resp = await sendChat(question);
      setMessages((m) => [
        ...m,
        {
          role: "assistant",
          content: resp.answer,
          cypher: resp.cypher,
          nodeIds: resp.node_ids,
        },
      ]);
      return resp;
    } finally {
      setLoading(false);
    }
  };

  return { messages, send, loading };
}
