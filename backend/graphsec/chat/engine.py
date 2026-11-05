"""Text-to-Cypher pipeline."""
import logging
from typing import Any

from anthropic import Anthropic

from graphsec.chat.formatter import format_answer
from graphsec.chat.prompts import system_prompt
from graphsec.chat.validator import CypherValidationError, extract_cypher, validate
from graphsec.config import get_settings
from graphsec.graph.client import run_read_with_graph
from graphsec.models.chat import ChatRequest, ChatResponse

log = logging.getLogger(__name__)


def ask(req: ChatRequest) -> ChatResponse:
    settings = get_settings()
    if not settings.anthropic_api_key:
        return ChatResponse(
            answer="ANTHROPIC_API_KEY nao configurada.",
            error="missing_api_key",
        )

    client = Anthropic(api_key=settings.anthropic_api_key)
    messages: list[dict[str, Any]] = [
        *req.history,
        {"role": "user", "content": req.question},
    ]
    try:
        msg = client.messages.create(
            model=settings.anthropic_model,
            max_tokens=1024,
            system=system_prompt(),
            messages=messages,
        )
        raw = "".join(b.text for b in msg.content if hasattr(b, "text"))
    except Exception as e:
        log.exception("LLM call failed")
        return ChatResponse(answer=f"Erro ao chamar LLM: {e}", error="llm_error")

    if raw.strip().startswith("ERRO:"):
        return ChatResponse(answer=raw.strip(), error="not_answerable")

    try:
        cypher = validate(extract_cypher(raw))
    except CypherValidationError as e:
        return ChatResponse(answer=f"Query invalida: {e}", error="invalid_cypher")

    try:
        rows, path_nodes, path_edges = run_read_with_graph(cypher)
    except Exception as e:
        log.exception("Cypher execution failed")
        return ChatResponse(
            answer=f"Erro ao executar query: {e}",
            cypher=cypher,
            error="execution_error",
        )

    answer = format_answer(req.question, cypher, rows)
    # prefere os nós do subgrafo tocado (cobre paths); senão extrai dos rows
    node_ids = path_nodes or _extract_node_ids(rows)
    return ChatResponse(
        answer=answer,
        cypher=cypher,
        rows=rows,
        node_ids=node_ids,
        path_edges=path_edges,
    )


def _extract_node_ids(rows: list[dict[str, Any]]) -> list[str]:
    ids: list[str] = []
    for row in rows:
        for v in row.values():
            if isinstance(v, dict):
                for key in ("arn", "instance_id", "bucket_name", "db_id", "group_id"):
                    if key in v:
                        ids.append(str(v[key]))
    return ids
