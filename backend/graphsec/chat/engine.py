"""Text-to-Cypher pipeline."""
import logging
import re
from contextlib import contextmanager
from typing import Any, Iterator
from uuid import uuid4

from anthropic import Anthropic

from graphsec.chat.formatter import format_answer
from graphsec.chat.prompts import system_prompt
from graphsec.chat.validator import CypherValidationError, extract_cypher, validate
from graphsec.config import get_settings
from graphsec.graph.client import run_read_with_graph
from graphsec.models.chat import ChatRequest, ChatResponse

log = logging.getLogger(__name__)


@contextmanager
def _llm_agent() -> Iterator[str]:
    """Registra um agent llm_query efêmero durante a consulta."""
    agent_id = f"llm_query:{uuid4().hex[:8]}"
    try:
        from graphsec.gateway import get_registry

        get_registry().register(agent_id, "llm_query", {})
    except Exception:  # noqa: BLE001
        pass
    try:
        yield agent_id
    finally:
        try:
            from graphsec.gateway import get_registry

            get_registry().deregister(agent_id)
        except Exception:  # noqa: BLE001
            pass


def _track_read(agent_id: str, node_ids: list[str]) -> None:
    if not node_ids:
        return
    try:
        from graphsec.gateway import get_tracker

        get_tracker().track(agent_id, "read", node_ids, agent_type="llm_query")
    except Exception:  # noqa: BLE001
        pass


# padroes que indicam intencao de blast radius + captura do identity
_BLAST_PATTERNS = [
    re.compile(r"blast\s*radius\s+(?:do |da |de |d'|o |a |)([\w\-:/.]+)", re.I),
    re.compile(r"o que (?:o |a |)([\w\-:/.]+)\s+(?:alcanca|alcança|acessa|consegue)", re.I),
    re.compile(r"se (?:o |a |)([\w\-:/.]+)\s+for comprometid", re.I),
    re.compile(r"token (?:do |da |de |)([\w\-:/.]+)\s+vazou", re.I),
    re.compile(r"impacto (?:do |da |de |)([\w\-:/.]+)", re.I),
]


def _try_blast_radius(question: str) -> ChatResponse | None:
    """Se a pergunta for sobre blast radius, resolve o identity e computa.
    Retorna None se nao for intencao de blast (cai no text-to-Cypher)."""
    candidates: list[str] = []
    for pat in _BLAST_PATTERNS:
        for m in pat.finditer(question):
            candidates.append(m.group(1).strip(" .,?"))
    if not candidates:
        return None

    from graphsec.graph.blast_radius import BlastRadiusEngine

    engine = BlastRadiusEngine()
    for cand in candidates:
        report = engine.compute(cand)
        if report is None:
            continue
        rec = _blast_recommendation(report)
        answer = f"{report.summary}\n\n{rec}"
        node_ids = [n["id"] for n in report.graph_nodes]
        path_edges = [
            {"source": e["source"], "target": e["target"]}
            for e in report.graph_edges
        ]
        return ChatResponse(
            answer=answer,
            rows=[r.model_dump() for r in report.resources],
            node_ids=node_ids,
            path_edges=path_edges,  # type: ignore[arg-type]
        )
    return None


def _blast_recommendation(report: Any) -> str:
    name = report.compromised_identity.split("/")[-1]
    if report.total_resources_reached == 0 and not report.escalation_paths:
        return f"Recomendacao: revogar credenciais de {name} (exposicao limitada)."
    actions = [f"revogar/rotacionar as credenciais de {name}"]
    if report.escalation_paths:
        actions.append("revisar as roles assumiveis (privilege escalation)")
    if report.pii_data_exposed:
        actions.append("auditar acessos recentes aos buckets de dados sensiveis")
    return "Recomendacao imediata: " + "; ".join(actions) + "."


def ask(req: ChatRequest) -> ChatResponse:
    blast = _try_blast_radius(req.question)
    if blast is not None:
        return blast
    with _llm_agent() as agent_id:
        return _ask(req, agent_id)


def _ask(req: ChatRequest, agent_id: str) -> ChatResponse:
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
    _track_read(agent_id, node_ids)
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
