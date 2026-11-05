"""Format Cypher results into a user-friendly answer via the LLM."""
import json
from typing import Any

from anthropic import Anthropic

from graphsec.chat.prompts import FORMATTER_PROMPT
from graphsec.config import get_settings


def format_answer(question: str, cypher: str, rows: list[dict[str, Any]]) -> str:
    settings = get_settings()
    if not settings.anthropic_api_key:
        return _fallback(rows)

    client = Anthropic(api_key=settings.anthropic_api_key)
    prompt = FORMATTER_PROMPT.format(
        question=question,
        cypher=cypher,
        rows=json.dumps(rows[:50], default=str, ensure_ascii=False),
    )
    try:
        msg = client.messages.create(
            model=settings.anthropic_model,
            max_tokens=512,
            messages=[{"role": "user", "content": prompt}],
        )
        text = "".join(b.text for b in msg.content if hasattr(b, "text")).strip()
    except Exception:
        text = ""

    # LLM às vezes devolve vazio mesmo com dados válidos: renderiza os rows.
    return text or _fallback(rows)


def _fallback(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return "Nenhum resultado encontrado."

    lines = [f"Encontrados {len(rows)} resultado(s):", ""]
    for row in rows[:20]:
        parts = [f"{k}: {_fmt(v)}" for k, v in row.items() if v is not None]
        lines.append("- " + " · ".join(parts))
    if len(rows) > 20:
        lines.append(f"… e mais {len(rows) - 20}.")
    return "\n".join(lines)


def _fmt(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, default=str, ensure_ascii=False)
    return str(value)
