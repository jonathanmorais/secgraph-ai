"""Cypher validator: ensures the LLM-produced query is safe (read-only)."""
import re

FORBIDDEN_KEYWORDS = {
    "CREATE", "DELETE", "DETACH", "SET", "MERGE", "REMOVE", "DROP",
    "LOAD", "CALL", "FOREACH", "USING", "ALTER",
}


class CypherValidationError(ValueError):
    pass


def validate(cypher: str) -> str:
    """Return the trimmed query or raise CypherValidationError."""
    if not cypher or not cypher.strip():
        raise CypherValidationError("Query vazia.")

    q = cypher.strip().rstrip(";")
    upper_tokens = set(re.findall(r"\b[A-Z]{3,}\b", q.upper()))
    hits = upper_tokens & FORBIDDEN_KEYWORDS
    if hits:
        raise CypherValidationError(
            f"Palavras-chave proibidas na query: {', '.join(sorted(hits))}"
        )

    if not re.search(r"\bMATCH\b|\bRETURN\b", q, flags=re.IGNORECASE):
        raise CypherValidationError("Query precisa ter MATCH ou RETURN.")

    return q


def extract_cypher(response_text: str) -> str:
    """Extract the first ```cypher ... ``` block from the LLM response."""
    m = re.search(r"```(?:cypher)?\s*(.*?)```", response_text, flags=re.DOTALL | re.IGNORECASE)
    if not m:
        raise CypherValidationError("Nenhum bloco Cypher encontrado na resposta.")
    return m.group(1).strip()
