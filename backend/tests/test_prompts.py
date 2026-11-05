"""Garante que as regras mandatórias do text-to-Cypher estão no system prompt.

Essas regras são convenção obrigatória do projeto (ver CLAUDE.md § Chat LLM).
Se alterar/remover uma regra, atualize também este teste conscientemente —
ele existe para impedir regressão silenciosa que quebra os attack paths."""
from graphsec.chat.prompts import FEW_SHOTS, system_prompt

MANDATORY_RULES = [
    # somente leitura
    "READ-ONLY",
    "Nunca CREATE/DELETE/SET/MERGE/REMOVE/DROP/LOAD",
    # dados sensíveis identificados por nome, não por Finding
    "identificados pelo NOME do recurso",
    "toLower",
    # caminho da internet começa no gateway e é direcionado
    "InternetGateway",
    "shortestPath",
    "PUBLIC_ACCESS, CAN_ASSUME, HAS_POLICY, ALLOWS",
    # não depender de Finding/STORES_DATA
    "Finding/STORES_DATA podem nao estar populados",
    # erro explícito quando não dá pra responder
    "ERRO:",
]


def test_system_prompt_contains_mandatory_rules():
    prompt = system_prompt()
    missing = [rule for rule in MANDATORY_RULES if rule not in prompt]
    assert not missing, f"Regras mandatórias ausentes do system prompt: {missing}"


def test_system_prompt_embeds_schema_and_examples():
    prompt = system_prompt()
    assert "SCHEMA DO GRAFO:" in prompt
    assert "S3Bucket" in prompt  # schema injetado
    # few-shots de attack path presentes
    for ex in FEW_SHOTS:
        assert ex["q"] in prompt


def test_few_shots_are_read_only():
    forbidden = ("CREATE", "DELETE", "MERGE", "SET ", "REMOVE", "DROP")
    for ex in FEW_SHOTS:
        upper = ex["c"].upper()
        assert not any(f in upper for f in forbidden), f"few-shot não read-only: {ex['q']}"
