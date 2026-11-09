"""Agent Activity Gateway — registry, tracker e API de atividade em tempo real.

Camada efêmera (toda em Redis, sem persistência no Neo4j) que rastreia quais
agents (collectors, LLM queries, path engine, sessões de usuário) estão tocando
quais nós do grafo. Exposto via REST + WebSocket para o overlay no frontend.
"""
from functools import lru_cache

from graphsec.gateway.registry import AgentRegistry
from graphsec.gateway.tracker import ActivityTracker


@lru_cache
def get_registry() -> AgentRegistry:
    return AgentRegistry()


@lru_cache
def get_tracker() -> ActivityTracker:
    tracker = ActivityTracker(registry=get_registry())
    tracker.start()
    return tracker


__all__ = ["AgentRegistry", "ActivityTracker", "get_registry", "get_tracker"]
