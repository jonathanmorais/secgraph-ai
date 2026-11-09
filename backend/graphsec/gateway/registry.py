"""Agent Registry — agents ativos vivem em Redis com TTL (sem DB)."""
import json
import time
from typing import Any

import redis

from graphsec.config import get_settings

AGENT_TTL = 60  # fallback: agent que morre sem deregistrar some em 60s
AGENT_TYPES = frozenset({"collector", "llm_query", "path_engine", "user_session"})
_KEY_PREFIX = "agents:"


class AgentRegistry:
    def __init__(self, client: "redis.Redis | None" = None) -> None:
        self._r = client or redis.from_url(
            get_settings().redis_url, decode_responses=True
        )

    @staticmethod
    def _key(agent_id: str) -> str:
        return f"{_KEY_PREFIX}{agent_id}"

    def register(
        self, agent_id: str, agent_type: str, metadata: dict[str, Any] | None = None
    ) -> None:
        if agent_type not in AGENT_TYPES:
            raise ValueError(f"agent_type invalido: {agent_type}")
        key = self._key(agent_id)
        self._r.hset(
            key,
            mapping={
                "agent_id": agent_id,
                "agent_type": agent_type,
                "metadata": json.dumps(metadata or {}, default=str),
                "registered_at": repr(time.time()),
            },
        )
        self._r.expire(key, AGENT_TTL)

    def deregister(self, agent_id: str) -> None:
        self._r.delete(self._key(agent_id))

    def heartbeat(self, agent_id: str) -> bool:
        """Renova o TTL. Retorna False se o agent já expirou/não existe."""
        key = self._key(agent_id)
        if not self._r.exists(key):
            return False
        self._r.expire(key, AGENT_TTL)
        return True

    def get_type(self, agent_id: str) -> str | None:
        return self._r.hget(self._key(agent_id), "agent_type")

    def list_active(self) -> list[dict[str, Any]]:
        agents: list[dict[str, Any]] = []
        for key in self._r.scan_iter(match=f"{_KEY_PREFIX}*", count=100):
            data = self._r.hgetall(key)
            if not data:
                continue
            try:
                data["metadata"] = json.loads(data.get("metadata", "{}"))
            except (ValueError, TypeError):
                data["metadata"] = {}
            data["ttl"] = self._r.ttl(key)
            agents.append(data)
        return agents
