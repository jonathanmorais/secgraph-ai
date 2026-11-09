"""Activity Tracker — acumula eventos e publica em batches de 500ms no Redis.

Fluxo: track() enfileira num buffer local -> thread daemon consolida a cada
500ms -> publica batch no pub/sub `graph:activity` e grava no stream
`graph:activity:log` (XADD MAXLEN ~1000) para consulta histórica.
"""
import json
import logging
import threading
import time
from typing import Any

import redis

from graphsec.config import get_settings

log = logging.getLogger(__name__)

ACTIVITY_CHANNEL = "graph:activity"
ACTIVITY_STREAM = "graph:activity:log"
STREAM_MAXLEN = 1000
FLUSH_INTERVAL = 0.5  # segundos
ACTIONS = frozenset({"read", "write", "analyze", "browse"})


class ActivityTracker:
    def __init__(
        self,
        client: "redis.Redis | None" = None,
        registry: Any = None,
        flush_interval: float = FLUSH_INTERVAL,
    ) -> None:
        self._r = client or redis.from_url(
            get_settings().redis_url, decode_responses=True
        )
        self._registry = registry
        self._interval = flush_interval
        self._buffer: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def track(
        self,
        agent_id: str,
        action: str,
        targets: list[str],
        agent_type: str | None = None,
    ) -> None:
        """Enfileira um evento. Nunca levanta exceção no caminho da aplicação."""
        if action not in ACTIONS or not targets:
            return
        with self._lock:
            self._buffer.append(
                {
                    "agent_id": agent_id,
                    "agent_type": agent_type,
                    "action": action,
                    "targets": list(targets),
                }
            )

    def _drain(self) -> list[dict[str, Any]]:
        with self._lock:
            events, self._buffer = self._buffer, []
        return events

    def _consolidate(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Agrupa por (agent_id, action), unindo targets preservando ordem."""
        grouped: dict[tuple[str, str], dict[str, Any]] = {}
        type_cache: dict[str, str | None] = {}
        for ev in events:
            key = (ev["agent_id"], ev["action"])
            slot = grouped.get(key)
            if slot is None:
                agent_type = ev.get("agent_type")
                if agent_type is None and self._registry is not None:
                    if ev["agent_id"] not in type_cache:
                        type_cache[ev["agent_id"]] = self._registry.get_type(
                            ev["agent_id"]
                        )
                    agent_type = type_cache[ev["agent_id"]]
                slot = {
                    "agent_id": ev["agent_id"],
                    "agent_type": agent_type or "unknown",
                    "action": ev["action"],
                    "targets": [],
                }
                grouped[key] = slot
            seen = set(slot["targets"])
            for t in ev["targets"]:
                if t not in seen:
                    slot["targets"].append(t)
                    seen.add(t)
        return list(grouped.values())

    def flush(self) -> dict[str, Any] | None:
        """Consolida o buffer e publica um batch. Retorna o batch (ou None)."""
        events = self._drain()
        if not events:
            return None
        consolidated = self._consolidate(events)
        batch = {"ts": time.time(), "events": consolidated}
        try:
            payload = json.dumps(batch, default=str)
            self._r.publish(ACTIVITY_CHANNEL, payload)
            for ev in consolidated:
                self._r.xadd(
                    ACTIVITY_STREAM,
                    {
                        "agent_id": ev["agent_id"],
                        "agent_type": ev["agent_type"],
                        "action": ev["action"],
                        "targets": json.dumps(ev["targets"], default=str),
                        "ts": repr(batch["ts"]),
                    },
                    maxlen=STREAM_MAXLEN,
                    approximate=True,
                )
        except redis.RedisError:
            log.warning("tracker flush falhou (redis indisponível)", exc_info=True)
        return batch

    def _loop(self) -> None:
        while not self._stop.wait(self._interval):
            self.flush()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, name="activity-tracker", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
