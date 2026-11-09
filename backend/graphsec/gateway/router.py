"""API de atividade de agents: REST + WebSocket em tempo real."""
import asyncio
import contextlib
import json
import time
from uuid import uuid4

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from graphsec.config import get_settings
from graphsec.gateway import get_registry, get_tracker
from graphsec.gateway.tracker import ACTIVITY_CHANNEL, ACTIVITY_STREAM

router = APIRouter(tags=["agents"])

WS_THROTTLE = 0.5  # máx 2 msgs/segundo pro browser
NODE_WINDOW = 30  # segundos de histórico para "quem toca este nó"


@router.get("/api/agents")
def list_agents() -> list[dict]:
    return get_registry().list_active()


@router.get("/api/agents/{agent_id}/activity")
def agent_activity(agent_id: str, limit: int = 100) -> list[dict]:
    """Últimas interações desse agent (lê o stream de trás pra frente)."""
    r = get_registry()._r
    entries = r.xrevrange(ACTIVITY_STREAM, count=max(limit * 5, 200))
    out: list[dict] = []
    for entry_id, fields in entries:
        if fields.get("agent_id") != agent_id:
            continue
        out.append(_parse_entry(entry_id, fields))
        if len(out) >= limit:
            break
    return out


@router.get("/api/nodes/{node_id}/agents")
def node_agents(node_id: str) -> list[dict]:
    """Quais agents tocaram este nó nos últimos 30s."""
    r = get_registry()._r
    min_id = f"{int((time.time() - NODE_WINDOW) * 1000)}-0"
    entries = r.xrange(ACTIVITY_STREAM, min=min_id, max="+")
    seen: dict[str, dict] = {}
    for _entry_id, fields in entries:
        try:
            targets = json.loads(fields.get("targets", "[]"))
        except (ValueError, TypeError):
            targets = []
        if node_id not in targets:
            continue
        aid = fields.get("agent_id", "")
        seen[aid] = {
            "agent_id": aid,
            "agent_type": fields.get("agent_type", "unknown"),
            "action": fields.get("action", ""),
        }
    return list(seen.values())


def _parse_entry(entry_id: str, fields: dict) -> dict:
    try:
        targets = json.loads(fields.get("targets", "[]"))
    except (ValueError, TypeError):
        targets = []
    return {
        "id": entry_id,
        "agent_id": fields.get("agent_id", ""),
        "agent_type": fields.get("agent_type", "unknown"),
        "action": fields.get("action", ""),
        "targets": targets,
        "ts": float(fields.get("ts", "0") or 0),
    }


@router.websocket("/ws/activity")
async def ws_activity(ws: WebSocket) -> None:
    import redis.asyncio as aioredis

    await ws.accept()
    settings = get_settings()
    registry = get_registry()
    tracker = get_tracker()

    session_id = f"user_session:{uuid4().hex[:8]}"
    registry.register(session_id, "user_session", {"kind": "browser"})

    r = aioredis.from_url(settings.redis_url, decode_responses=True)
    pubsub = r.pubsub()
    await pubsub.subscribe(ACTIVITY_CHANNEL)

    async def pump_out() -> None:
        buffer: list[dict] = []
        last_send = 0.0
        while True:
            msg = await pubsub.get_message(
                ignore_subscribe_messages=True, timeout=WS_THROTTLE
            )
            if msg and msg.get("type") == "message":
                with contextlib.suppress(ValueError, TypeError):
                    buffer.append(json.loads(msg["data"]))
            registry.heartbeat(session_id)
            now = time.monotonic()
            if buffer and now - last_send >= WS_THROTTLE:
                await ws.send_json({"batches": buffer})
                buffer = []
                last_send = now

    async def pump_in() -> None:
        while True:
            data = await ws.receive_json()
            targets = data.get("targets") or []
            action = data.get("action", "browse")
            if targets:
                registry.heartbeat(session_id)
                tracker.track(
                    session_id, action, targets, agent_type="user_session"
                )

    try:
        await asyncio.gather(pump_out(), pump_in())
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        registry.deregister(session_id)
        with contextlib.suppress(Exception):
            await pubsub.unsubscribe(ACTIVITY_CHANNEL)
            await pubsub.aclose()
            await r.aclose()
