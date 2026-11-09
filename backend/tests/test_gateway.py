"""Testes do Agent Activity Gateway: registry, tracker e integração WebSocket."""
import json
import time

import fakeredis
import pytest

from graphsec.gateway.registry import AGENT_TTL, AgentRegistry
from graphsec.gateway.tracker import (
    ACTIVITY_CHANNEL,
    ACTIVITY_STREAM,
    ActivityTracker,
)


@pytest.fixture
def fake() -> fakeredis.FakeRedis:
    return fakeredis.FakeRedis(decode_responses=True)


# ---------------- AgentRegistry ----------------


def test_register_and_list(fake: fakeredis.FakeRedis) -> None:
    reg = AgentRegistry(client=fake)
    reg.register("collector:aws", "collector", {"source": "aws"})
    active = reg.list_active()
    assert len(active) == 1
    assert active[0]["agent_id"] == "collector:aws"
    assert active[0]["agent_type"] == "collector"
    assert active[0]["metadata"] == {"source": "aws"}
    assert 0 < active[0]["ttl"] <= AGENT_TTL


def test_register_sets_ttl(fake: fakeredis.FakeRedis) -> None:
    reg = AgentRegistry(client=fake)
    reg.register("a", "llm_query")
    ttl = fake.ttl("agents:a")
    assert 0 < ttl <= AGENT_TTL


def test_heartbeat_renews_and_deregister(fake: fakeredis.FakeRedis) -> None:
    reg = AgentRegistry(client=fake)
    reg.register("a", "llm_query")
    assert reg.heartbeat("a") is True
    reg.deregister("a")
    assert reg.heartbeat("a") is False
    assert reg.list_active() == []


def test_ttl_expiry_makes_agent_disappear(fake: fakeredis.FakeRedis) -> None:
    reg = AgentRegistry(client=fake)
    reg.register("a", "collector")
    # simula o agent morrendo sem deregistrar: a key expira
    fake.delete("agents:a")
    assert reg.heartbeat("a") is False
    assert reg.list_active() == []


def test_register_rejects_invalid_type(fake: fakeredis.FakeRedis) -> None:
    reg = AgentRegistry(client=fake)
    with pytest.raises(ValueError):
        reg.register("a", "bogus")


def test_get_type(fake: fakeredis.FakeRedis) -> None:
    reg = AgentRegistry(client=fake)
    reg.register("p", "path_engine")
    assert reg.get_type("p") == "path_engine"
    assert reg.get_type("missing") is None


# ---------------- ActivityTracker (batching) ----------------


def test_tracker_consolidates_events_in_window(fake: fakeredis.FakeRedis) -> None:
    """Eventos do mesmo (agent, action) viram UM evento com targets unidos."""
    reg = AgentRegistry(client=fake)
    reg.register("c", "collector")
    tr = ActivityTracker(client=fake, registry=reg)

    tr.track("c", "write", ["n1", "n2"])
    tr.track("c", "write", ["n2", "n3"])  # n2 duplicado
    tr.track("c", "read", ["n4"])

    batch = tr.flush()
    assert batch is not None
    events = {(e["agent_id"], e["action"]): e for e in batch["events"]}
    # consolidação + dedup + ordem preservada
    assert events[("c", "write")]["targets"] == ["n1", "n2", "n3"]
    assert events[("c", "read")]["targets"] == ["n4"]
    assert events[("c", "write")]["agent_type"] == "collector"


def test_tracker_empty_flush_returns_none(fake: fakeredis.FakeRedis) -> None:
    tr = ActivityTracker(client=fake)
    assert tr.flush() is None


def test_tracker_ignores_invalid_action_and_empty_targets(
    fake: fakeredis.FakeRedis,
) -> None:
    tr = ActivityTracker(client=fake)
    tr.track("c", "bogus", ["n1"])
    tr.track("c", "write", [])
    assert tr.flush() is None


def test_tracker_publishes_to_channel_and_stream(fake: fakeredis.FakeRedis) -> None:
    reg = AgentRegistry(client=fake)
    reg.register("c", "collector")
    tr = ActivityTracker(client=fake, registry=reg)

    pubsub = fake.pubsub()
    pubsub.subscribe(ACTIVITY_CHANNEL)
    # consome a mensagem de confirmação de subscribe
    pubsub.get_message(timeout=1)

    tr.track("c", "analyze", ["n1", "n2"])
    tr.flush()

    # pub/sub recebeu o batch
    msg = None
    for _ in range(5):
        msg = pubsub.get_message(timeout=1)
        if msg and msg.get("type") == "message":
            break
    assert msg and msg["type"] == "message"
    payload = json.loads(msg["data"])
    assert payload["events"][0]["action"] == "analyze"
    assert payload["events"][0]["targets"] == ["n1", "n2"]

    # stream histórico gravou o evento
    entries = fake.xrange(ACTIVITY_STREAM)
    assert len(entries) == 1
    _eid, fields = entries[0]
    assert fields["agent_id"] == "c"
    assert json.loads(fields["targets"]) == ["n1", "n2"]


def test_tracker_background_thread_flushes(fake: fakeredis.FakeRedis) -> None:
    """A thread daemon consolida o buffer na janela configurada."""
    reg = AgentRegistry(client=fake)
    reg.register("c", "collector")
    tr = ActivityTracker(client=fake, registry=reg, flush_interval=0.1)
    tr.start()
    try:
        tr.track("c", "write", ["n1"])
        tr.track("c", "write", ["n2"])
        time.sleep(0.3)
    finally:
        tr.stop()
    entries = fake.xrange(ACTIVITY_STREAM)
    # os dois writes caíram na mesma janela -> um evento consolidado
    assert len(entries) == 1
    _eid, fields = entries[0]
    assert json.loads(fields["targets"]) == ["n1", "n2"]


def test_three_agents_consolidated_into_single_batch(
    fake: fakeredis.FakeRedis,
) -> None:
    """3 agents publicando simultaneamente -> um único batch com 3 eventos."""
    reg = AgentRegistry(client=fake)
    reg.register("collector:aws", "collector")
    reg.register("llm_query:x1", "llm_query")
    reg.register("path_engine:y1", "path_engine")
    tr = ActivityTracker(client=fake, registry=reg)

    pubsub = fake.pubsub()
    pubsub.subscribe(ACTIVITY_CHANNEL)
    pubsub.get_message(timeout=1)

    tr.track("collector:aws", "write", ["n1"])
    tr.track("llm_query:x1", "read", ["n2"])
    tr.track("path_engine:y1", "analyze", ["n1", "n3"])

    batch = tr.flush()
    assert batch is not None
    assert len(batch["events"]) == 3
    by_type = {e["agent_type"] for e in batch["events"]}
    assert by_type == {"collector", "llm_query", "path_engine"}

    # um único batch publicado no channel
    msg = None
    for _ in range(5):
        msg = pubsub.get_message(timeout=1)
        if msg and msg.get("type") == "message":
            break
    payload = json.loads(msg["data"])
    assert len(payload["events"]) == 3
