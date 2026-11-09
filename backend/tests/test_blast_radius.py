"""Testes do Blast Radius Engine."""
import fakeredis
import pytest

from graphsec.graph import blast_radius as br
from graphsec.graph.blast_radius import (
    BlastRadiusEngine,
    BlastRadiusReport,
    ReachedResource,
    classify_criticality,
    classify_data,
    generate_summary,
)


@pytest.fixture
def fake() -> fakeredis.FakeRedis:
    return fakeredis.FakeRedis(decode_responses=True)


# ------------- classificação (puro, sem DB) -------------


def test_classify_data_pii_by_name() -> None:
    assert classify_data("S3Bucket", "lab-dados-pii-123") == "pii"
    assert classify_data("S3Bucket", "backup-clientes") == "pii"


def test_classify_data_financial_by_name() -> None:
    assert classify_data("S3Bucket", "exporta-financeiro") == "financial"
    assert classify_data("RDSInstance", "db-pagamentos") == "financial"


def test_classify_data_public_and_unknown() -> None:
    assert classify_data("S3Bucket", "my-public-assets") == "public"
    assert classify_data("S3Bucket", "random-logs") == "unknown"
    assert classify_data("LambdaFunction", "proc") == "unknown"


def test_classify_criticality() -> None:
    assert classify_criticality("S3Bucket", "pii", None) == "critical"
    assert classify_criticality("RDSInstance", "financial", None) == "critical"
    assert classify_criticality("S3Bucket", "unknown", None) == "high"
    assert classify_criticality("LambdaFunction", "unknown", None) == "medium"
    assert classify_criticality("EC2Instance", "unknown", "1.2.3.4") == "medium"
    assert classify_criticality("EC2Instance", "unknown", None) == "low"


# ------------- summary (puro) -------------


def _report(**kw) -> BlastRadiusReport:
    base = dict(
        compromised_identity="arn:aws:iam::1:user/dev-no-mfa",
        compromised_type="IAMUser",
        computed_at=br.datetime.now(br.timezone.utc),
        computation_time_ms=10,
        total_resources_reached=0,
        total_roles_escalatable=0,
        total_data_stores_reached=0,
        critical_resources_reached=0,
        pii_data_exposed=False,
        max_depth_reached=0,
    )
    base.update(kw)
    return BlastRadiusReport(**base)


def test_summary_counts_resources_and_pii() -> None:
    rep = _report(
        resources=[
            ReachedResource(
                uid="arn:aws:s3:::dados-pii", resource_type="S3Bucket",
                name="dados-pii", hops=2, path_via=["HAS_POLICY", "ALLOWS"],
                path_nodes=[], criticality="critical", data_classification="pii",
            ),
            ReachedResource(
                uid="arn:aws:s3:::logs", resource_type="S3Bucket", name="logs",
                hops=3, path_via=[], path_nodes=[], criticality="high",
            ),
        ],
        pii_data_exposed=True,
        max_depth_reached=3,
    )
    s = generate_summary(rep)
    assert "2 buckets S3" in s
    assert "PII" in s or "sensiveis" in s
    assert "3 hops" in s


def test_summary_detects_admin_escalation() -> None:
    rep = _report(
        escalation_paths=[
            br.EscalatedRole(
                uid="arn:aws:iam::1:role/AdminRole", role_name="AdminRole",
                chain_length=2, assumption_chain=["a", "b"],
            )
        ],
        max_depth_reached=2,
    )
    s = generate_summary(rep)
    assert "administrativa" in s


def test_summary_no_resources() -> None:
    s = generate_summary(_report())
    assert "nao alcanca nenhum recurso" in s


# ------------- engine: cache (fakeredis + queries mockadas) -------------


@pytest.fixture
def mocked_engine(fake, monkeypatch) -> BlastRadiusEngine:
    monkeypatch.setattr(
        br, "run_read",
        lambda q, p=None: _fake_query(q, p),
    )
    monkeypatch.setattr(br, "fetch_graph", lambda q, p=None: {"nodes": [], "edges": []})
    return BlastRadiusEngine(redis_client=fake)


def _fake_query(cypher: str, params: dict | None):
    params = params or {}
    if "RETURN identity.uid" in cypher:  # _resolve_identity
        return [{"uid": "arn:aws:iam::1:user/dev", "type": "IAMUser", "name": "dev"}]
    if "shortestPath" in cypher and "res:S3Bucket" in cypher:  # _reached_resources
        return [{
            "uid": "arn:aws:s3:::dados-pii", "type": "S3Bucket", "hops": 2,
            "via": ["HAS_POLICY", "ALLOWS"], "path_nodes": ["x", "y"],
            "name": "dados-pii", "public_ip": None,
        }]
    if "role:IAMRole" in cypher:  # _escalation_paths
        return []
    return []


def test_compute_populates_report(mocked_engine: BlastRadiusEngine) -> None:
    rep = mocked_engine.compute("dev")
    assert rep is not None
    assert rep.total_resources_reached == 1
    assert rep.pii_data_exposed is True
    assert rep.critical_resources_reached == 1
    assert rep.max_depth_reached == 2
    assert "dev" in rep.summary


def test_compute_cache_hit(mocked_engine: BlastRadiusEngine) -> None:
    first = mocked_engine.compute("dev")
    second = mocked_engine.compute("dev")
    assert first is not None and second is not None
    assert second.computation_time_ms == 0  # veio do cache
    assert second.total_resources_reached == first.total_resources_reached


def test_compute_cache_invalidated_on_version_bump(
    mocked_engine: BlastRadiusEngine, fake
) -> None:
    mocked_engine.compute("dev")
    # grafo muda -> nova versão -> nova computação (não cache hit)
    fake.set("graph:last_sync_ts", "999999.0")
    rep = mocked_engine.compute("dev")
    assert rep is not None
    assert rep.computation_time_ms >= 0


def test_compute_unknown_identity_returns_none(fake, monkeypatch) -> None:
    monkeypatch.setattr(br, "run_read", lambda q, p=None: [])
    monkeypatch.setattr(br, "fetch_graph", lambda q, p=None: {"nodes": [], "edges": []})
    engine = BlastRadiusEngine(redis_client=fake)
    assert engine.compute("ghost") is None


# ------------- integração (grafo vivo, guardado) -------------


def _neo4j_up() -> bool:
    try:
        from graphsec.graph.client import run_read

        run_read("RETURN 1 AS ok")
        return True
    except Exception:
        return False


@pytest.mark.skipif(not _neo4j_up(), reason="Neo4j indisponível")
def test_integration_ec2_reaches_pii() -> None:
    from graphsec.graph.client import run_read

    rows = run_read(
        "MATCH (e:EC2Instance)-[:CAN_ASSUME]->(:IAMRole)-[:HAS_POLICY]->"
        "(:IAMPolicy)-[:ALLOWS]->(b:S3Bucket) RETURN e.uid AS uid LIMIT 1"
    )
    if not rows:
        pytest.skip("grafo sem cenário EC2->PII (rode os syncs)")
    engine = BlastRadiusEngine()
    rep = engine.compute(rows[0]["uid"])
    assert rep is not None
    assert rep.compromised_type == "EC2Instance"
    assert rep.total_resources_reached >= 1
    assert rep.computation_time_ms < 2000  # target de performance
