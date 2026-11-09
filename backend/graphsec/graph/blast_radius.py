"""Blast Radius Engine — "este identity foi comprometido, o que ele alcança?".

Dado um identity comprometido (IAMUser, IAMRole ou EC2Instance), computa tudo
que ele alcança no grafo via arestas de privilegio (CAN_ASSUME, HAS_POLICY,
ALLOWS): recursos, dados sensiveis, roles escalaveis e o caminho ate cada um.

Adaptacoes a este codebase (vs. spec generica):
- Sincrono (o driver Neo4j e as rotas FastAPI daqui sao sincronos).
- Chave universal e `uid` (= ARN para IAM, instance_id para EC2), nao `.arn`.
- Dados sensiveis sao classificados por NOME do recurso (bucket/db), nao por
  nos Finding — que podem nao estar populados (mesma regra do text-to-Cypher).
"""
import logging
import time
from collections import Counter
from datetime import datetime, timezone

import redis
from pydantic import BaseModel, Field

from graphsec.config import get_settings
from graphsec.graph.client import fetch_graph, run_read

log = logging.getLogger(__name__)

# arestas que representam ganho de privilegio a partir de um identity
PRIV_EDGES = "CAN_ASSUME|HAS_POLICY|ALLOWS"
RESOURCE_LABELS = ("S3Bucket", "RDSInstance", "LambdaFunction", "EC2Instance")
IDENTITY_LABELS = ("IAMUser", "IAMRole", "EC2Instance")

PII_HINTS = ("pii", "pessoal", "cpf", "cliente")
FIN_HINTS = ("financ", "pagamento", "cartao", "cartão", "credit")

CACHE_TTL = 1800  # 30 min
GRAPH_VERSION_KEY = "graph:last_sync_ts"
SLOW_MS = 2000  # acima disso, marca o resultado como parcial


# ------------------------- modelos -------------------------


class ReachedResource(BaseModel):
    uid: str
    resource_type: str
    name: str
    hops: int
    path_via: list[str]
    path_nodes: list[str]
    criticality: str
    data_classification: str | None = None


class EscalatedRole(BaseModel):
    uid: str
    role_name: str
    is_service_role: bool = False
    chain_length: int
    assumption_chain: list[str]


class BlastRadiusReport(BaseModel):
    compromised_identity: str
    compromised_type: str
    computed_at: datetime
    computation_time_ms: int
    partial: bool = False

    total_resources_reached: int
    total_roles_escalatable: int
    total_data_stores_reached: int
    critical_resources_reached: int
    pii_data_exposed: bool
    max_depth_reached: int

    resources: list[ReachedResource] = Field(default_factory=list)
    escalation_paths: list[EscalatedRole] = Field(default_factory=list)

    graph_nodes: list[dict] = Field(default_factory=list)
    graph_edges: list[dict] = Field(default_factory=list)

    summary: str = ""


# ------------------------- classificacao -------------------------


def classify_data(resource_type: str, name: str | None) -> str | None:
    low = (name or "").lower()
    if any(w in low for w in PII_HINTS):
        return "pii"
    if any(w in low for w in FIN_HINTS):
        return "financial"
    if resource_type == "S3Bucket" and "public" in low:
        return "public"
    return "unknown"


def classify_criticality(
    resource_type: str, data_classification: str | None, public_ip: str | None
) -> str:
    if data_classification in ("pii", "financial"):
        return "critical"
    if resource_type in ("RDSInstance", "S3Bucket"):
        return "high"
    if resource_type == "LambdaFunction":
        return "medium"
    if resource_type == "EC2Instance" and public_ip:
        return "medium"
    return "low"


_RTYPE_PT = {
    "S3Bucket": "buckets S3",
    "RDSInstance": "bancos RDS",
    "EC2Instance": "instancias EC2",
    "LambdaFunction": "Lambdas",
}


def generate_summary(report: BlastRadiusReport) -> str:
    name = report.compromised_identity.split("/")[-1]
    parts: list[str] = []

    if report.resources:
        by_type = Counter(r.resource_type for r in report.resources)
        chunks = [
            f"{c} {_RTYPE_PT.get(t, t)}" for t, c in by_type.most_common()
        ]
        parts.append(f"{name} alcanca {', '.join(chunks)}")
    else:
        parts.append(f"{name} nao alcanca nenhum recurso diretamente")

    if report.pii_data_exposed:
        parts.append("incluindo dados sensiveis (PII/financeiro)")

    if report.escalation_paths:
        admin = [
            r for r in report.escalation_paths if "admin" in r.role_name.lower()
        ]
        if admin:
            parts.append(f"pode escalar para {len(admin)} role(s) administrativa(s)")
        else:
            parts.append(f"pode assumir {len(report.escalation_paths)} role(s) adicional(is)")

    if report.max_depth_reached:
        parts.append(f"em ate {report.max_depth_reached} hops")

    return ". ".join(parts) + "."


# ------------------------- engine -------------------------


class BlastRadiusEngine:
    def __init__(self, redis_client: "redis.Redis | None" = None) -> None:
        self._r = redis_client or redis.from_url(
            get_settings().redis_url, decode_responses=True
        )

    def _graph_version(self) -> str:
        try:
            return self._r.get(GRAPH_VERSION_KEY) or "unknown"
        except redis.RedisError:
            return "unknown"

    def _resolve_identity(self, ident: str) -> dict | None:
        """Aceita uid/ARN/instance_id ou nome (user_name/role_name)."""
        rows = run_read(
            """
            MATCH (identity)
            WHERE (identity:IAMUser OR identity:IAMRole OR identity:EC2Instance)
              AND (identity.uid = $ident OR identity.arn = $ident
                   OR identity.instance_id = $ident
                   OR identity.user_name = $ident OR identity.role_name = $ident)
            RETURN identity.uid AS uid, labels(identity)[0] AS type,
                   coalesce(identity.user_name, identity.role_name,
                            identity.instance_id, identity.uid) AS name
            LIMIT 1
            """,
            {"ident": ident},
        )
        return rows[0] if rows else None

    def compute(
        self, ident: str, max_depth: int = 8, include_indirect: bool = True
    ) -> BlastRadiusReport | None:
        identity = self._resolve_identity(ident)
        if identity is None:
            return None
        uid = identity["uid"]

        cache_key = f"blast:{uid}:{self._graph_version()}:{max_depth}"
        try:
            cached = self._r.get(cache_key)
            if cached:
                rep = BlastRadiusReport.model_validate_json(cached)
                rep.computation_time_ms = 0  # cache hit
                return rep
        except redis.RedisError:
            pass

        start = time.monotonic()
        resources = self._reached_resources(uid, max_depth)
        escalation = self._escalation_paths(uid, min(max_depth, 6))
        nodes, edges = self._blast_subgraph(uid, max_depth, resources)
        elapsed_ms = int((time.monotonic() - start) * 1000)

        data_stores = sum(
            1 for r in resources if r.resource_type in ("S3Bucket", "RDSInstance")
        )
        report = BlastRadiusReport(
            compromised_identity=uid,
            compromised_type=identity["type"],
            computed_at=datetime.now(timezone.utc),
            computation_time_ms=elapsed_ms,
            partial=elapsed_ms > SLOW_MS,
            total_resources_reached=len(resources),
            total_roles_escalatable=len(escalation),
            total_data_stores_reached=data_stores,
            critical_resources_reached=sum(
                1 for r in resources if r.criticality == "critical"
            ),
            pii_data_exposed=any(
                r.data_classification in ("pii", "financial") for r in resources
            ),
            max_depth_reached=max((r.hops for r in resources), default=0),
            resources=resources,
            escalation_paths=escalation,
            graph_nodes=nodes,
            graph_edges=edges,
        )
        report.summary = generate_summary(report)

        try:
            self._r.set(cache_key, report.model_dump_json(), ex=CACHE_TTL)
        except redis.RedisError:
            pass
        return report

    def _reached_resources(self, uid: str, max_depth: int) -> list[ReachedResource]:
        rows = run_read(
            f"""
            MATCH (c {{uid: $uid}})
            MATCH (res)
            WHERE (res:S3Bucket OR res:RDSInstance OR res:LambdaFunction
                   OR res:EC2Instance) AND res <> c
            MATCH path = shortestPath((c)-[:{PRIV_EDGES}*1..{max_depth}]->(res))
            RETURN res.uid AS uid, labels(res)[0] AS type, length(path) AS hops,
                   [r IN relationships(path) | type(r)] AS via,
                   [n IN nodes(path) | n.uid] AS path_nodes,
                   coalesce(res.bucket_name, res.db_id, res.function_name,
                            res.instance_id, res.uid) AS name,
                   res.public_ip AS public_ip
            ORDER BY hops ASC
            """,
            {"uid": uid},
        )
        out: list[ReachedResource] = []
        for r in rows:
            data_class = classify_data(r["type"], r["name"])
            out.append(
                ReachedResource(
                    uid=r["uid"],
                    resource_type=r["type"],
                    name=r["name"],
                    hops=r["hops"],
                    path_via=r["via"],
                    path_nodes=r["path_nodes"],
                    data_classification=data_class,
                    criticality=classify_criticality(
                        r["type"], data_class, r.get("public_ip")
                    ),
                )
            )
        return out

    def _escalation_paths(self, uid: str, max_depth: int) -> list[EscalatedRole]:
        rows = run_read(
            f"""
            MATCH (c {{uid: $uid}})
            MATCH (role:IAMRole) WHERE role <> c
            MATCH path = shortestPath((c)-[:{PRIV_EDGES}*1..{max_depth}]->(role))
            RETURN role.uid AS uid, role.role_name AS role_name,
                   coalesce(role.is_service_role, false) AS is_service_role,
                   length(path) AS chain_length,
                   [n IN nodes(path) | n.uid] AS chain
            ORDER BY chain_length ASC
            """,
            {"uid": uid},
        )
        return [
            EscalatedRole(
                uid=r["uid"],
                role_name=r["role_name"] or r["uid"].split("/")[-1],
                is_service_role=bool(r["is_service_role"]),
                chain_length=r["chain_length"],
                assumption_chain=r["chain"],
            )
            for r in rows
        ]

    def _blast_subgraph(
        self, uid: str, max_depth: int, resources: list[ReachedResource]
    ) -> tuple[list[dict], list[dict]]:
        raw = fetch_graph(
            f"""
            MATCH (c {{uid: $uid}})
            MATCH path = shortestPath((c)-[:{PRIV_EDGES}*1..{max_depth}]->(reached))
            WHERE reached <> c
            RETURN path
            """,
            {"uid": uid},
        )
        crit_by_uid = {r.uid: r.criticality for r in resources}
        id_map = {
            n["element_id"]: str(n["props"].get("uid") or n["element_id"])
            for n in raw["nodes"]
        }
        nodes = [
            {
                "id": id_map[n["element_id"]],
                "label": n["labels"][0] if n["labels"] else "Node",
                "criticality": crit_by_uid.get(
                    id_map[n["element_id"]],
                    "origin" if id_map[n["element_id"]] == uid else "path",
                ),
            }
            for n in raw["nodes"]
        ]
        edges = [
            {
                "source": id_map.get(e["start"], e["start"]),
                "target": id_map.get(e["end"], e["end"]),
                "relation": e["type"],
            }
            for e in raw["edges"]
        ]
        return nodes, edges

    def compare(self, ident_a: str, ident_b: str) -> dict | None:
        a = self.compute(ident_a)
        b = self.compute(ident_b)
        if a is None or b is None:
            return None
        set_a = {r.uid for r in a.resources}
        set_b = {r.uid for r in b.resources}
        return {
            "a": {"identity": a.compromised_identity, "reached": a.total_resources_reached},
            "b": {"identity": b.compromised_identity, "reached": b.total_resources_reached},
            "overlap": sorted(set_a & set_b),
            "unique_to_a": sorted(set_a - set_b),
            "unique_to_b": sorted(set_b - set_a),
        }

    def rank_all_identities(self, limit: int = 20) -> list[dict]:
        """Rankeia identities por tamanho do blast radius (preemptivo).
        Barato o bastante pra rodar on-demand; cacheado por 1h."""
        cache_key = f"blast:ranking:{self._graph_version()}:{limit}"
        try:
            cached = self._r.get(cache_key)
            if cached:
                import json

                return json.loads(cached)
        except redis.RedisError:
            pass

        rows = run_read(
            f"""
            MATCH (identity)
            WHERE identity:IAMUser OR identity:IAMRole OR identity:EC2Instance
            OPTIONAL MATCH (identity)-[:{PRIV_EDGES}*1..6]->(reached)
            WHERE reached:S3Bucket OR reached:RDSInstance
               OR reached:LambdaFunction OR reached:EC2Instance
            WITH identity, count(DISTINCT reached) AS reach_count,
                 collect(DISTINCT labels(reached)[0]) AS resource_types
            RETURN identity.uid AS uid,
                   coalesce(identity.user_name, identity.role_name,
                            identity.instance_id) AS name,
                   labels(identity)[0] AS type,
                   reach_count, resource_types
            ORDER BY reach_count DESC
            LIMIT $limit
            """,
            {"limit": limit},
        )
        try:
            import json

            self._r.set(cache_key, json.dumps(rows), ex=3600)
        except redis.RedisError:
            pass
        return rows
