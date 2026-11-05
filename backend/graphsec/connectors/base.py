import json
from abc import ABC, abstractmethod
from typing import Any

from graphsec.models.graph import Edge, Node


def _sanitize(value: Any) -> Any:
    """Neo4j só aceita primitivos ou arrays de primitivos como propriedade.
    Converte dict / list[dict] / tipos opacos para string JSON."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, list):
        if all(isinstance(v, (bool, int, float, str)) or v is None for v in value):
            return value
        return json.dumps(value, default=str, ensure_ascii=False)
    return json.dumps(value, default=str, ensure_ascii=False)


def sanitize_props(props: dict[str, Any]) -> dict[str, Any]:
    return {k: _sanitize(v) for k, v in props.items() if v is not None}


def infer_label(uid: str) -> tuple[str, dict[str, Any]]:
    """Infere o label e propriedades de um nó a partir do seu identificador
    (geralmente um ARN). Usado para criar stubs de recursos referenciados por
    edges mas não coletados diretamente (ex.: policies/roles AWS-managed)."""
    if uid.startswith("arn:aws:iam:"):
        tail = uid.split(":")[-1]
        if tail == "root":
            parts = uid.split(":")
            return "AWSAccount", {"account_id": parts[4], "alias": "root"}
        if tail.startswith("role/"):
            name = tail.split("/")[-1]
            return "IAMRole", {"role_name": name, "is_aws_managed": "service-role" in tail}
        if tail.startswith("policy/") or uid.startswith("arn:aws:iam::aws:policy"):
            name = tail.split("/")[-1]
            return "IAMPolicy", {"policy_name": name, "is_aws_managed": "::aws:" in uid}
        if tail.startswith("user/"):
            return "IAMUser", {"user_name": tail.split("/")[-1]}
    if uid.startswith("arn:aws:s3:::"):
        return "S3Bucket", {"bucket_name": uid.split(":::")[-1]}
    if uid.endswith(".amazonaws.com"):
        return "ServicePrincipal", {"service": uid.replace(".amazonaws.com", "")}
    if uid.startswith("sg-"):
        return "SecurityGroup", {"group_id": uid}
    if uid.startswith("vpc-"):
        return "VPC", {"vpc_id": uid}
    if uid.startswith("subnet-"):
        return "Subnet", {"subnet_id": uid}
    if uid.startswith("i-"):
        return "EC2Instance", {"instance_id": uid}
    return "Resource", {"name": uid}


def persist_graph(nodes: list[Node], edges: list[Edge]) -> dict[str, int]:
    """Persiste em duas fases: primeiro TODOS os nós, depois TODAS as arestas.
    Isso garante que arestas cross-connector (ex.: policy IAM -> bucket S3)
    encontrem o nó alvo independentemente da ordem de coleta."""
    from graphsec.graph.client import run_write

    known_ids = {node.id for node in nodes}

    # fase 1 — nós
    for node in nodes:
        props = sanitize_props({**node.properties, "uid": node.id})
        run_write(
            f"MERGE (n:{node.label} {{uid: $uid}}) SET n += $props",
            {"uid": node.id, "props": props},
        )

    # stubs para alvos de aresta ainda inexistentes (recursos AWS-managed etc.)
    stub_ids = {
        endpoint
        for edge in edges
        for endpoint in (edge.source, edge.target)
        if endpoint not in known_ids
    }
    for uid in stub_ids:
        label, props = infer_label(uid)
        run_write(
            f"MERGE (n:{label} {{uid: $uid}}) "
            "ON CREATE SET n += $props, n.is_stub = true",
            {"uid": uid, "props": sanitize_props({**props, "uid": uid})},
        )

    # fase 2 — arestas
    for edge in edges:
        run_write(
            "MATCH (a {uid: $src}) "
            "MATCH (b {uid: $dst}) "
            f"MERGE (a)-[r:{edge.type}]->(b) SET r += $props",
            {
                "src": edge.source,
                "dst": edge.target,
                "props": sanitize_props(edge.properties),
            },
        )

    return {"nodes": len(nodes), "stubs": len(stub_ids), "edges": len(edges)}


class BaseConnector(ABC):
    name: str = "base"

    @abstractmethod
    def get_nodes(self) -> list[Node]: ...

    @abstractmethod
    def get_edges(self) -> list[Edge]: ...

    def sync(self) -> dict[str, int]:
        return persist_graph(self.get_nodes(), self.get_edges())
