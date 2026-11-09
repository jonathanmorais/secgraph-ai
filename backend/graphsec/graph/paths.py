"""Attack path analysis."""
from typing import Any
from uuid import uuid4

from graphsec.graph.client import run_read, run_read_with_graph


ATTACK_PATHS_INTERNET_TO_DATA = """
MATCH path = (igw:InternetGateway)-[:ROUTES_TO]->(vpc:VPC)
  <-[:IN_VPC]-(ec2:EC2Instance)
  -[:MEMBER_OF]->(sg:SecurityGroup)
WHERE ec2.public_ip IS NOT NULL AND sg.exposes_world = true
WITH ec2, path
MATCH p2 = (ec2)-[:CAN_ASSUME|HAS_POLICY|ALLOWS*1..4]->(target)
WHERE target:S3Bucket OR target:RDSInstance
RETURN path, p2, length(path) + length(p2) AS hops
ORDER BY hops ASC
LIMIT $limit
"""

SHORTEST_PATH_TO_TARGET = """
MATCH (source), (target)
WHERE elementId(source) = $source_id AND elementId(target) = $target_id
MATCH path = shortestPath((source)-[*..10]-(target))
RETURN path, length(path) AS hops
"""


def _track_analyze(node_ids: list[str]) -> None:
    """Registra um agent path_engine efêmero e rastreia os nós analisados."""
    if not node_ids:
        return
    agent_id = f"path_engine:{uuid4().hex[:8]}"
    try:
        from graphsec.gateway import get_registry, get_tracker

        get_registry().register(agent_id, "path_engine", {})
        get_tracker().track(agent_id, "analyze", node_ids, agent_type="path_engine")
        get_registry().deregister(agent_id)
    except Exception:  # noqa: BLE001 — tracking é best-effort
        pass


def find_attack_paths(limit: int = 20) -> list[dict[str, Any]]:
    rows, node_ids, _edges = run_read_with_graph(
        ATTACK_PATHS_INTERNET_TO_DATA, {"limit": limit}
    )
    _track_analyze(node_ids)
    return rows


def shortest_path(source_id: str, target_id: str) -> list[dict[str, Any]]:
    return run_read(
        SHORTEST_PATH_TO_TARGET, {"source_id": source_id, "target_id": target_id}
    )
