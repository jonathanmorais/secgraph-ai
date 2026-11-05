"""Attack path analysis."""
from typing import Any
from graphsec.graph.client import run_read


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


def find_attack_paths(limit: int = 20) -> list[dict[str, Any]]:
    return run_read(ATTACK_PATHS_INTERNET_TO_DATA, {"limit": limit})


def shortest_path(source_id: str, target_id: str) -> list[dict[str, Any]]:
    return run_read(
        SHORTEST_PATH_TO_TARGET, {"source_id": source_id, "target_id": target_id}
    )
