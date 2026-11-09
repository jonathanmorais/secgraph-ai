from fastapi import APIRouter, HTTPException, Query

from graphsec.graph.client import fetch_graph, run_read
from graphsec.graph.paths import find_attack_paths, shortest_path
from graphsec.graph.queries import FULL_GRAPH, K8S_LABELS
from graphsec.models.graph import Edge, GraphData, Node

router = APIRouter(prefix="/api/graph", tags=["graph"])


@router.get("/", response_model=GraphData)
def get_graph(limit: int = Query(500, le=5000)) -> GraphData:
    raw = fetch_graph(FULL_GRAPH, {"limit": limit, "exclude_labels": K8S_LABELS})

    # element_id -> id estável (uid setado no sync, senão o element_id)
    id_map = {
        n["element_id"]: str(n["props"].get("uid") or n["element_id"])
        for n in raw["nodes"]
    }

    nodes = [
        Node(
            id=id_map[n["element_id"]],
            label=n["labels"][0] if n["labels"] else "Node",
            properties={k: v for k, v in n["props"].items() if k != "uid"},
        )
        for n in raw["nodes"]
    ]
    edges = [
        Edge(
            source=id_map.get(e["start"], e["start"]),
            target=id_map.get(e["end"], e["end"]),
            type=e["type"],
            properties=e["props"],
        )
        for e in raw["edges"]
    ]
    return GraphData(nodes=nodes, edges=edges)


@router.get("/paths")
def attack_paths(limit: int = 20) -> list[dict]:
    return find_attack_paths(limit)


@router.get("/paths/{source_id}/{target_id}")
def path_between(source_id: str, target_id: str) -> list[dict]:
    result = shortest_path(source_id, target_id)
    if not result:
        raise HTTPException(404, "Sem caminho encontrado")
    return result


@router.post("/query")
def run_cypher(cypher: dict) -> list[dict]:
    """Execute arbitrary read-only Cypher (admin-only; validator reused)."""
    from graphsec.chat.validator import CypherValidationError, validate

    try:
        q = validate(cypher.get("query", ""))
    except CypherValidationError as e:
        raise HTTPException(400, str(e)) from e
    return run_read(q, cypher.get("params", {}))
