from contextlib import contextmanager
from typing import Any, Iterator
from neo4j import Driver, GraphDatabase, Session

from graphsec.config import get_settings


_driver: Driver | None = None


def get_driver() -> Driver:
    global _driver
    if _driver is None:
        s = get_settings()
        _driver = GraphDatabase.driver(s.neo4j_uri, auth=(s.neo4j_user, s.neo4j_password))
    return _driver


def close_driver() -> None:
    global _driver
    if _driver is not None:
        _driver.close()
        _driver = None


@contextmanager
def session() -> Iterator[Session]:
    drv = get_driver()
    with drv.session() as s:
        yield s


def run_read(cypher: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    with session() as s:
        result = s.execute_read(lambda tx: list(tx.run(cypher, params or {})))
        return [r.data() for r in result]


def run_write(cypher: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    with session() as s:
        result = s.execute_write(lambda tx: list(tx.run(cypher, params or {})))
        return [r.data() for r in result]


def run_read_with_graph(
    cypher: str, params: dict[str, Any] | None = None
) -> tuple[list[dict[str, Any]], list[str], list[dict[str, str]]]:
    """Executa a query e retorna (rows, uids_dos_nos, arestas) do subgrafo
    que a query tocou. Usado para destacar o path encontrado no frontend."""

    def work(tx: Any) -> tuple[list[dict[str, Any]], list[str], list[dict[str, str]]]:
        result = tx.run(cypher, params or {})
        records = list(result)
        rows = [r.data() for r in records]
        graph = result.graph()
        id_map = {n.element_id: dict(n).get("uid") or n.element_id for n in graph.nodes}
        node_uids = list(id_map.values())
        edges = [
            {"source": id_map[r.start_node.element_id], "target": id_map[r.end_node.element_id]}
            for r in graph.relationships
        ]
        return rows, node_uids, edges

    with session() as s:
        return s.execute_read(work)


def fetch_graph(cypher: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    """Executa a query e retorna nós/arestas preservando labels e tipos."""

    def work(tx: Any) -> dict[str, Any]:
        result = tx.run(cypher, params or {})
        graph = result.graph()
        nodes = [
            {
                "element_id": n.element_id,
                "labels": list(n.labels),
                "props": dict(n),
            }
            for n in graph.nodes
        ]
        edges = [
            {
                "start": r.start_node.element_id,
                "end": r.end_node.element_id,
                "type": r.type,
                "props": dict(r),
            }
            for r in graph.relationships
        ]
        return {"nodes": nodes, "edges": edges}

    with session() as s:
        return s.execute_read(work)
