"""Entrypoint: sync all AWS connectors into Neo4j."""
import logging

from graphsec.connectors.aws.ec2 import EC2Connector
from graphsec.connectors.aws.iam import IAMConnector
from graphsec.connectors.aws.lambda_ import LambdaConnector
from graphsec.connectors.aws.rds import RDSConnector
from graphsec.connectors.aws.s3 import S3Connector
from graphsec.connectors.base import persist_graph
from graphsec.graph.schema import apply_constraints
from graphsec.models.graph import Edge, Node

log = logging.getLogger(__name__)


def sync_all() -> dict[str, int]:
    """Coleta nós/arestas de todos os connectors e persiste em duas fases,
    para que arestas cross-connector (ex.: IAM policy -> S3 bucket) resolvam."""
    apply_constraints()
    connectors = [
        IAMConnector(),
        EC2Connector(),
        S3Connector(),
        RDSConnector(),
        LambdaConnector(),
    ]
    nodes: list[Node] = []
    edges: list[Edge] = []
    for conn in connectors:
        log.info("Coletando %s", conn.name)
        nodes.extend(conn.get_nodes())
        edges.extend(conn.get_edges())
    return persist_graph(nodes, edges)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print(sync_all())
