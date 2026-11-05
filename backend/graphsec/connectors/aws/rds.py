"""AWS RDS connector."""
from typing import Any
import boto3

from graphsec.connectors.base import BaseConnector
from graphsec.models.graph import Edge, Node


class RDSConnector(BaseConnector):
    name = "aws-rds"

    def __init__(self, session: Any = None, region: str | None = None) -> None:
        self.client = (session or boto3).client("rds", region_name=region)
        self._nodes: list[Node] = []
        self._edges: list[Edge] = []
        self._loaded = False

    def _load(self) -> None:
        if self._loaded:
            return
        for db in self.client.describe_db_instances().get("DBInstances", []):
            self._nodes.append(
                Node(
                    id=db["DBInstanceIdentifier"],
                    label="RDSInstance",
                    properties={
                        "db_id": db["DBInstanceIdentifier"],
                        "engine": db.get("Engine"),
                        "publicly_accessible": db.get("PubliclyAccessible", False),
                        "encrypted": db.get("StorageEncrypted", False),
                    },
                )
            )
            if vpc := db.get("DBSubnetGroup", {}).get("VpcId"):
                self._edges.append(
                    Edge(source=db["DBInstanceIdentifier"], target=vpc, type="IN_VPC")
                )
        self._loaded = True

    def get_nodes(self) -> list[Node]:
        self._load()
        return self._nodes

    def get_edges(self) -> list[Edge]:
        self._load()
        return self._edges
