"""AWS Lambda connector."""
from typing import Any
import boto3

from graphsec.connectors.base import BaseConnector
from graphsec.models.graph import Edge, Node


class LambdaConnector(BaseConnector):
    name = "aws-lambda"

    def __init__(self, session: Any = None, region: str | None = None) -> None:
        self.client = (session or boto3).client("lambda", region_name=region)
        self._nodes: list[Node] = []
        self._edges: list[Edge] = []
        self._loaded = False

    def _load(self) -> None:
        if self._loaded:
            return
        paginator = self.client.get_paginator("list_functions")
        for page in paginator.paginate():
            for fn in page.get("Functions", []):
                self._nodes.append(
                    Node(
                        id=fn["FunctionName"],
                        label="LambdaFunction",
                        properties={
                            "function_name": fn["FunctionName"],
                            "runtime": fn.get("Runtime"),
                            "role_arn": fn.get("Role"),
                            "vpc_config": fn.get("VpcConfig", {}),
                        },
                    )
                )
                if role := fn.get("Role"):
                    self._edges.append(
                        Edge(source=fn["FunctionName"], target=role, type="CAN_ASSUME")
                    )
        self._loaded = True

    def get_nodes(self) -> list[Node]:
        self._load()
        return self._nodes

    def get_edges(self) -> list[Edge]:
        self._load()
        return self._edges
