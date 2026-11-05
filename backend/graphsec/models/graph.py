from typing import Any
from pydantic import BaseModel, Field


class Node(BaseModel):
    id: str
    label: str
    properties: dict[str, Any] = Field(default_factory=dict)


class Edge(BaseModel):
    source: str
    target: str
    type: str
    properties: dict[str, Any] = Field(default_factory=dict)


class GraphData(BaseModel):
    nodes: list[Node] = Field(default_factory=list)
    edges: list[Edge] = Field(default_factory=list)


class CypherQuery(BaseModel):
    query: str
    params: dict[str, Any] = Field(default_factory=dict)


class AttackPath(BaseModel):
    nodes: list[Node]
    edges: list[Edge]
    hops: int
    severity: str = "medium"
