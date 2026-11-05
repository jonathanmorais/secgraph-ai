from typing import Any
from pydantic import BaseModel, Field


class ChatRequest(BaseModel):
    question: str
    history: list[dict[str, str]] = Field(default_factory=list)


class PathEdge(BaseModel):
    source: str
    target: str


class ChatResponse(BaseModel):
    answer: str
    cypher: str | None = None
    rows: list[dict[str, Any]] = Field(default_factory=list)
    node_ids: list[str] = Field(default_factory=list)
    path_edges: list[PathEdge] = Field(default_factory=list)
    error: str | None = None
