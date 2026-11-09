"""API do Blast Radius Engine — incident response em segundos."""
from functools import lru_cache

from fastapi import APIRouter, HTTPException

from graphsec.graph.blast_radius import BlastRadiusEngine, BlastRadiusReport

router = APIRouter(prefix="/api/blast-radius", tags=["blast-radius"])


@lru_cache
def _engine() -> BlastRadiusEngine:
    return BlastRadiusEngine()


@router.get("/ranking")
def ranking(limit: int = 20) -> list[dict]:
    """Top identities por tamanho do blast radius (quem proteger primeiro)."""
    return _engine().rank_all_identities(limit=limit)


@router.get("/{ident}/compare/{other}")
def compare(ident: str, other: str) -> dict:
    result = _engine().compare(ident, other)
    if result is None:
        raise HTTPException(404, "Um dos identities nao existe no grafo")
    return result


@router.get("/{ident}/graph")
def blast_graph(ident: str, max_depth: int = 8) -> dict:
    """Subgrafo pronto pro Cytoscape.js (nodes + edges com criticidade)."""
    report = _engine().compute(ident, max_depth=max_depth)
    if report is None:
        raise HTTPException(404, f"Identity nao encontrado: {ident}")
    return {"nodes": report.graph_nodes, "edges": report.graph_edges}


@router.get("/{ident}", response_model=BlastRadiusReport)
def blast_radius(
    ident: str, max_depth: int = 8, include_indirect: bool = True
) -> BlastRadiusReport:
    report = _engine().compute(
        ident, max_depth=max_depth, include_indirect=include_indirect
    )
    if report is None:
        raise HTTPException(404, f"Identity nao encontrado: {ident}")
    return report
