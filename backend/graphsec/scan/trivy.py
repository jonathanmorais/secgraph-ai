"""Trivy image scanner: imagem -> CVEs.

Roda `trivy image --format json <ref>` e transforma o resultado em nós CVE
+ arestas ContainerImage -[:HAS_CVE]-> CVE.
"""
import json
import logging
import subprocess
from typing import Any

from graphsec.graph.schema import CVE_SEVERITY_ORDER
from graphsec.models.graph import Edge, Node

log = logging.getLogger(__name__)


def parse_trivy_json(image_ref: str, data: dict[str, Any]) -> tuple[list[Node], list[Edge], dict[str, int]]:
    """Converte o JSON do Trivy em nós CVE e arestas HAS_CVE para a imagem."""
    nodes: list[Node] = []
    edges: list[Edge] = []
    seen: set[str] = set()
    counts: dict[str, int] = {}

    for result in data.get("Results", []) or []:
        for vuln in result.get("Vulnerabilities", []) or []:
            cve_id = vuln.get("VulnerabilityID")
            if not cve_id:
                continue
            severity = (vuln.get("Severity") or "UNKNOWN").upper()
            counts[severity] = counts.get(severity, 0) + 1
            if cve_id not in seen:
                seen.add(cve_id)
                nodes.append(
                    Node(
                        id=cve_id,
                        label="CVE",
                        properties={
                            "cve_id": cve_id,
                            "severity": severity,
                            "package": vuln.get("PkgName", ""),
                            "installed_version": vuln.get("InstalledVersion", ""),
                            "fixed_version": vuln.get("FixedVersion", ""),
                            "title": vuln.get("Title", "") or vuln.get("Description", "")[:120],
                        },
                    )
                )
            edges.append(
                Edge(
                    source=image_ref,
                    target=cve_id,
                    type="HAS_CVE",
                    properties={"severity": severity},
                )
            )
    return nodes, edges, counts


def scan_image(image_ref: str, timeout: int = 300) -> tuple[list[Node], list[Edge], dict[str, int]]:
    """Escaneia uma imagem com o Trivy (subprocess)."""
    try:
        proc = subprocess.run(
            ["trivy", "image", "--quiet", "--format", "json", "--scanners", "vuln", image_ref],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True,
        )
        data = json.loads(proc.stdout)
    except FileNotFoundError:
        log.error("trivy não encontrado no PATH; pulando scan de %s", image_ref)
        return [], [], {}
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, json.JSONDecodeError) as e:
        log.warning("Falha ao escanear %s: %s", image_ref, e)
        return [], [], {}
    return parse_trivy_json(image_ref, data)


def scan_images(image_refs: list[str]) -> tuple[list[Node], list[Edge], dict[str, dict[str, int]]]:
    """Escaneia várias imagens; retorna nós/arestas agregados + contagem por imagem."""
    all_nodes: list[Node] = []
    all_edges: list[Edge] = []
    per_image: dict[str, dict[str, int]] = {}
    for ref in image_refs:
        log.info("Escaneando imagem %s", ref)
        nodes, edges, counts = scan_image(ref)
        all_nodes.extend(nodes)
        all_edges.extend(edges)
        per_image[ref] = counts
    return all_nodes, all_edges, per_image


def summarize_counts(counts: dict[str, int]) -> dict[str, int]:
    """Total + críticas, para enriquecer o nó da imagem."""
    total = sum(counts.values())
    critical = counts.get("CRITICAL", 0)
    high = counts.get("HIGH", 0)
    return {"cve_count": total, "critical_count": critical, "high_count": high}


def worst_severity(counts: dict[str, int]) -> str:
    present = [s for s, n in counts.items() if n > 0]
    if not present:
        return "NONE"
    return max(present, key=lambda s: CVE_SEVERITY_ORDER.get(s, 0))
