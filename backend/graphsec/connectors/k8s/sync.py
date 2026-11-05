"""Entrypoint: sincroniza workloads K8s + scan de CVE (Trivy) no grafo."""
import logging

from graphsec.connectors.base import persist_graph
from graphsec.connectors.k8s.cluster import K8sConnector
from graphsec.scan.trivy import scan_images, summarize_counts, worst_severity

log = logging.getLogger(__name__)


def sync_k8s(scan_cve: bool = True) -> dict[str, int]:
    conn = K8sConnector()
    nodes = conn.get_nodes()
    edges = conn.get_edges()

    cve_nodes = 0
    if scan_cve:
        images = conn.image_refs()
        log.info("Escaneando %d imagens com Trivy", len(images))
        scan_nodes, scan_edges, per_image = scan_images(images)
        # enriquece os nós de imagem com contagem de CVE
        for node in nodes:
            if node.label == "ContainerImage":
                counts = per_image.get(node.id, {})
                node.properties.update(summarize_counts(counts))
                node.properties["worst_severity"] = worst_severity(counts)
        nodes.extend(scan_nodes)
        edges.extend(scan_edges)
        cve_nodes = len({n.id for n in scan_nodes})

    result = persist_graph(nodes, edges)
    result["cves"] = cve_nodes
    return result


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print(sync_k8s())
