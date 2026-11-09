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

    agent_id = "collector:k8s"
    try:
        from graphsec.gateway import get_registry

        get_registry().register(agent_id, "collector", {"source": "k8s"})
    except Exception:  # noqa: BLE001
        pass
    try:
        result = persist_graph(nodes, edges, agent_id=agent_id)
    finally:
        try:
            from graphsec.gateway import get_registry

            get_registry().deregister(agent_id)
        except Exception:  # noqa: BLE001
            pass
    result["cves"] = cve_nodes
    return result


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print(sync_k8s())
