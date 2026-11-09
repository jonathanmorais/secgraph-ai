"""Rotas de workloads K8s: containers/CVEs de um EC2 e paths de privilégio."""
from fastapi import APIRouter, BackgroundTasks

from graphsec.graph.client import fetch_graph, run_read

router = APIRouter(prefix="/api/workloads", tags=["workloads"])


@router.get("/ec2/{instance_id}")
def ec2_workloads(instance_id: str) -> dict:
    """Pods, containers, imagens e CVEs rodando num nó EC2."""
    rows = run_read(
        """
        MATCH (ec2:EC2Instance {uid: $uid})-[:HOSTS]->(pod:Pod)-[:RUNS]->(c:Container)
          -[:USES_IMAGE]->(img:ContainerImage)
        OPTIONAL MATCH (img)-[:HAS_CVE]->(cve:CVE)
        RETURN pod.name AS pod, pod.namespace AS namespace, c.name AS container,
               img.image_ref AS image, img.cve_count AS cve_count,
               img.critical_count AS critical, img.worst_severity AS worst
        ORDER BY critical DESC
        """,
        {"uid": instance_id},
    )
    # dedup por (pod, container)
    seen = set()
    workloads = []
    for r in rows:
        key = (r["pod"], r["container"])
        if key in seen:
            continue
        seen.add(key)
        workloads.append(r)
    return {"instance_id": instance_id, "workloads": workloads}


@router.get("/ec2/{instance_id}/cves")
def ec2_cves(instance_id: str) -> list[dict]:
    """CVEs das imagens rodando no EC2, ordenadas por severidade."""
    return run_read(
        """
        MATCH (ec2:EC2Instance {uid: $uid})-[:HOSTS]->(:Pod)-[:RUNS]->(:Container)
          -[:USES_IMAGE]->(img:ContainerImage)-[:HAS_CVE]->(cve:CVE)
        WITH DISTINCT cve, img
        RETURN cve.cve_id AS cve, cve.severity AS severity, cve.package AS package,
               cve.installed_version AS installed, cve.fixed_version AS fixed,
               img.image_ref AS image, cve.title AS title
        ORDER BY CASE cve.severity
                   WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3
                   WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END DESC
        LIMIT 200
        """,
        {"uid": instance_id},
    )


@router.get("/ec2/{instance_id}/subgraph")
def ec2_k8s_subgraph(
    instance_id: str,
    cve_severities: str = "CRITICAL",
    max_cve_per_image: int = 5,
) -> dict:
    """Retorna nós e edges K8s ligados a uma EC2 (para injetar no grafo sob demanda).
    Filtra CVEs pelas severidades pedidas (default: CRITICAL) e limita por imagem
    pra manter a tela legível. Contador total fica em img.cve_count."""
    sevs = [s.strip().upper() for s in cve_severities.split(",") if s.strip()]

    # Primeiro: elementos fixos (EC2, Pods, Containers, Imagens, SAs, Roles)
    structure_q = """
    MATCH (ec2:EC2Instance {uid: $uid})-[r1:HOSTS]->(pod:Pod)
    OPTIONAL MATCH (pod)-[r2:RUNS]->(c:Container)
    OPTIONAL MATCH (c)-[r3:USES_IMAGE]->(img:ContainerImage)
    OPTIONAL MATCH (pod)-[r4:USES_SA]->(sa:ServiceAccount)
    OPTIONAL MATCH (sa)-[r5:CAN_ASSUME]->(role:IAMRole)
    RETURN ec2, r1, pod, r2, c, r3, img, r4, sa, r5, role
    """
    structure = fetch_graph(structure_q, {"uid": instance_id})

    # Segundo: TOP-N CVEs por imagem (limita pra não poluir)
    cve_q = """
    MATCH (ec2:EC2Instance {uid: $uid})-[:HOSTS]->(:Pod)-[:RUNS]->(:Container)
      -[:USES_IMAGE]->(img:ContainerImage)
    OPTIONAL MATCH (img)-[hc:HAS_CVE]->(cve:CVE)
    WHERE cve.severity IN $sevs
    WITH img, cve, hc,
         CASE cve.severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3
                           WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END AS sev_rank
    ORDER BY sev_rank DESC
    WITH img, collect({cve: cve, rel: hc})[0..$max_n] AS top
    UNWIND top AS entry
    WITH img, entry.cve AS cve, entry.rel AS hc
    WHERE cve IS NOT NULL
    RETURN img, hc, cve
    """
    cves = fetch_graph(cve_q, {"uid": instance_id, "sevs": sevs, "max_n": max_cve_per_image})

    # merge dos dois subgraphs por element_id
    seen_nodes = {n["element_id"]: n for n in structure["nodes"]}
    for n in cves["nodes"]:
        seen_nodes.setdefault(n["element_id"], n)
    seen_edges = {(e["start"], e["end"], e["type"]): e for e in structure["edges"]}
    for e in cves["edges"]:
        seen_edges.setdefault((e["start"], e["end"], e["type"]), e)
    raw = {"nodes": list(seen_nodes.values()), "edges": list(seen_edges.values())}
    id_map = {
        n["element_id"]: str(n["props"].get("uid") or n["element_id"])
        for n in raw["nodes"]
    }
    nodes = [
        {
            "id": id_map[n["element_id"]],
            "label": n["labels"][0] if n["labels"] else "Node",
            "properties": {k: v for k, v in n["props"].items() if k != "uid"},
        }
        for n in raw["nodes"]
    ]
    edges = [
        {
            "source": id_map.get(e["start"], e["start"]),
            "target": id_map.get(e["end"], e["end"]),
            "type": e["type"],
            "properties": e["props"],
        }
        for e in raw["edges"]
    ]
    return {"nodes": nodes, "edges": edges}


@router.get("/ec2/{instance_id}/attack-path")
def ec2_attack_path(instance_id: str) -> dict:
    """Path de privilégio: EC2 -> Pod -> ServiceAccount -> IAMRole -> ... -> recurso.
    Retorna node_ids e path_edges para destacar em verde no grafo."""
    from graphsec.graph.client import run_read_with_graph

    _, node_ids, path_edges = run_read_with_graph(
        """
        MATCH path = (ec2:EC2Instance {uid: $uid})-[:HOSTS]->(:Pod)-[:USES_SA]->
          (:ServiceAccount)-[:CAN_ASSUME]->(:IAMRole)-[:HAS_POLICY]->(:IAMPolicy)
          -[:ALLOWS]->(target)
        RETURN path
        """,
        {"uid": instance_id},
    )
    return {"node_ids": node_ids, "path_edges": path_edges}


@router.post("/sync")
def trigger_k8s_sync(bg: BackgroundTasks, scan_cve: bool = True) -> dict[str, str]:
    from graphsec.connectors.k8s.sync import sync_k8s

    bg.add_task(sync_k8s, scan_cve)
    return {"status": "started"}
