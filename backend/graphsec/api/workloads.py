"""Rotas de workloads K8s: containers/CVEs de um EC2 e paths de privilégio."""
from fastapi import APIRouter, BackgroundTasks

from graphsec.graph.client import run_read

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
