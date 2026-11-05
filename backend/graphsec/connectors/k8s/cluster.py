"""Kubernetes connector: pods, containers, images, service accounts, IRSA.

Mapeia a topologia de workloads e liga o nó k8s (EC2) -> Pod -> Container ->
Image e Pod -> ServiceAccount -> IAMRole (via annotation IRSA), conectando
no grafo AWS existente.
"""
import re
from typing import Any

from graphsec.connectors.base import BaseConnector
from graphsec.models.graph import Edge, Node

IRSA_ANNOTATION = "eks.amazonaws.com/role-arn"
# providerID: aws:///<az>/<instance-id>
_PROVIDER_RE = re.compile(r"aws:///[^/]+/(i-[0-9a-f]+)")


def parse_instance_id(provider_id: str | None) -> str | None:
    if not provider_id:
        return None
    m = _PROVIDER_RE.search(provider_id)
    return m.group(1) if m else None


def parse_image_ref(ref: str) -> dict[str, str]:
    """Quebra 'repo:tag@sha256:...' em componentes."""
    digest = ""
    if "@" in ref:
        ref_no_digest, digest = ref.split("@", 1)
    else:
        ref_no_digest = ref
    # tag: último ':' após a última '/'
    last_slash = ref_no_digest.rfind("/")
    colon = ref_no_digest.rfind(":")
    if colon > last_slash:
        repo = ref_no_digest[:colon]
        tag = ref_no_digest[colon + 1:]
    else:
        repo = ref_no_digest
        tag = "latest"
    return {"repo": repo, "tag": tag, "digest": digest}


class K8sConnector(BaseConnector):
    name = "k8s"

    def __init__(self, core_v1: Any = None) -> None:
        self._core = core_v1
        self._nodes: list[Node] = []
        self._edges: list[Edge] = []
        self._images: set[str] = set()
        self._loaded = False

    def _client(self) -> Any:
        if self._core is not None:
            return self._core
        from kubernetes import client, config

        try:
            config.load_incluster_config()
        except Exception:
            config.load_kube_config()
        self._core = client.CoreV1Api()
        return self._core

    def _load(self) -> None:
        if self._loaded:
            return
        core = self._client()
        node_instance = self._load_nodes(core)
        self._load_service_accounts(core)
        self._load_pods(core, node_instance)
        self._loaded = True

    def _load_nodes(self, core: Any) -> dict[str, str]:
        """Retorna map node_name -> instance_id (para ligar Pod ao EC2)."""
        mapping: dict[str, str] = {}
        for n in core.list_node().items:
            name = n.metadata.name
            instance_id = parse_instance_id(getattr(n.spec, "provider_id", None))
            if instance_id:
                mapping[name] = instance_id
        return mapping

    def _load_service_accounts(self, core: Any) -> None:
        for sa in core.list_service_account_for_all_namespaces().items:
            ns = sa.metadata.namespace
            name = sa.metadata.name
            ann = sa.metadata.annotations or {}
            role_arn = ann.get(IRSA_ANNOTATION)
            uid = f"sa/{ns}/{name}"
            self._nodes.append(
                Node(
                    id=uid,
                    label="ServiceAccount",
                    properties={"name": name, "namespace": ns, "role_arn": role_arn},
                )
            )
            if role_arn:
                self._edges.append(Edge(source=uid, target=role_arn, type="CAN_ASSUME"))

    def _load_pods(self, core: Any, node_instance: dict[str, str]) -> None:
        for pod in core.list_pod_for_all_namespaces().items:
            ns = pod.metadata.namespace
            name = pod.metadata.name
            node_name = pod.spec.node_name
            sa_name = pod.spec.service_account_name or "default"
            pod_uid = f"pod/{ns}/{name}"
            self._nodes.append(
                Node(
                    id=pod_uid,
                    label="Pod",
                    properties={
                        "name": name,
                        "namespace": ns,
                        "node_name": node_name or "",
                        "status": pod.status.phase if pod.status else "",
                    },
                )
            )
            # EC2 (nó) -> Pod
            if node_name and node_name in node_instance:
                self._edges.append(
                    Edge(source=node_instance[node_name], target=pod_uid, type="HOSTS")
                )
            # Pod -> ServiceAccount
            self._edges.append(
                Edge(source=pod_uid, target=f"sa/{ns}/{sa_name}", type="USES_SA")
            )
            # containers
            for c in pod.spec.containers:
                c_uid = f"container/{ns}/{name}/{c.name}"
                self._nodes.append(
                    Node(
                        id=c_uid,
                        label="Container",
                        properties={
                            "name": c.name,
                            "namespace": ns,
                            "pod": name,
                            "image_ref": c.image,
                        },
                    )
                )
                self._edges.append(Edge(source=pod_uid, target=c_uid, type="RUNS"))
                self._register_image(c.image)
                self._edges.append(
                    Edge(source=c_uid, target=c.image, type="USES_IMAGE")
                )

    def _register_image(self, ref: str) -> None:
        if ref in self._images:
            return
        self._images.add(ref)
        parts = parse_image_ref(ref)
        self._nodes.append(
            Node(id=ref, label="ContainerImage", properties={"image_ref": ref, **parts})
        )

    def image_refs(self) -> list[str]:
        self._load()
        return sorted(self._images)

    def get_nodes(self) -> list[Node]:
        self._load()
        return self._nodes

    def get_edges(self) -> list[Edge]:
        self._load()
        return self._edges
