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
# providerID AWS: aws:///<az>/<instance-id>
_PROVIDER_RE = re.compile(r"aws:///[^/]+/(i-[0-9a-f]+)")
# hostname AWS para k3s / kubelet sem cloud-provider: ip-10-42-1-92.ec2.internal
_HOSTNAME_RE = re.compile(r"ip-(\d+)-(\d+)-(\d+)-(\d+)")


def parse_instance_id(provider_id: str | None) -> str | None:
    if not provider_id:
        return None
    m = _PROVIDER_RE.search(provider_id)
    return m.group(1) if m else None


def parse_private_ip(hostname: str | None) -> str | None:
    """Extrai IP privado do hostname AWS style `ip-10-42-1-92.ec2.internal`."""
    if not hostname:
        return None
    m = _HOSTNAME_RE.search(hostname)
    return ".".join(m.groups()) if m else None


# frameworks de agente de IA reconhecíveis por nome de imagem (fallback)
_AI_IMAGE_HINTS = {
    "langchain": "langchain",
    "llamaindex": "llamaindex",
    "llama-index": "llamaindex",
    "autogpt": "autogpt",
    "crewai": "crewai",
    "vllm": "vllm",
    "ollama": "ollama",
    "/mcp": "mcp",
    "mcp-server": "mcp",
    "semantic-kernel": "semantic-kernel",
}


def detect_ai_agent(
    annotations: dict[str, str] | None,
    labels: dict[str, str] | None,
    images: list[str],
) -> tuple[bool, str]:
    """Classifica um workload como agente de IA e infere o framework.

    Ordem de confiança: annotation explícita > label de componente > imagem."""
    annotations = annotations or {}
    labels = labels or {}

    if annotations.get("graphsec.io/ai-agent", "").lower() == "true":
        fw = annotations.get("graphsec.io/ai-framework", "unknown")
        return True, fw

    if labels.get("app.kubernetes.io/component") == "agent":
        fw = annotations.get("graphsec.io/ai-framework", "unknown")
        return True, fw

    for img in images:
        low = img.lower()
        for hint, fw in _AI_IMAGE_HINTS.items():
            if hint in low:
                return True, fw

    return False, ""


def resolve_instance_id_by_private_ip(private_ip: str) -> str | None:
    """Busca o uid da EC2 no grafo pelo private_ip (fallback para k3s)."""
    from graphsec.graph.client import run_read

    rows = run_read(
        "MATCH (ec2:EC2Instance {private_ip: $ip}) RETURN ec2.uid AS uid LIMIT 1",
        {"ip": private_ip},
    )
    return rows[0]["uid"] if rows else None


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
        """Retorna map node_name -> instance_id (para ligar Pod ao EC2).
        Suporta providerID AWS (aws:///...) e fallback via hostname (k3s)."""
        mapping: dict[str, str] = {}
        for n in core.list_node().items:
            name = n.metadata.name
            instance_id = parse_instance_id(getattr(n.spec, "provider_id", None))
            if not instance_id:
                private_ip = parse_private_ip(name)
                if private_ip:
                    instance_id = resolve_instance_id_by_private_ip(private_ip)
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
            meta = pod.metadata
            images = [c.image for c in pod.spec.containers if c.image]
            is_ai_agent, ai_framework = detect_ai_agent(
                meta.annotations, meta.labels, images
            )
            props: dict[str, Any] = {
                "name": name,
                "namespace": ns,
                "node_name": node_name or "",
                "status": pod.status.phase if pod.status else "",
                "is_ai_agent": is_ai_agent,
            }
            if is_ai_agent:
                props["ai_framework"] = ai_framework
            self._nodes.append(Node(id=pod_uid, label="Pod", properties=props))
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
