"""AWS EC2 connector: instances, security groups, VPCs, IGWs."""
from typing import Any
import boto3

from graphsec.connectors.base import BaseConnector
from graphsec.models.graph import Edge, Node


def _flatten_rules(perms: list[dict[str, Any]]) -> dict[str, Any]:
    """Transforma IpPermissions em arrays planos + flags de risco."""
    ports: list[int] = []
    cidrs: list[str] = []
    protocols: list[str] = []
    exposes_world = False
    world_ports: list[int] = []

    for p in perms:
        proto = str(p.get("IpProtocol", ""))
        from_port = p.get("FromPort")
        to_port = p.get("ToPort")
        for r in p.get("IpRanges", []):
            cidr = r.get("CidrIp", "")
            cidrs.append(cidr)
            protocols.append(proto)
            if from_port is not None:
                ports.append(int(from_port))
            if cidr == "0.0.0.0/0":
                exposes_world = True
                if from_port is not None and to_port is not None:
                    world_ports.extend(range(int(from_port), int(to_port) + 1))
                elif proto == "-1":
                    world_ports.append(-1)

    return {
        "ports": sorted(set(ports)),
        "cidrs": sorted(set(cidrs)),
        "protocols": sorted(set(protocols)),
        "exposes_world": exposes_world,
        "world_ports": sorted(set(world_ports)),
        "exposes_ssh_world": exposes_world and (22 in world_ports or -1 in world_ports),
        "exposes_http_world": exposes_world and (80 in world_ports or -1 in world_ports),
        "exposes_rdp_world": exposes_world and (3389 in world_ports or -1 in world_ports),
    }


class EC2Connector(BaseConnector):
    name = "aws-ec2"

    def __init__(self, session: Any = None, region: str | None = None) -> None:
        self.client = (session or boto3).client("ec2", region_name=region)
        self._iam = (session or boto3).client("iam")
        self._profile_role: dict[str, str] = {}
        self._world_sgs: set[str] = set()
        self._public_ec2_vpc: list[tuple[str, str]] = []
        self._nodes: list[Node] = []
        self._edges: list[Edge] = []
        self._loaded = False

    def _role_for_profile(self, profile_arn: str) -> str | None:
        """Resolve o ARN da role real por trás de um instance profile.
        O nome do profile frequentemente difere do nome da role."""
        if profile_arn in self._profile_role:
            return self._profile_role[profile_arn]
        name = profile_arn.split("/")[-1]
        try:
            prof = self._iam.get_instance_profile(InstanceProfileName=name)
            roles = prof["InstanceProfile"].get("Roles", [])
            role_arn = roles[0]["Arn"] if roles else None
        except Exception:
            role_arn = None
        self._profile_role[profile_arn] = role_arn
        return role_arn

    def _load(self) -> None:
        if self._loaded:
            return
        self._load_vpcs()
        self._load_sgs()
        self._load_instances()
        self._load_igws()
        self._loaded = True

    def _load_vpcs(self) -> None:
        for v in self.client.describe_vpcs().get("Vpcs", []):
            self._nodes.append(
                Node(
                    id=v["VpcId"],
                    label="VPC",
                    properties={
                        "vpc_id": v["VpcId"],
                        "cidr_block": v.get("CidrBlock", ""),
                        "region": self.client.meta.region_name or "",
                    },
                )
            )

    def _load_sgs(self) -> None:
        for sg in self.client.describe_security_groups().get("SecurityGroups", []):
            inbound = _flatten_rules(sg.get("IpPermissions", []))
            outbound = _flatten_rules(sg.get("IpPermissionsEgress", []))
            if inbound["exposes_world"]:
                self._world_sgs.add(sg["GroupId"])
            self._nodes.append(
                Node(
                    id=sg["GroupId"],
                    label="SecurityGroup",
                    properties={
                        "group_id": sg["GroupId"],
                        "vpc_id": sg.get("VpcId", ""),
                        "name": sg.get("GroupName", ""),
                        "inbound_ports": inbound["ports"],
                        "inbound_cidrs": inbound["cidrs"],
                        "inbound_protocols": inbound["protocols"],
                        "inbound_world_ports": inbound["world_ports"],
                        "exposes_world": inbound["exposes_world"],
                        "exposes_ssh_world": inbound["exposes_ssh_world"],
                        "exposes_http_world": inbound["exposes_http_world"],
                        "exposes_rdp_world": inbound["exposes_rdp_world"],
                        "outbound_ports": outbound["ports"],
                        "outbound_cidrs": outbound["cidrs"],
                    },
                )
            )

    def _load_instances(self) -> None:
        for res in self.client.describe_instances().get("Reservations", []):
            for inst in res.get("Instances", []):
                sg_ids = [s["GroupId"] for s in inst.get("SecurityGroups", [])]
                iam_profile = (inst.get("IamInstanceProfile") or {}).get("Arn")
                self._nodes.append(
                    Node(
                        id=inst["InstanceId"],
                        label="EC2Instance",
                        properties={
                            "instance_id": inst["InstanceId"],
                            "public_ip": inst.get("PublicIpAddress"),
                            "private_ip": inst.get("PrivateIpAddress"),
                            "state": inst.get("State", {}).get("Name"),
                            "sg_ids": sg_ids,
                            "iam_instance_profile": iam_profile,
                        },
                    )
                )
                for sg_id in sg_ids:
                    self._edges.append(
                        Edge(source=inst["InstanceId"], target=sg_id, type="MEMBER_OF")
                    )
                    # SG escancarado + instância com IP público = exposição direta
                    if sg_id in self._world_sgs and inst.get("PublicIpAddress"):
                        self._edges.append(
                            Edge(source=sg_id, target=inst["InstanceId"], type="EXPOSES")
                        )
                if vpc := inst.get("VpcId"):
                    self._edges.append(
                        Edge(source=inst["InstanceId"], target=vpc, type="IN_VPC")
                    )
                    world_exposed = any(sid in self._world_sgs for sid in sg_ids)
                    if inst.get("PublicIpAddress") and world_exposed:
                        self._public_ec2_vpc.append((inst["InstanceId"], vpc))
                if subnet := inst.get("SubnetId"):
                    self._edges.append(
                        Edge(source=inst["InstanceId"], target=subnet, type="IN_SUBNET")
                    )
                if iam_profile:
                    role_arn = self._role_for_profile(iam_profile)
                    if role_arn:
                        self._edges.append(
                            Edge(source=inst["InstanceId"], target=role_arn, type="CAN_ASSUME")
                        )

    def _load_igws(self) -> None:
        for igw in self.client.describe_internet_gateways().get("InternetGateways", []):
            for att in igw.get("Attachments", []):
                vpc = att.get("VpcId")
                self._nodes.append(
                    Node(
                        id=igw["InternetGatewayId"],
                        label="InternetGateway",
                        properties={"igw_id": igw["InternetGatewayId"], "vpc_id": vpc},
                    )
                )
                if vpc:
                    self._edges.append(
                        Edge(source=igw["InternetGatewayId"], target=vpc, type="ROUTES_TO")
                    )
                    # aresta de entrada direta: internet alcança a EC2 exposta
                    for ec2_id, ec2_vpc in self._public_ec2_vpc:
                        if ec2_vpc == vpc:
                            self._edges.append(
                                Edge(
                                    source=igw["InternetGatewayId"],
                                    target=ec2_id,
                                    type="PUBLIC_ACCESS",
                                )
                            )

    def get_nodes(self) -> list[Node]:
        self._load()
        return self._nodes

    def get_edges(self) -> list[Edge]:
        self._load()
        return self._edges
