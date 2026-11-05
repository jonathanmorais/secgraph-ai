"""AWS IAM connector: users, roles, policies, trust relationships."""
import json
from typing import Any
import boto3

from graphsec.connectors.base import BaseConnector
from graphsec.models.graph import Edge, Node


class IAMConnector(BaseConnector):
    name = "aws-iam"

    def __init__(self, session: Any = None) -> None:
        self.client = (session or boto3).client("iam")
        self._nodes: list[Node] = []
        self._edges: list[Edge] = []
        self._loaded = False

    def _load(self) -> None:
        if self._loaded:
            return
        self._load_users()
        self._load_roles()
        self._load_policies()
        self._loaded = True

    def _load_users(self) -> None:
        paginator = self.client.get_paginator("list_users")
        for page in paginator.paginate():
            for u in page.get("Users", []):
                mfa = self.client.list_mfa_devices(UserName=u["UserName"]).get("MFADevices", [])
                self._nodes.append(
                    Node(
                        id=u["Arn"],
                        label="IAMUser",
                        properties={
                            "arn": u["Arn"],
                            "user_name": u["UserName"],
                            "create_date": u["CreateDate"].isoformat(),
                            "has_mfa": bool(mfa),
                            "last_used": (u.get("PasswordLastUsed") or "").__str__(),
                        },
                    )
                )
                for p in self.client.list_attached_user_policies(UserName=u["UserName"]).get(
                    "AttachedPolicies", []
                ):
                    self._edges.append(
                        Edge(source=u["Arn"], target=p["PolicyArn"], type="HAS_POLICY")
                    )
                self._load_inline(u["Arn"], "user", u["UserName"])

    def _load_roles(self) -> None:
        paginator = self.client.get_paginator("list_roles")
        for page in paginator.paginate():
            for r in page.get("Roles", []):
                trust = r.get("AssumeRolePolicyDocument", {})
                self._nodes.append(
                    Node(
                        id=r["Arn"],
                        label="IAMRole",
                        properties={
                            "arn": r["Arn"],
                            "role_name": r["RoleName"],
                            "trust_policy": json.dumps(trust),
                            "is_service_role": "service" in json.dumps(trust).lower(),
                        },
                    )
                )
                for principal_arn in self._extract_trust_principals(trust):
                    self._edges.append(
                        Edge(source=principal_arn, target=r["Arn"], type="CAN_ASSUME")
                    )
                for p in self.client.list_attached_role_policies(RoleName=r["RoleName"]).get(
                    "AttachedPolicies", []
                ):
                    self._edges.append(
                        Edge(source=r["Arn"], target=p["PolicyArn"], type="HAS_POLICY")
                    )
                self._load_inline(r["Arn"], "role", r["RoleName"])

    def _load_inline(self, principal_arn: str, kind: str, name: str) -> None:
        """Coleta policies inline (role ou user) — ponto cego comum, pois não
        têm ARN e não aparecem nas chamadas de attached policies."""
        if kind == "role":
            names = self.client.list_role_policies(RoleName=name).get("PolicyNames", [])
            getter = lambda pn: self.client.get_role_policy(RoleName=name, PolicyName=pn)
        else:
            names = self.client.list_user_policies(UserName=name).get("PolicyNames", [])
            getter = lambda pn: self.client.get_user_policy(UserName=name, PolicyName=pn)

        for pn in names:
            doc = getter(pn).get("PolicyDocument", {})
            uid = f"{principal_arn}:inline/{pn}"
            self._nodes.append(
                Node(
                    id=uid,
                    label="IAMPolicy",
                    properties={
                        "policy_name": pn,
                        "is_inline": True,
                        "is_aws_managed": False,
                        "document": json.dumps(doc),
                    },
                )
            )
            self._edges.append(Edge(source=principal_arn, target=uid, type="HAS_POLICY"))
            for resource in self._extract_allowed_resources(doc):
                self._edges.append(Edge(source=uid, target=resource, type="ALLOWS"))

    @staticmethod
    def _normalize_resource(arn: str) -> str | None:
        """Normaliza o ARN do recurso para o mesmo identificador (uid) que o
        connector daquele recurso usa, para a aresta ALLOWS apontar ao nó real.
        S3: arn:aws:s3:::bucket[/key] -> bucket (uid do S3Connector)."""
        if arn.startswith("arn:aws:s3:::"):
            name = arn[len("arn:aws:s3:::"):].split("/")[0]
            return name or None
        return arn

    @classmethod
    def _extract_allowed_resources(cls, doc: dict[str, Any]) -> list[str]:
        """Extrai recursos permitidos (Effect=Allow), normalizados e deduplicados."""
        out: list[str] = []
        stmts = doc.get("Statement", [])
        if isinstance(stmts, dict):
            stmts = [stmts]
        for stmt in stmts:
            if stmt.get("Effect") != "Allow":
                continue
            res = stmt.get("Resource", [])
            for r in [res] if isinstance(res, str) else res:
                if not r or r == "*" or not r.startswith("arn:"):
                    continue
                norm = cls._normalize_resource(r)
                if norm and norm not in out:
                    out.append(norm)
        return out

    def _load_policies(self) -> None:
        paginator = self.client.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local"):
            for p in page.get("Policies", []):
                self._nodes.append(
                    Node(
                        id=p["Arn"],
                        label="IAMPolicy",
                        properties={
                            "arn": p["Arn"],
                            "policy_name": p["PolicyName"],
                            "is_aws_managed": False,
                        },
                    )
                )

    @staticmethod
    def _extract_trust_principals(trust: dict[str, Any]) -> list[str]:
        out: list[str] = []
        for stmt in trust.get("Statement", []):
            principal = stmt.get("Principal", {})
            for kind in ("AWS", "Service"):
                val = principal.get(kind)
                if isinstance(val, str):
                    out.append(val)
                elif isinstance(val, list):
                    out.extend(val)
        return out

    def get_nodes(self) -> list[Node]:
        self._load()
        return self._nodes

    def get_edges(self) -> list[Edge]:
        self._load()
        return self._edges
