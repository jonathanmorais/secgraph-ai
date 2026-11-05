"""AWS S3 connector: buckets, public access, encryption."""
from typing import Any
import boto3

from graphsec.connectors.base import BaseConnector
from graphsec.models.graph import Edge, Node


class S3Connector(BaseConnector):
    name = "aws-s3"

    def __init__(self, session: Any = None) -> None:
        self.client = (session or boto3).client("s3")
        self._nodes: list[Node] = []
        self._loaded = False

    def _load(self) -> None:
        if self._loaded:
            return
        for b in self.client.list_buckets().get("Buckets", []):
            name = b["Name"]
            is_public = self._is_public(name)
            encryption = self._encryption(name)
            region = self._region(name)
            self._nodes.append(
                Node(
                    id=name,
                    label="S3Bucket",
                    properties={
                        "bucket_name": name,
                        "is_public": is_public,
                        "encryption": encryption,
                        "region": region,
                    },
                )
            )
        self._loaded = True

    def _is_public(self, bucket: str) -> bool:
        try:
            pab = self.client.get_public_access_block(Bucket=bucket)
            cfg = pab["PublicAccessBlockConfiguration"]
            return not all([
                cfg.get("BlockPublicAcls"), cfg.get("BlockPublicPolicy"),
                cfg.get("IgnorePublicAcls"), cfg.get("RestrictPublicBuckets"),
            ])
        except Exception:
            return True

    def _encryption(self, bucket: str) -> str:
        try:
            enc = self.client.get_bucket_encryption(Bucket=bucket)
            rules = enc["ServerSideEncryptionConfiguration"]["Rules"]
            return rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
        except Exception:
            return "none"

    def _region(self, bucket: str) -> str:
        try:
            loc = self.client.get_bucket_location(Bucket=bucket)
            return loc.get("LocationConstraint") or "us-east-1"
        except Exception:
            return "unknown"

    def get_nodes(self) -> list[Node]:
        self._load()
        return self._nodes

    def get_edges(self) -> list[Edge]:
        self._load()
        return []
