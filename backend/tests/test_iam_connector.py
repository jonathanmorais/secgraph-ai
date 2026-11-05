import boto3
import pytest
from moto import mock_aws

from graphsec.connectors.aws.iam import IAMConnector


@pytest.fixture
def aws(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    with mock_aws():
        yield


def test_iam_connector_lists_users(aws):
    client = boto3.client("iam")
    client.create_user(UserName="alice")
    client.create_user(UserName="bob")

    conn = IAMConnector()
    nodes = conn.get_nodes()
    user_names = [n.properties["user_name"] for n in nodes if n.label == "IAMUser"]
    assert "alice" in user_names
    assert "bob" in user_names


def test_iam_connector_detects_mfa_absent(aws):
    client = boto3.client("iam")
    client.create_user(UserName="carol")
    conn = IAMConnector()
    users = [n for n in conn.get_nodes() if n.label == "IAMUser"]
    assert all(u.properties["has_mfa"] is False for u in users)
