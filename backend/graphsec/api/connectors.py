from fastapi import APIRouter, BackgroundTasks

from graphsec.connectors.aws.sync import sync_all

router = APIRouter(prefix="/api/connectors", tags=["connectors"])


@router.post("/aws/sync")
def trigger_aws_sync(bg: BackgroundTasks) -> dict[str, str]:
    bg.add_task(sync_all)
    return {"status": "started"}


@router.get("/")
def list_connectors() -> list[dict[str, str]]:
    return [
        {"name": "aws-iam", "status": "available"},
        {"name": "aws-ec2", "status": "available"},
        {"name": "aws-s3", "status": "available"},
        {"name": "aws-rds", "status": "available"},
        {"name": "aws-lambda", "status": "available"},
        {"name": "azure", "status": "planned"},
    ]
