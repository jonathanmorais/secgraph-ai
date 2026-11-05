"""Celery tasks: periodic sync and maintenance."""
from celery import Celery
from celery.schedules import crontab

from graphsec.config import get_settings
from graphsec.connectors.aws.sync import sync_all

settings = get_settings()
app = Celery("graphsec", broker=settings.redis_url, backend=settings.redis_url)
app.conf.timezone = "America/Sao_Paulo"


@app.task
def task_sync_aws() -> dict[str, dict[str, int]]:
    return sync_all()


app.conf.beat_schedule = {
    "aws-sync-hourly": {
        "task": "graphsec.scheduler.tasks.task_sync_aws",
        "schedule": crontab(minute=0),
    },
}
