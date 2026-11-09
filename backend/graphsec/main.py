from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from graphsec.api import blast_radius, chat, connectors, graph, reports, workloads
from graphsec.gateway import router as gateway_router
from graphsec.graph.client import close_driver


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    yield
    close_driver()


app = FastAPI(title="GraphSec API", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(graph.router)
app.include_router(chat.router)
app.include_router(connectors.router)
app.include_router(reports.router)
app.include_router(workloads.router)
app.include_router(gateway_router.router)
app.include_router(blast_radius.router)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
