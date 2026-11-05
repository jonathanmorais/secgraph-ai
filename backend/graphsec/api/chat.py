from fastapi import APIRouter

from graphsec.chat.engine import ask
from graphsec.models.chat import ChatRequest, ChatResponse

router = APIRouter(prefix="/api/chat", tags=["chat"])


@router.post("/", response_model=ChatResponse)
def chat(req: ChatRequest) -> ChatResponse:
    return ask(req)
