from fastapi import APIRouter
from pydantic import BaseModel
from backend.app.services.translator_service import translate

router = APIRouter()


class TranslateRequest(BaseModel):
    query: str


@router.post("/")
def translate_query(req: TranslateRequest):
    return translate(req.query)