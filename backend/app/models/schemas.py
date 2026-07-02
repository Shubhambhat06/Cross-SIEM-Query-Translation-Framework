from pydantic import BaseModel


class TranslateRequest(BaseModel):
    query: str
    platform: str


class ExecuteRequest(BaseModel):
    query: str
    platform: str


class AttckRequest(BaseModel):
    query: str