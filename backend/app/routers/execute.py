from fastapi import APIRouter

router = APIRouter(prefix="/api")


@router.post("/execute")
async def execute():
    return {"message": "Execute endpoint"}