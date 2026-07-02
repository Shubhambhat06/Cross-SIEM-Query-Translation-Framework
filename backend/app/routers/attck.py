from fastapi import APIRouter

router = APIRouter(prefix="/api")


@router.post("/attck/map")
async def map_attck():
    return {
        "technique": None
    }