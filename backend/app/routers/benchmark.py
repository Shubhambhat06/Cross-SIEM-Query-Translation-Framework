from fastapi import APIRouter

router = APIRouter(prefix="/api")


@router.get("/benchmark/stats")
async def benchmark():
    return {
        "queries": 0,
        "coverage": 0,
        "platforms": 5
    }