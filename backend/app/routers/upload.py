from fastapi import APIRouter

router = APIRouter(prefix="/api")


@router.post("/upload")
async def upload():
    return {
        "message": "Upload endpoint"
    }