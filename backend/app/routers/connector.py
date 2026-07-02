from fastapi import APIRouter

router = APIRouter(prefix="/api")


@router.get("/connectors/status")
async def status():
    return {
        "elastic": False,
        "splunk": False,
        "wazuh": False,
        "sentinel": False,
        "qradar": False
    }