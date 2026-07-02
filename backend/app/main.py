from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.routers.translate import router as translate_router
from backend.app.routers.connector import router as connector_router
from backend.app.routers.benchmark import router as benchmark_router
from backend.app.routers.upload import router as upload_router
from backend.app.routers.attck import router as attck_router
from backend.app.routers.execute import router as execute_router

app = FastAPI(title="NL-SIEM API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(
    translate_router,
    prefix="/api/translate",
    tags=["Translate"]
)

app.include_router(
    connector_router,
    prefix="/api/connectors",
    tags=["Connectors"]
)

app.include_router(
    benchmark_router,
    prefix="/api/benchmark",
    tags=["Benchmark"]
)

app.include_router(
    upload_router,
    prefix="/api/upload",
    tags=["Upload"]
)

app.include_router(
    attck_router,
    prefix="/api/attck",
    tags=["ATT&CK"]
)

app.include_router(
    execute_router,
    prefix="/api/execute",
    tags=["Execute"]
)


@app.get("/")
def root():
    return {
        "message": "NL-SIEM Backend Running"
    }