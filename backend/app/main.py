from app.core.database import Base, engine
from app.models.incident import Incident
from app.models.audit import AuditEvent
from app.models.rotation import RotationOperation
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.scans import router as scans_router
from app.api.incidents import router as incidents_router
from app.api.history import router as history_router

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="SecretShield",
    description=(
        "SecretShield is a secret incident-resolution platform built around "
        "Gitleaks."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"http://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(scans_router)
app.include_router(incidents_router)
app.include_router(history_router)


@app.get("/health")
async def health():
    return {"status": "ok"}
