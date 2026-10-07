from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class RescanFinding(BaseModel):
    file: str | None = None
    secret_type: str | None = None
    fingerprint: str | None = None


class RotationRescanResult(BaseModel):
    incident_id: str
    status: str
    resolved: bool
    message: str
    finding: RescanFinding | None = None


class RotationResponse(BaseModel):
    incident_id: str
    provider: Literal["mock"]
    status: Literal["SIMULATED"]
    operation_id: str
    created_at: datetime
    completed_at: datetime
    rescan: RotationRescanResult
    incident_status: str
