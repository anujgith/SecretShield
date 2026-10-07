from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    repository_path: str = Field(
        ...,
        description="Local path of the repository to scan"
    )


class ScanFinding(BaseModel):
    rule_id: str | None = None
    description: str | None = None
    file: str | None = None
    line: int | None = None
    column: int | None = None
    secret_type: str | None = None
    fingerprint: str | None = None
    risk_score: int = 0
    severity: str = "LOW"
    risk_reasons: list[str] = []
    incident_id: str | None = None

class ScanResponse(BaseModel):
    status: str
    repository_path: str
    findings_count: int
    findings: list[ScanFinding]
