from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.schemas.scan import ScanRequest, ScanResponse
from app.services.audit import record_audit_event
from app.services.scan import scan_repository as run_shared_scan

router = APIRouter(prefix="/scan", tags=["Scans"])


@router.post(
    "", response_model=ScanResponse, summary="Scan current repository files",
    description=(
        "Scans local repository files. Responses and incident records contain "
        "metadata only; raw secret values are never returned or stored."
    ),
)
async def scan_repository(request: ScanRequest, db: Session = Depends(get_db)):
    try:
        return run_shared_scan(request.repository_path, db)
    except FileNotFoundError as exc:
        db.rollback()
        record_audit_event(db, "SCAN", "Current-file scan failed: repository path not found.", repository=request.repository_path)
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        db.rollback()
        record_audit_event(db, "SCAN", "Current-file scan failed: invalid repository path.", repository=request.repository_path)
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        db.rollback()
        record_audit_event(db, "SCAN", "Current-file scan failed during Gitleaks execution.", repository=request.repository_path)
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    except Exception as exc:
        db.rollback()
        record_audit_event(db, "SCAN", "Current-file scan failed unexpectedly.", repository=request.repository_path)
        raise HTTPException(status_code=500, detail="Current-file scan failed.") from exc
