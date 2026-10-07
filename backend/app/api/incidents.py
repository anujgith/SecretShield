from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session


from app.core.database import get_db
from app.models.incident import Incident
from app.services.remediation import get_remediation_guidance
from app.services.policy import evaluate_policy
from app.services.ai_guidance import get_ai_guidance
from app.services.audit import record_audit_event
from app.models.audit import AuditEvent
from app.models.rotation import RotationOperation
from app.schemas.rotation import RotationResponse
from app.services.rescan import rescan_incident as perform_rescan
from app.services.rotation import RotationManager

router = APIRouter(prefix="/incidents", tags=["Incidents"])


class IncidentStatusUpdate(BaseModel):
    status: str


@router.get("/")
def get_incidents(db: Session = Depends(get_db)):
    incidents = db.query(Incident).order_by(Incident.created_at.desc()).all()

    return [
        {
            "id": incident.id,
            "incident_id": incident.incident_id,
            "repository": incident.repository,
            "file_path": incident.file_path,
            "secret_type": incident.secret_type,
            "severity": incident.severity,
            "risk_score": incident.risk_score,
            "commit_hash": incident.commit_hash,
            "fingerprint": incident.fingerprint,
            "status": incident.status,
            "description": incident.description,
            "created_at": incident.created_at,
            "updated_at": incident.updated_at,
            "source": "current-file",
            "policy": evaluate_policy(
                severity=incident.severity,
                secret_type=incident.secret_type,
                risk_score=incident.risk_score,
            ),
            "ai_guidance": get_ai_guidance(
                secret_type=incident.secret_type,
                severity=incident.severity,
                description=incident.description,
            ),
        }
        for incident in incidents
    ]


@router.get("/{incident_id}", summary="Get incident details")
def get_incident(incident_id: str, db: Session = Depends(get_db)):
    incident = (
        db.query(Incident)
        .filter(Incident.incident_id == incident_id)
        .first()
    )
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    return {
        "id": incident.id,
        "incident_id": incident.incident_id,
        "repository": incident.repository,
        "file_path": incident.file_path,
        "secret_type": incident.secret_type,
        "severity": incident.severity,
        "risk_score": incident.risk_score,
        "commit_hash": incident.commit_hash,
        "fingerprint": incident.fingerprint,
        "status": incident.status,
        "description": incident.description,
        "created_at": incident.created_at,
        "updated_at": incident.updated_at,
        "source": "current-file",
        "policy": evaluate_policy(
            severity=incident.severity,
            secret_type=incident.secret_type,
            risk_score=incident.risk_score,
        ),
        "ai_guidance": get_ai_guidance(
            secret_type=incident.secret_type,
            severity=incident.severity,
            description=incident.description,
        ),
    }


@router.patch(
    "/{incident_id}",
    summary="Update an incident status",
    description="Updates an existing incident to DETECTED, INVESTIGATING, or RESOLVED.",
)
def update_incident_status(
    incident_id: str,
    update: IncidentStatusUpdate,
    db: Session = Depends(get_db)
):
   
    incident = (
        db.query(Incident)
        .filter(Incident.incident_id == incident_id)
        .first()
    )

   

    if not incident:
        raise HTTPException(
            status_code=404,
            detail="Incident not found"
        )

    allowed_statuses = [
        "DETECTED",
        "INVESTIGATING",
        "RESOLVED"
    ]

    if update.status not in allowed_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Use one of: {allowed_statuses}"
        )

    previous_status = incident.status
    incident.status = update.status
    db.commit()
    db.refresh(incident)
    if previous_status != incident.status:
        event_type = "RESOLVE" if incident.status == "RESOLVED" else "STATUS"
        message = (
            "Incident resolved by user."
            if incident.status == "RESOLVED"
            else f"Incident status changed to {incident.status}."
        )
        record_audit_event(
            db,
            event_type,
            message,
            incident_id=incident.incident_id,
            repository=incident.repository,
        )

    return {
        "message": "Incident status updated successfully",
        "incident_id": incident.incident_id,
        "status": incident.status
    }


@router.post(
    "/{incident_id}/rescan",
    summary="Rescan an existing incident",
    description=(
        "Scans the incident repository and compares the exact stored Gitleaks "
        "fingerprint. Resolves the existing incident when that fingerprint is absent."
    ),
)
def rescan_incident(
    incident_id: str,
    db: Session = Depends(get_db)
):
    incident = (
        db.query(Incident)
        .filter(Incident.incident_id == incident_id)
        .first()
    )

    if not incident:
        raise HTTPException(
            status_code=404,
            detail="Incident not found"
        )

    try:
        return perform_rescan(db, incident)
    except FileNotFoundError as exc:
        db.rollback()
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post(
    "/{incident_id}/rotate",
    response_model=RotationResponse,
    summary="Simulate a mock secret rotation and rescan",
)
def rotate_incident_secret(incident_id: str, db: Session = Depends(get_db)):
    incident = (
        db.query(Incident)
        .filter(Incident.incident_id == incident_id)
        .first()
    )
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    if incident.status.upper() == "RESOLVED":
        raise HTTPException(
            status_code=409,
            detail="Incident is already resolved; no rotation is needed.",
        )
    if not incident.fingerprint:
        raise HTTPException(
            status_code=400,
            detail="This incident cannot be safely rescanned because its fingerprint is missing.",
        )

    operation = (
        db.query(RotationOperation)
        .filter(RotationOperation.incident_id == incident.incident_id)
        .first()
    )
    if operation is None:
        record_audit_event(
            db, "ROTATION_REQUESTED", "Mock rotation requested.",
            incident_id=incident.incident_id, repository=incident.repository,
        )
        simulated = RotationManager().simulate_rotation()
        operation = RotationOperation(
            incident_id=incident.incident_id,
            provider=simulated["provider"],
            status=simulated["status"],
            operation_id=simulated["operation_id"],
            created_at=simulated["created_at"],
            completed_at=simulated["completed_at"],
        )
        db.add(operation)
        try:
            db.commit()
            db.refresh(operation)
        except Exception as exc:
            db.rollback()
            raise HTTPException(status_code=500, detail="Could not persist mock rotation metadata.") from exc
        record_audit_event(
            db, "ROTATION_SIMULATED", "Mock rotation operation simulated.",
            incident_id=incident.incident_id, repository=incident.repository,
        )

    try:
        rescan_result = perform_rescan(db, incident)
    except FileNotFoundError as exc:
        db.rollback()
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail="Rescan after mock rotation failed.") from exc

    record_audit_event(
        db, "RESCAN_AFTER_ROTATION", "Fingerprint rescan completed after mock rotation.",
        incident_id=incident.incident_id, repository=incident.repository,
    )
    return {
        "incident_id": incident.incident_id,
        "provider": operation.provider,
        "status": operation.status,
        "operation_id": operation.operation_id,
        "created_at": operation.created_at,
        "completed_at": operation.completed_at,
        "rescan": rescan_result,
        "incident_status": incident.status,
    }


@router.get("/activity/", summary="List recent security activity")
def get_activity(db: Session = Depends(get_db)):
    events = (
        db.query(AuditEvent)
        .order_by(AuditEvent.created_at.desc())
        .limit(50)
        .all()
    )
    return [
        {
            "id": event.id,
            "event_type": event.event_type,
            "message": event.message,
            "incident_id": event.incident_id,
            "repository": event.repository,
            "created_at": event.created_at,
        }
        for event in events
    ]


@router.get(
    "/{incident_id}/remediation",
    summary="Get remediation guidance for an incident",
)
def get_incident_remediation(
    incident_id: str,
    db: Session = Depends(get_db)
):
    requested_id = incident_id.strip()

    rows = db.execute(
        text("""
            SELECT incident_id, secret_type, severity, status
            FROM incidents
        """)
    ).mappings().all()

    for row in rows:
        db_id = str(row["incident_id"]).strip()

        normalized_db_id = "".join(
            c for c in db_id.upper()
            if c.isalnum()
        )

        normalized_request = "".join(
            c for c in requested_id.upper()
            if c.isalnum()
        )

        if normalized_db_id == normalized_request:
            guidance = get_remediation_guidance(
                row["secret_type"]
            )

            record_audit_event(
                db,
                "REMEDIATION",
                "Remediation guidance viewed.",
                incident_id=str(row["incident_id"]),
            )

            return {
                "incident_id": row["incident_id"],
                "secret_type": row["secret_type"],
                "severity": row["severity"],
                "status": row["status"],
                "remediation": guidance
            }

    raise HTTPException(
        status_code=404,
        detail="Incident not found"
    )
