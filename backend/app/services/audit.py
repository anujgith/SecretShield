from sqlalchemy.orm import Session

from app.models.audit import AuditEvent


def record_audit_event(
    db: Session,
    event_type: str,
    message: str,
    *,
    incident_id: str | None = None,
    repository: str | None = None,
) -> None:
    """Persist a metadata-only activity event without affecting API work."""
    try:
        db.add(
            AuditEvent(
                event_type=event_type,
                message=message,
                incident_id=incident_id,
                repository=repository,
            )
        )
        db.commit()
    except Exception:
        db.rollback()
